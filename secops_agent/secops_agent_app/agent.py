import logging
import os
from typing import Any
from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.agents.context import Context
from google.adk.agents.context_cache_config import ContextCacheConfig
from google.adk.apps import App
from google.adk.apps.app import ResumabilityConfig
from google.adk.apps.compaction import EventsCompactionConfig
from google.adk.models import Gemini
from google.adk.planners import BuiltInPlanner
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
import google.auth
import google.auth.transport.requests
from google.genai import types
from opentelemetry.instrumentation.google_genai import GoogleGenAiSdkInstrumentor

from google.adk.tools.tool_context import ToolContext
from mcp.client.session import ClientSession


async def _bypass_mcp_output_schema_validation(
    self: ClientSession, name: str, result: Any
) -> None:
  """Bypass mcp.ClientSession outputSchema validation for Chronicle OneMCP streaming/text responses."""
  del self, name, result


ClientSession.validate_tool_result = _bypass_mcp_output_schema_validation

# Default TTL (seconds) for caching the remote Chronicle OneMCP tools/list response
DEFAULT_MCP_TOOL_CACHE_TTL_SECONDS = 300.0

# SecOps MCP tools that are permanently disabled and hidden from the LLM to
# eliminate 169.8 KB (-68.94%) of inputSchema bloat and 710.5 KB of outputSchema
# bloat from the 108-variant FeedDetails proto and RunParserResponse UDM proto.
DISABLED_SECOPS_TOOLS = frozenset(
    {
        "create_feed",
        "update_feed",
        "run_parser",
        "list_feeds",
        "get_feed",
        "disable_feed",
        "enable_feed",
    }
)

# Destructive SecOps MCP tools that can optionally require human-in-the-loop confirmation
DESTRUCTIVE_SECOPS_TOOLS = frozenset(
    {
        "delete_feed",
        "disable_feed",
        "deactivate_parser",
        "delete_data_table_row",
        "execute_bulk_close_case",
        "execute_manual_action",
    }
)

STATIC_SECOPS_INSTRUCTION = """You are a Google Security Operations (SecOps) assistant powered by Google ADK 2.x.
You have access to the remote Chronicle OneMCP server, which provides tools for SIEM event search, entity investigation, detection rule management, and SOAR case operations.
Always use the provided tools to fetch authoritative telemetry and case data from Chronicle rather than guessing.
When a tool requires projectId, customerId, or region, always supply the active tenant identifiers from your instructions.
Feed administration and parser simulation tools (create_feed, update_feed, run_parser, list_feeds, get_feed, disable_feed, enable_feed) are intentionally disabled by policy to optimize context window usage.
"""


def strip_mcp_output_schemas(callback_context: Any, llm_request: Any) -> None:
  """ADK 2.x before_model_callback stripping 3.73 MB of MCP outputSchema on generate_content while preserving parameters_json_schema."""
  del callback_context
  config = getattr(llm_request, "config", None)
  if not config:
    return
  for tool in getattr(config, "tools", None) or []:
    for fd in getattr(tool, "function_declarations", None) or []:
      fd.response_json_schema = None
      fd.response = None


def get_disabled_secops_tools() -> frozenset[str]:
  """Return the set of disabled SecOps MCP tools (always including DISABLED_SECOPS_TOOLS plus any SECOPS_DISABLED_TOOLS env entries)."""
  extra_raw = os.environ.get("SECOPS_DISABLED_TOOLS", "")
  extra = {t.strip() for t in extra_raw.split(",") if t.strip()}
  return DISABLED_SECOPS_TOOLS | extra


def is_secops_tool_enabled(
    tool: BaseTool, readonly_context: Any = None
) -> bool:
  """Filter predicate passed to McpToolset(tool_filter=...) to exclude disabled SecOps tools."""
  del readonly_context
  tool_name = getattr(tool, "name", "")
  return tool_name not in get_disabled_secops_tools()


def _requires_tool_confirmation(tool_name: str = "", **_: Any) -> bool:
  """Determine whether a SecOps MCP tool requires human-in-the-loop confirmation."""
  require_destructive = (
      os.environ.get("SECOPS_REQUIRE_DESTRUCTIVE_CONFIRMATION", "false").lower()
      == "true"
  )
  if not require_destructive:
    return False
  return tool_name in DESTRUCTIVE_SECOPS_TOOLS


def confirm_destructive_secops_tool(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
) -> dict[str, Any] | None:
  """ADK 2.x before_tool_callback blocking disabled tools and enforcing HITL confirmation on destructive tools."""
  tool_name = getattr(tool, "name", "")
  if tool_name in get_disabled_secops_tools():
    return {
        "status": "disabled",
        "tool": tool_name,
        "error": (
            f"Tool '{tool_name}' is disabled in this SecOps agent deployment."
        ),
    }
  if not _requires_tool_confirmation(tool_name=tool_name):
    return None

  if not tool_context.tool_confirmation:
    tool_context.request_confirmation(
        hint=(
            f"Please approve or reject the destructive SecOps tool call "
            f"{tool_name}() by responding with a ToolConfirmation payload."
        ),
        payload={"tool_name": tool_name, "args": args},
    )
    tool_context.actions.skip_summarization = True
    return {
        "status": "confirmation_required",
        "tool": tool_name,
        "error": (
            f"Tool '{tool_name}' modifies or deletes SecOps resources and "
            "requires explicit human-in-the-loop confirmation."
        ),
    }

  if not tool_context.tool_confirmation.confirmed:
    return {
        "status": "rejected",
        "tool": tool_name,
        "error": f"Tool call '{tool_name}' was rejected by the user.",
    }

  return None


def handle_secops_tool_error(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: Context,
    error: Exception,
) -> dict[str, Any]:
  """ADK 2.x on_tool_error_callback for structured MCP tool error recovery."""
  del tool_context
  tool_name = getattr(tool, "name", str(tool))
  logging.warning(
      "SecOps MCP tool '%s' raised %s with args %s: %s",
      tool_name,
      type(error).__name__,
      list(args.keys()),
      error,
  )
  return {
      "status": "error",
      "tool": tool_name,
      "error_type": type(error).__name__,
      "message": str(error),
  }


def get_secops_headers(context: Any) -> dict[str, str]:
  """Build HTTP headers for Chronicle OneMCP requests with OAuth token passthrough."""
  chronicle_project_id = os.environ.get("CHRONICLE_PROJECT_ID")
  gemini_auth_id = os.environ.get("GEMINI_AUTHORIZATION_ID")

  headers = {"Accept": "text/event-stream", "Content-Type": "application/json"}

  if chronicle_project_id:
    headers["x-goog-user-project"] = chronicle_project_id
  else:
    logging.critical(
        "CHRONICLE_PROJECT_ID is missing from environment! OneMCP tool calls"
        " *will* fail without a routing context."
    )

  user_token = None
  if context and getattr(context, "state", None) and gemini_auth_id:
    user_token = context.state.get(gemini_auth_id)
    if user_token:
      headers["Authorization"] = f"Bearer {user_token}"
      logging.info(
          "DEBUG: Tool Call Auth Header present (starts with: %s...)",
          user_token[:10],
      )

  if not user_token:
    try:
      creds, _ = google.auth.default(
          scopes=["https://www.googleapis.com/auth/cloud-platform"]
      )
      creds.refresh(google.auth.transport.requests.Request())
      if creds.token:
        headers["Authorization"] = f"Bearer {creds.token}"
    except Exception:
      pass

  return headers


def create_mcp_toolset(
    region: str,
    tool_list_cache_ttl_seconds: float = DEFAULT_MCP_TOOL_CACHE_TTL_SECONDS,
) -> McpToolset:
  """Create an ADK 2.x McpToolset with tool-list caching for Chronicle OneMCP."""
  secops_mcp_url = f"https://chronicle.{region}.rep.googleapis.com/mcp"
  logging.info(
      "Initializing ADK 2.x McpToolset with URL: %s (cache TTL: %ss)",
      secops_mcp_url,
      tool_list_cache_ttl_seconds,
  )

  return McpToolset(
      connection_params=StreamableHTTPConnectionParams(url=secops_mcp_url),
      header_provider=get_secops_headers,
      tool_filter=is_secops_tool_enabled,
      tool_list_cache_ttl_seconds=tool_list_cache_ttl_seconds,
      use_mcp_resources=False,
      errlog=None,  # explicitly None to prevent sys.stderr capturing (which cannot be pickled)
  )


def create_agent() -> Agent:
  """Create the ADK 2.x SecOps LlmAgent using generate_content + strip_mcp_output_schemas (Case B)."""
  load_dotenv()
  # Keep FeatureName.JSON_SCHEMA_FOR_FUNC_DECL enabled (default) so
  # FunctionDeclaration.parameters_json_schema preserves lossless JSON Schema
  # ($defs/$ref), while strip_mcp_output_schemas removes response_json_schema
  # (3.02 MB of remaining outputSchema) before each generate_content call.
  os.environ.pop("ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL", None)

  project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get(
      "GCP_PROJECT_ID"
  )
  if not project_id and os.environ.get("REASONING_ENGINE_DEPLOYMENT") != "True":
    try:
      _, project_id = google.auth.default()
    except Exception:
      pass

  os.environ["GOOGLE_CLOUD_PROJECT"] = project_id or ""
  os.environ["GOOGLE_CLOUD_LOCATION"] = "global"
  os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"

  if os.environ.get("REASONING_ENGINE_DEPLOYMENT") != "True":
    GoogleGenAiSdkInstrumentor().instrument()

  if "GOOGLE_CLOUD_AGENT_ENGINE_ID" in os.environ:
    os.environ.setdefault("GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY", "true")

  region = os.environ.get("CHRONICLE_REGION", "us")
  customer_id = os.environ.get("CHRONICLE_CUSTOMER_ID")
  chronicle_project_id = os.environ.get("CHRONICLE_PROJECT_ID")

  cache_ttl = float(
      os.environ.get(
          "MCP_TOOL_LIST_CACHE_TTL_SECONDS",
          str(DEFAULT_MCP_TOOL_CACHE_TTL_SECONDS),
      )
  )
  secops_toolset = create_mcp_toolset(
      region, tool_list_cache_ttl_seconds=cache_ttl
  )

  return Agent(
      name="secops_agent",
      model=Gemini(
          model="gemini-2.5-pro",
          use_interactions_api=False,
          client_kwargs={"location": "global"},
          retry_options=types.HttpRetryOptions(attempts=3),
      ),
      static_instruction=STATIC_SECOPS_INSTRUCTION,
      instruction=f"""Current Tenant Information:
- Project ID: {chronicle_project_id}
- Customer ID: {customer_id}
- Region: {region}
""",
      planner=BuiltInPlanner(
          thinking_config=types.ThinkingConfig(
              include_thoughts=(
                  os.environ.get("SECOPS_INCLUDE_THOUGHTS", "false").lower()
                  == "true"
              ),
              thinking_budget=1024,
          )
      ),
      tools=[secops_toolset],
      before_model_callback=strip_mcp_output_schemas,
      before_tool_callback=confirm_destructive_secops_tool,
      on_tool_error_callback=handle_secops_tool_error,
  )


def create_app() -> App:
  """Create the ADK 2.x App container with ContextCacheConfig, EventsCompactionConfig, and ResumabilityConfig."""
  root_agent = create_agent()
  return App(
      name="secops_agent_app",
      root_agent=root_agent,
      context_cache_config=ContextCacheConfig(
          min_tokens=4096,
          ttl_seconds=1800,
          cache_intervals=10,
      ),
      events_compaction_config=EventsCompactionConfig(
          compaction_interval=10,
          overlap_size=2,
      ),
      resumability_config=ResumabilityConfig(is_resumable=True),
  )
