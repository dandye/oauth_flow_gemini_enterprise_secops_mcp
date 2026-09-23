import asyncio
import logging
import os
import weakref
from typing import Any

import google.auth
import google.auth.transport.requests
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
from google.adk.tools.tool_context import ToolContext
from google.genai import types
from mcp.client.session import ClientSession
from opentelemetry.instrumentation.google_genai import GoogleGenAiSdkInstrumentor


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


class EventLoopSafeGemini(Gemini):
  """Gemini LLM wrapper that recreates api_client when the asyncio event loop changes.

  In Vertex AI Reasoning Engine (AdkApp), each request can execute on a fresh
  asyncio event loop while the root Agent and its Gemini model instance are
  reused across turns. Recreating the cached google.genai.Client when the
  previous loop has closed prevents httpcore.AsyncConnectionPool from raising
  RuntimeError('Event loop is closed').
  """

  _last_loop_ref: Any = None

  @property
  def api_client(self) -> Any:
    try:
      loop = asyncio.get_running_loop()
    except RuntimeError:
      loop = None
    if loop is not None:
      prev_loop = (
          self._last_loop_ref() if callable(self._last_loop_ref) else None
      )
      if prev_loop is not loop or prev_loop.is_closed():
        self.__dict__.pop("api_client", None)
        self.__dict__.pop("_live_api_client", None)
        self._last_loop_ref = weakref.ref(loop)
    return super().api_client


def _extract_user_oauth_token(
    state: Any, gemini_auth_id: str | None
) -> str | None:
  """Extract user OAuth access token from ADK session state (including AdkApp temp: keys)."""
  if state is None:
    return None

  oauth_auth_id = os.environ.get("OAUTH_AUTH_ID")
  candidate_keys: list[str] = []
  for raw_id in (
      gemini_auth_id,
      oauth_auth_id,
      "testing-argolis_1775243150544",
      "gement-onemcp-auth-passthrough-argolis-v1",
  ):
    if raw_id:
      for candidate in (f"temp:{raw_id}", raw_id):
        if candidate not in candidate_keys:
          candidate_keys.append(candidate)

  for key in candidate_keys:
    try:
      val = state.get(key)
    except Exception:
      val = None
    if isinstance(val, str) and val.strip():
      logging.info(
          "DEBUG: Tool Call Auth Header resolved from key '%s' (starts with:"
          " %s...)",
          key,
          val[:10],
      )
      return val.strip()
    if isinstance(val, dict) and isinstance(val.get("access_token"), str):
      token = val["access_token"].strip()
      if token:
        logging.info(
            "DEBUG: Tool Call Auth Header resolved from dict key '%s' (starts"
            " with: %s...)",
            key,
            token[:10],
        )
        return token

  # Fallback: inspect state dictionary for any ephemeral temp:* or authorization keys
  state_dict: dict[str, Any] = {}
  if hasattr(state, "to_dict") and callable(state.to_dict):
    try:
      state_dict = state.to_dict() or {}
    except Exception:
      state_dict = {}
  elif isinstance(state, dict):
    state_dict = state

  if state_dict:
    logging.info(
        "DEBUG: Available session state keys: %s", list(state_dict.keys())
    )
    for key, val in state_dict.items():
      if key.startswith("temp:") or "auth" in key.lower():
        if isinstance(val, str) and len(val.strip()) > 20:
          logging.info(
              "DEBUG: Tool Call Auth Header resolved via fallback key '%s'"
              " (starts with: %s...)",
              key,
              val[:10],
          )
          return val.strip()
        if isinstance(val, dict) and isinstance(val.get("access_token"), str):
          token = val["access_token"].strip()
          if token:
            return token

  return None


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

  state = getattr(context, "state", None) if context else None
  user_token = _extract_user_oauth_token(state, gemini_auth_id)
  if user_token:
    headers["Authorization"] = f"Bearer {user_token}"
  else:
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
  """Create an ADK 2.x McpToolset with tool-list caching and event-loop-safe session pooling."""
  secops_mcp_url = f"https://chronicle.{region}.rep.googleapis.com/mcp"
  logging.info(
      "Initializing ADK 2.x McpToolset with URL: %s (cache TTL: %ss)",
      secops_mcp_url,
      tool_list_cache_ttl_seconds,
  )

  toolset_ref: list[McpToolset] = []
  last_loop_ref: list[Any] = [None]

  def _loop_safe_header_provider(context: Any) -> dict[str, str]:
    try:
      loop = asyncio.get_running_loop()
    except RuntimeError:
      loop = None
    if loop is not None and toolset_ref:
      prev_loop = last_loop_ref[0]() if callable(last_loop_ref[0]) else None
      if prev_loop is not loop or prev_loop.is_closed():
        session_mgr = getattr(toolset_ref[0], "_mcp_session_manager", None)
        sessions = getattr(session_mgr, "_sessions", None)
        if isinstance(sessions, dict) and sessions:
          logging.info(
              "Clearing %d pooled MCP session(s) from closed event loop",
              len(sessions),
          )
          sessions.clear()
        last_loop_ref[0] = weakref.ref(loop)
    return get_secops_headers(context)

  toolset = McpToolset(
      connection_params=StreamableHTTPConnectionParams(url=secops_mcp_url),
      header_provider=_loop_safe_header_provider,
      tool_filter=is_secops_tool_enabled,
      tool_list_cache_ttl_seconds=tool_list_cache_ttl_seconds,
      use_mcp_resources=False,
      errlog=None,  # explicitly None to prevent sys.stderr capturing (which cannot be pickled)
  )
  toolset_ref.append(toolset)
  return toolset


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
      model=EventLoopSafeGemini(
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
