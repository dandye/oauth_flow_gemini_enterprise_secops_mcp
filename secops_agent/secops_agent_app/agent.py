import logging
import os
from typing import Any

import google.auth
import google.auth.transport.requests
from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.agents.callback_context import CallbackContext
from google.adk.agents.context import Context
from google.adk.agents.context_cache_config import ContextCacheConfig
from google.adk.apps import App
from google.adk.apps.app import ResumabilityConfig
from google.adk.apps.compaction import EventsCompactionConfig
from google.adk.models import Gemini
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.planners import BuiltInPlanner
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.mcp_tool import mcp_session_manager
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.tool_context import ToolContext
from google.genai import types
from opentelemetry.instrumentation import google_genai as otel_genai

# Default TTL (seconds) for caching the remote Google SecOps MCP tools/list response.
DEFAULT_MCP_TOOL_CACHE_TTL_SECONDS = 300.0

# Default Gemini model for the SecOps agent.
DEFAULT_SECOPS_MODEL = "gemini-3.8-flash"

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

# Destructive SecOps MCP tools that can optionally require human-in-the-loop confirmation.
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
You have access to the remote Google Security Operations MCP server, which provides tools for SIEM event search, entity investigation, detection rule management, and SOAR case operations.
Always call the provided tools to fetch authoritative telemetry and case data from Google Security Operations rather than guessing.
When a tool requires projectId, customerId, or region, supply the active tenant identifiers from your instructions.
Feed administration and parser simulation tools (create_feed, update_feed, run_parser, list_feeds, get_feed, disable_feed, enable_feed) are disabled by policy to keep tool schemas compact.
"""


def get_disabled_secops_tools() -> frozenset[str]:
  """Return disabled SecOps MCP tools from policy and SECOPS_DISABLED_TOOLS."""
  extra_raw = os.environ.get("SECOPS_DISABLED_TOOLS", "")
  extra = {t.strip() for t in extra_raw.split(",") if t.strip()}
  return DISABLED_SECOPS_TOOLS | extra


def is_secops_tool_enabled(
    tool: BaseTool, readonly_context: Any = None
) -> bool:
  """Filter predicate passed to McpToolset(tool_filter=...) to exclude disabled tools."""
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
  """Block disabled tools and enforce confirmation on destructive SecOps tools."""
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
  """Convert SecOps MCP tool exceptions into structured error responses."""
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


def strip_mcp_output_schemas(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> LlmResponse | None:
  """Clear MCP output schemas on generate_content tool declarations."""
  del callback_context
  config = getattr(llm_request, "config", None)
  tools = getattr(config, "tools", None) if config is not None else None
  if not tools:
    return None
  for tool in tools:
    func_decls = getattr(tool, "function_declarations", None)
    if not func_decls:
      continue
    for fd in func_decls:
      if hasattr(fd, "response_json_schema"):
        fd.response_json_schema = None
      if hasattr(fd, "response"):
        fd.response = None
  return None


def _clear_mcp_tool_output_schema(raw_tool: Any) -> None:
  """Clear output_schema and outputSchema attributes on an MCP tool object."""
  if raw_tool is None:
    return
  for attr in ("output_schema", "outputSchema"):
    if hasattr(raw_tool, attr):
      setattr(raw_tool, attr, None)


def _clear_session_output_schemas(
    session: Any,
    tool_names: set[str] | frozenset[str],
) -> None:
  """Nullify cached tool output schemas on a single MCP ClientSession."""
  schemas = getattr(session, "_tool_output_schemas", None)
  if not isinstance(schemas, dict):
    return
  for key in list(schemas):
    schemas[key] = None
  for tool_name in tool_names:
    schemas[tool_name] = None


class _SecOpsMcpSessionManager(mcp_session_manager.MCPSessionManager):
  """MCPSessionManager that clears output schemas on newly created sessions."""

  def __init__(self, *args: Any, **kwargs: Any) -> None:
    super().__init__(*args, **kwargs)
    self._known_tool_names: set[str] = set()

  async def create_session(self, headers: dict[str, str] | None = None) -> Any:
    """Create or reuse a per-loop MCP session with output schemas disabled."""
    session = await super().create_session(headers=headers)
    _clear_session_output_schemas(session, self._known_tool_names)
    return session


class SecOpsMcpToolset(McpToolset):
  """Scoped McpToolset that disables MCP output-schema validation per toolset.

  Streaming Google Security Operations MCP tools such as list_security_alerts
  return text progress chunks in result.content without structuredContent.
  Clearing outputSchema / output_schema on listed tools and nullifying
  _tool_output_schemas on pooled sessions prevents MCP 2.x validate_tool_result
  RuntimeErrors without mutating global ClientSession state.
  """

  def __init__(self, *args: Any, **kwargs: Any) -> None:
    super().__init__(*args, **kwargs)
    old_mgr = self._mcp_session_manager
    self._mcp_session_manager = _SecOpsMcpSessionManager(
        connection_params=self._connection_params,
        errlog=self._errlog,
        sampling_callback=self._sampling_callback,
        sampling_capabilities=self._sampling_capabilities,
        elicitation_callback=self._elicitation_callback,
        message_handler=getattr(old_mgr, "_message_handler", None),
    )

  async def get_tools(
      self,
      readonly_context: Any = None,
  ) -> list[BaseTool]:
    """Return enabled SecOps MCP tools with output schemas cleared."""
    tools = await super().get_tools(readonly_context=readonly_context)
    tool_names: set[str] = set()
    for tool in tools:
      tool_name = getattr(tool, "name", None)
      if isinstance(tool_name, str) and tool_name:
        tool_names.add(tool_name)
      _clear_mcp_tool_output_schema(getattr(tool, "_mcp_tool", None))

    for cached in getattr(self, "_tool_list_cache", {}).values():
      for raw_tool in getattr(cached, "tools", ()) or ():
        raw_name = getattr(raw_tool, "name", None)
        if isinstance(raw_name, str) and raw_name:
          tool_names.add(raw_name)
        _clear_mcp_tool_output_schema(raw_tool)

    session_mgr = getattr(self, "_mcp_session_manager", None)
    known_names = getattr(session_mgr, "_known_tool_names", None)
    if isinstance(known_names, set):
      known_names.update(tool_names)

    sessions = getattr(session_mgr, "_sessions", None)
    if isinstance(sessions, dict):
      for entry in sessions.values():
        session = entry[0] if isinstance(entry, tuple) and entry else entry
        _clear_session_output_schemas(session, tool_names)

    return tools


def get_secops_headers(context: Any) -> dict[str, str]:
  """Build HTTP headers for Google SecOps MCP requests with OAuth passthrough.

  When GEMINI_AUTHORIZATION_ID or OAUTH_AUTH_ID is configured, a delegated user
  OAuth access token must be present in context.state ('temp:<auth_id>' or
  '<auth_id>'). Application Default Credentials (ADC) are never attached unless
  SECOPS_ALLOW_ADC_FALLBACK=true is explicitly enabled for local CLI testing.
  """
  chronicle_project_id = os.environ.get("CHRONICLE_PROJECT_ID")
  auth_id = os.environ.get("GEMINI_AUTHORIZATION_ID") or os.environ.get(
      "OAUTH_AUTH_ID"
  )
  allow_adc_fallback = (
      os.environ.get("SECOPS_ALLOW_ADC_FALLBACK", "false").lower() == "true"
  )

  headers = {"Accept": "text/event-stream", "Content-Type": "application/json"}

  if chronicle_project_id:
    headers["x-goog-user-project"] = chronicle_project_id
  else:
    logging.critical(
        "CHRONICLE_PROJECT_ID is missing from environment; Google SecOps MCP"
        " tool calls require an x-goog-user-project header."
    )

  user_token = None
  if auth_id and context and getattr(context, "state", None):
    user_token = context.state.get(f"temp:{auth_id}") or context.state.get(
        auth_id
    )

  if user_token:
    headers["Authorization"] = f"Bearer {user_token}"
    return headers

  if auth_id:
    logging.warning(
        "OAuth authorization ID '%s' is configured, but no delegated user"
        " token was found in context.state ('temp:%s' or '%s').",
        auth_id,
        auth_id,
        auth_id,
    )

  if not allow_adc_fallback:
    return headers

  try:
    creds, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    creds.refresh(google.auth.transport.requests.Request())
    if creds.token:
      headers["Authorization"] = f"Bearer {creds.token}"
  except Exception as exc:
    logging.warning(
        "SECOPS_ALLOW_ADC_FALLBACK is enabled, but ADC token refresh failed:"
        " %s",
        exc,
    )

  return headers


def create_mcp_toolset(
    region: str,
    tool_list_cache_ttl_seconds: float = DEFAULT_MCP_TOOL_CACHE_TTL_SECONDS,
) -> SecOpsMcpToolset:
  """Create a scoped ADK 2.x SecOpsMcpToolset for the regional MCP endpoint."""
  secops_mcp_url = (
      os.environ.get("SECOPS_MCP_URL", "").strip()
      or f"https://{region}-chronicle.googleapis.com/mcp"
  )
  logging.info(
      "Initializing ADK 2.x SecOpsMcpToolset with URL: %s (cache TTL: %ss)",
      secops_mcp_url,
      tool_list_cache_ttl_seconds,
  )

  return SecOpsMcpToolset(
      connection_params=mcp_session_manager.StreamableHTTPConnectionParams(
          url=secops_mcp_url
      ),
      header_provider=get_secops_headers,
      tool_filter=is_secops_tool_enabled,
      tool_list_cache_ttl_seconds=tool_list_cache_ttl_seconds,
      use_mcp_resources=False,
      errlog=None,  # Prevent sys.stderr capture so the toolset remains picklable.
  )


def _build_thinking_config(model_name: str) -> types.ThinkingConfig:
  """Build a model-appropriate ThinkingConfig for Gemini 3 or Gemini 4."""
  include_thoughts = (
      os.environ.get("SECOPS_INCLUDE_THOUGHTS", "false").lower() == "true"
  )
  if model_name.startswith("gemini-4"):
    thinking_level = (
        os.environ.get("SECOPS_THINKING_LEVEL", "MEDIUM").strip().upper()
    )
    return types.ThinkingConfig(
        include_thoughts=include_thoughts,
        thinking_level=thinking_level,
    )
  thinking_budget = int(os.environ.get("SECOPS_THINKING_BUDGET", "1024"))
  return types.ThinkingConfig(
      include_thoughts=include_thoughts,
      thinking_budget=thinking_budget,
  )


def create_agent() -> Agent:
  """Create the ADK 2.x Google Security Operations LlmAgent."""
  load_dotenv()
  use_interactions_api = (
      os.environ.get("SECOPS_USE_INTERACTIONS_API", "true").lower() == "true"
  )
  if use_interactions_api:
    # Gemini Interactions API (convert_tools_config_to_interactions_format)
    # requires standard lowercase JSON Schema in func_decl.parameters_json_schema
    # (produced when FeatureName.JSON_SCHEMA_FOR_FUNC_DECL is enabled) and
    # drops func_decl.response_json_schema (outputSchema) automatically.
    os.environ.pop("ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL", None)

  project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get(
      "GCP_PROJECT_ID"
  )
  if not project_id and os.environ.get("REASONING_ENGINE_DEPLOYMENT") != "True":
    try:
      _, project_id = google.auth.default()
    except Exception:
      project_id = None

  os.environ["GOOGLE_CLOUD_PROJECT"] = project_id or ""
  os.environ["GOOGLE_CLOUD_LOCATION"] = "global"
  os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"

  if os.environ.get("REASONING_ENGINE_DEPLOYMENT") != "True":
    otel_genai.GoogleGenAiSdkInstrumentor().instrument()

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

  model_name = (
      os.environ.get("SECOPS_MODEL", "").strip() or DEFAULT_SECOPS_MODEL
  )
  tenant_instruction = f"""Current Tenant Information:
- Project ID: {chronicle_project_id}
- Customer ID: {customer_id}
- Region: {region}
"""

  # When use_interactions_api=True, ADK's _get_latest_user_contents slices the
  # trailing user messages for previous_interaction_id chaining. If both
  # static_instruction and instruction are set, ADK appends instruction as a
  # trailing user text message after function_response parts. Unifying them into
  # instruction keeps the full prompt in system_instruction across chained turns.
  if use_interactions_api:
    static_instruction = None
    full_instruction = f"{STATIC_SECOPS_INSTRUCTION}\n{tenant_instruction}"
    before_model_callback = None
  else:
    static_instruction = STATIC_SECOPS_INSTRUCTION
    full_instruction = tenant_instruction
    before_model_callback = strip_mcp_output_schemas

  return Agent(
      name="secops_agent",
      model=Gemini(
          model=model_name,
          use_interactions_api=use_interactions_api,
          client_kwargs={"location": "global"},
          retry_options=types.HttpRetryOptions(attempts=3),
      ),
      static_instruction=static_instruction,
      instruction=full_instruction,
      planner=BuiltInPlanner(
          thinking_config=_build_thinking_config(model_name),
      ),
      tools=[secops_toolset],
      before_model_callback=before_model_callback,
      before_tool_callback=confirm_destructive_secops_tool,
      on_tool_error_callback=handle_secops_tool_error,
  )


def create_app() -> App:
  """Create the ADK 2.x App with context caching, compaction, and resumability."""
  root_agent = create_agent()
  use_interactions_api = getattr(
      root_agent.model, "use_interactions_api", False
  )
  context_cache_config = (
      None
      if use_interactions_api
      else ContextCacheConfig(
          min_tokens=4096,
          ttl_seconds=1800,
          cache_intervals=10,
      )
  )
  return App(
      name="secops_agent_app",
      root_agent=root_agent,
      context_cache_config=context_cache_config,
      events_compaction_config=EventsCompactionConfig(
          compaction_interval=10,
          overlap_size=2,
      ),
      resumability_config=ResumabilityConfig(is_resumable=True),
  )
