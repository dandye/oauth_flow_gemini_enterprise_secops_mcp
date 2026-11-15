"""Unit tests for the Google Security Operations ADK 2.x MCP runtime."""

import logging
from types import SimpleNamespace
from typing import Any

import anyio
import cloudpickle
import google.auth
import mcp.types as mcp_types
import pytest
from google.adk.models import Gemini
from google.adk.models.llm_request import LlmRequest
from google.adk.tools.mcp_tool import McpToolset
from google.adk.utils._event_loop_cache import PerLoopCachedProperty
from google.genai import types
from mcp.client.session import ClientSession

import secops_agent.secops_agent_app.agent as agent_module
from oauth_flow_gemini_enterprise_secops_mcp.core import get_secops_mcp_endpoint
from secops_agent.secops_agent_app.agent import DEFAULT_SECOPS_MODEL
from secops_agent.secops_agent_app.agent import DESTRUCTIVE_SECOPS_TOOLS
from secops_agent.secops_agent_app.agent import DISABLED_SECOPS_TOOLS
from secops_agent.secops_agent_app.agent import STATIC_SECOPS_INSTRUCTION
from secops_agent.secops_agent_app.agent import SecOpsMcpToolset
from secops_agent.secops_agent_app.agent import confirm_destructive_secops_tool
from secops_agent.secops_agent_app.agent import create_agent
from secops_agent.secops_agent_app.agent import create_app
from secops_agent.secops_agent_app.agent import create_mcp_toolset
from secops_agent.secops_agent_app.agent import get_disabled_secops_tools
from secops_agent.secops_agent_app.agent import get_secops_headers
from secops_agent.secops_agent_app.agent import is_secops_tool_enabled
from secops_agent.secops_agent_app.agent import strip_mcp_output_schemas


def _clear_secops_env(monkeypatch: pytest.MonkeyPatch) -> None:
  for key in (
      "CHRONICLE_PROJECT_ID",
      "CHRONICLE_CUSTOMER_ID",
      "CHRONICLE_REGION",
      "SECOPS_MCP_URL",
      "GEMINI_AUTHORIZATION_ID",
      "OAUTH_AUTH_ID",
      "SECOPS_ALLOW_ADC_FALLBACK",
      "SECOPS_USE_INTERACTIONS_API",
      "SECOPS_MODEL",
      "SECOPS_THINKING_BUDGET",
      "SECOPS_THINKING_LEVEL",
      "SECOPS_INCLUDE_THOUGHTS",
      "SECOPS_DISABLED_TOOLS",
      "SECOPS_REQUIRE_DESTRUCTIVE_CONFIRMATION",
  ):
    monkeypatch.delenv(key, raising=False)
  monkeypatch.setattr(agent_module, "load_dotenv", lambda *_, **__: False)


def test_locational_mcp_endpoint_and_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  _clear_secops_env(monkeypatch)
  assert get_secops_mcp_endpoint() == "https://us-chronicle.googleapis.com/mcp"
  assert (
      get_secops_mcp_endpoint("europe-west2")
      == "https://europe-west2-chronicle.googleapis.com/mcp"
  )

  toolset_us = create_mcp_toolset("us")
  assert isinstance(toolset_us, SecOpsMcpToolset)
  assert (
      toolset_us._connection_params.url
      == "https://us-chronicle.googleapis.com/mcp"
  )
  assert toolset_us._header_provider is get_secops_headers

  monkeypatch.setenv(
      "SECOPS_MCP_URL", "  https://secops-gateway.example.com/mcp  "
  )
  assert (
      get_secops_mcp_endpoint("asia-southeast1")
      == "https://secops-gateway.example.com/mcp"
  )
  toolset_override = create_mcp_toolset("asia-southeast1")
  assert (
      toolset_override._connection_params.url
      == "https://secops-gateway.example.com/mcp"
  )


def test_get_secops_headers_temp_precedence_and_oauth_auth_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  _clear_secops_env(monkeypatch)
  monkeypatch.setenv("CHRONICLE_PROJECT_ID", "secops-tenant-proj")
  monkeypatch.setenv("OAUTH_AUTH_ID", "secops-oauth-id")

  both_state = SimpleNamespace(
      state={
          "secops-oauth-id": "persisted-bearer-value",
          "temp:secops-oauth-id": "ephemeral-bearer-value",
      }
  )
  headers = get_secops_headers(both_state)
  assert headers["x-goog-user-project"] == "secops-tenant-proj"
  assert headers["Authorization"] == "Bearer ephemeral-bearer-value"

  fallback_state = SimpleNamespace(
      state={"secops-oauth-id": "persisted-bearer-value"}
  )
  persisted_headers = get_secops_headers(fallback_state)
  assert persisted_headers["Authorization"] == "Bearer persisted-bearer-value"


def test_get_secops_headers_fails_fast_when_user_token_missing(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
  _clear_secops_env(monkeypatch)
  monkeypatch.setenv("CHRONICLE_PROJECT_ID", "secops-tenant-proj")
  monkeypatch.setenv("GEMINI_AUTHORIZATION_ID", "ge-secops-auth")

  def _unexpected_adc(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("google.auth.default must not be called by default")

  monkeypatch.setattr(google.auth, "default", _unexpected_adc)

  with caplog.at_level(logging.WARNING):
    headers = get_secops_headers(SimpleNamespace(state={}))

  assert "Authorization" not in headers
  assert headers["x-goog-user-project"] == "secops-tenant-proj"
  assert any(
      "ge-secops-auth" in record.getMessage()
      and record.levelno == logging.WARNING
      for record in caplog.records
  )


def test_get_secops_headers_adc_fallback_opt_in(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
  _clear_secops_env(monkeypatch)

  class _FakeCreds:

    def __init__(self) -> None:
      self.token: str | None = None

    def refresh(self, request: Any) -> None:
      del request
      self.token = "local-adc-access-value"  # noqa: S105

  monkeypatch.setattr(
      google.auth, "default", lambda scopes=None: (_FakeCreds(), "adc-proj")
  )

  # Without SECOPS_ALLOW_ADC_FALLBACK, no Authorization header is attached even
  # when auth_id is unconfigured.
  with caplog.at_level(logging.CRITICAL):
    no_fallback_headers = get_secops_headers(None)
  assert "Authorization" not in no_fallback_headers
  assert "x-goog-user-project" not in no_fallback_headers
  assert any(
      "CHRONICLE_PROJECT_ID" in record.getMessage() for record in caplog.records
  )

  # With SECOPS_ALLOW_ADC_FALLBACK=true and no auth_id, local CLI testing uses ADC.
  monkeypatch.setenv("CHRONICLE_PROJECT_ID", "secops-tenant-proj")
  monkeypatch.setenv("SECOPS_ALLOW_ADC_FALLBACK", "true")
  adc_headers = get_secops_headers(None)
  assert adc_headers["Authorization"] == "Bearer local-adc-access-value"

  # With auth_id configured + missing user token + SECOPS_ALLOW_ADC_FALLBACK=true,
  # a warning is logged and ADC fallback still attaches credentials.
  caplog.clear()
  monkeypatch.setenv("GEMINI_AUTHORIZATION_ID", "ge-secops-auth")
  with caplog.at_level(logging.WARNING):
    warn_adc_headers = get_secops_headers(SimpleNamespace(state={}))
  assert warn_adc_headers["Authorization"] == "Bearer local-adc-access-value"
  assert any(
      "ge-secops-auth" in record.getMessage() for record in caplog.records
  )


def test_strip_mcp_output_schemas_and_generate_content_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  _clear_secops_env(monkeypatch)
  monkeypatch.setenv("REASONING_ENGINE_DEPLOYMENT", "True")
  monkeypatch.setenv("CHRONICLE_PROJECT_ID", "secops-tenant-proj")
  monkeypatch.setenv(
      "CHRONICLE_CUSTOMER_ID", "a1b2c3d4-e5f6-4321-abcd-ef1234567890"
  )
  monkeypatch.setenv("SECOPS_USE_INTERACTIONS_API", "false")

  adk_app = create_app()
  assert adk_app.context_cache_config is not None
  assert adk_app.context_cache_config.min_tokens == 4096

  agent = adk_app.root_agent
  assert type(agent.model) is Gemini
  assert agent.model.model == DEFAULT_SECOPS_MODEL
  assert agent.model.model == "gemini-3.8-flash"
  assert agent.model.use_interactions_api is False
  assert agent.static_instruction == STATIC_SECOPS_INSTRUCTION
  assert "Google Security Operations" in STATIC_SECOPS_INSTRUCTION
  assert agent.before_model_callback is strip_mcp_output_schemas

  func_decl = types.FunctionDeclaration(
      name="list_security_alerts",
      description="List Google SecOps alerts.",
      parameters_json_schema={
          "type": "object",
          "properties": {"max_results": {"type": "integer"}},
      },
      response_json_schema={
          "type": "object",
          "properties": {"alerts": {"type": "array"}},
      },
      response=types.Schema(type=types.Type.OBJECT),
  )
  llm_request = LlmRequest(
      model="gemini-3.8-flash",
      config=types.GenerateContentConfig(
          tools=[types.Tool(function_declarations=[func_decl])]
      ),
  )

  result = strip_mcp_output_schemas(
      callback_context=SimpleNamespace(),  # type: ignore[arg-type]
      llm_request=llm_request,
  )
  assert result is None
  cleaned_decl = llm_request.config.tools[0].function_declarations[0]
  assert cleaned_decl.response_json_schema is None
  assert cleaned_decl.response is None
  assert cleaned_decl.parameters_json_schema == {
      "type": "object",
      "properties": {"max_results": {"type": "integer"}},
  }

  # Empty LlmRequest without tools is a safe no-op.
  empty_request = LlmRequest(model="gemini-3.8-flash")
  assert (
      strip_mcp_output_schemas(
          callback_context=SimpleNamespace(),  # type: ignore[arg-type]
          llm_request=empty_request,
      )
      is None
  )


@pytest.mark.asyncio
async def test_secops_mcp_toolset_clears_output_schemas_without_global_patch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  _clear_secops_env(monkeypatch)
  monkeypatch.setenv("CHRONICLE_PROJECT_ID", "secops-tenant-proj")

  # Confirm legacy wrappers were removed and ADK 2.14+ caches per loop natively.
  assert not hasattr(agent_module, "EventLoopSafeGemini")
  assert not hasattr(agent_module, "_loop_safe_header_provider")
  assert isinstance(Gemini.__dict__["api_client"], PerLoopCachedProperty)

  # Confirm global ClientSession.validate_tool_result is NOT monkeypatched:
  # an unrelated ClientSession still enforces outputSchema validation.
  c2s_send, c2s_recv = anyio.create_memory_object_stream(10)
  s2c_send, s2c_recv = anyio.create_memory_object_stream(10)
  unrelated_session = ClientSession(s2c_recv, c2s_send)
  unrelated_session._tool_output_schemas["strict_tool"] = {
      "type": "object",
      "properties": {"ok": {"type": "boolean"}},
      "required": ["ok"],
  }
  text_only_result = mcp_types.CallToolResult(
      content=[mcp_types.TextContent(type="text", text="progress chunk")]
  )
  with pytest.raises(RuntimeError, match="did not return structured content"):
    await unrelated_session.validate_tool_result(
        "strict_tool", text_only_result
    )
  await c2s_send.aclose()
  await c2s_recv.aclose()
  await s2c_send.aclose()
  await s2c_recv.aclose()

  # Now verify SecOpsMcpToolset clears output_schema on tools and pooled sessions.
  raw_tools = [
      mcp_types.Tool(
          name="list_security_alerts",
          description="Stream SecOps security alerts.",
          inputSchema={"type": "object", "properties": {}},
          outputSchema={
              "type": "object",
              "properties": {"alerts": {"type": "array"}},
              "required": ["alerts"],
          },
      ),
      mcp_types.Tool(
          name="udm_search",
          description="Search SecOps UDM events.",
          inputSchema={
              "type": "object",
              "properties": {"query": {"type": "string"}},
          },
          outputSchema={
              "type": "object",
              "properties": {"events": {"type": "array"}},
          },
      ),
      mcp_types.Tool(
          name="create_feed",
          description="Disabled feed tool.",
          inputSchema={"type": "object", "properties": {}},
          outputSchema={"type": "object", "properties": {}},
      ),
  ]

  pc2s_send, pc2s_recv = anyio.create_memory_object_stream(10)
  ps2c_send, ps2c_recv = anyio.create_memory_object_stream(10)
  pooled_session = ClientSession(ps2c_recv, pc2s_send)
  pooled_session._tool_output_schemas = {
      "list_security_alerts": {"type": "object", "required": ["alerts"]},
      "udm_search": {"type": "object"},
  }

  toolset = create_mcp_toolset("us")

  async def _fake_execute_with_session(
      *args: Any, **kwargs: Any
  ) -> mcp_types.ListToolsResult:
    del args, kwargs
    return mcp_types.ListToolsResult(tools=raw_tools)

  monkeypatch.setattr(
      McpToolset, "_execute_with_session", _fake_execute_with_session
  )
  toolset._mcp_session_manager._sessions["pooled-key"] = (
      pooled_session,
      None,  # type: ignore[assignment]
      None,  # type: ignore[assignment]
  )

  tools = await toolset.get_tools()
  assert [t.name for t in tools] == ["list_security_alerts", "udm_search"]
  for tool in tools:
    assert tool._mcp_tool.output_schema is None
    decl = tool._get_declaration()
    assert decl.response_json_schema is None

  # Pooled session has None output schemas so MCP 2.3 validate_tool_result succeeds
  # on streaming text chunks without calling list_tools() or raising RuntimeError.
  assert pooled_session._tool_output_schemas["list_security_alerts"] is None
  assert pooled_session._tool_output_schemas["udm_search"] is None
  await pooled_session.validate_tool_result(
      "list_security_alerts", text_only_result
  )

  # Newly created sessions after a tool-list cache hit also inherit None output
  # schemas for known tools via _SecOpsMcpSessionManager.create_session.
  nc2s_send, nc2s_recv = anyio.create_memory_object_stream(10)
  ns2c_send, ns2c_recv = anyio.create_memory_object_stream(10)
  fresh_session = ClientSession(ns2c_recv, nc2s_send)

  async def _fake_super_create_session(
      self: Any, headers: dict[str, str] | None = None
  ) -> ClientSession:
    del self, headers
    return fresh_session

  monkeypatch.setattr(
      agent_module.mcp_session_manager.MCPSessionManager,
      "create_session",
      _fake_super_create_session,
  )
  created = await toolset._mcp_session_manager.create_session(headers={})
  assert created is fresh_session
  assert created._tool_output_schemas["list_security_alerts"] is None
  await created.validate_tool_result("list_security_alerts", text_only_result)
  await nc2s_send.aclose()
  await nc2s_recv.aclose()
  await ns2c_send.aclose()
  await ns2c_recv.aclose()

  # CamelCase outputSchema attribute on custom/mock _mcp_tool is also cleared.
  camel_raw = SimpleNamespace(
      name="legacy_tool",
      outputSchema={"type": "object"},
  )
  agent_module._clear_mcp_tool_output_schema(camel_raw)
  assert camel_raw.outputSchema is None

  await pc2s_send.aclose()
  await pc2s_recv.aclose()
  await ps2c_send.aclose()
  await ps2c_recv.aclose()


def test_disabled_tools_and_hitl_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  _clear_secops_env(monkeypatch)
  assert "create_feed" in DISABLED_SECOPS_TOOLS
  assert "delete_feed" in DESTRUCTIVE_SECOPS_TOOLS

  monkeypatch.setenv("SECOPS_DISABLED_TOOLS", " custom_alpha , custom_beta , ")
  disabled = get_disabled_secops_tools()
  assert "custom_alpha" in disabled
  assert "custom_beta" in disabled
  assert is_secops_tool_enabled(SimpleNamespace(name="custom_alpha")) is False
  assert is_secops_tool_enabled(SimpleNamespace(name="udm_search")) is True

  ctx = SimpleNamespace(
      tool_confirmation=None,
      actions=SimpleNamespace(skip_summarization=False),
      request_confirmation=lambda **_: None,
  )
  # When SECOPS_REQUIRE_DESTRUCTIVE_CONFIRMATION is unset/false, destructive tools run without pause.
  assert (
      confirm_destructive_secops_tool(
          SimpleNamespace(name="delete_feed"), {"id": "1"}, ctx
      )
      is None
  )


def test_gemini_3_and_gemini_4_thinking_configs_and_pickling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  _clear_secops_env(monkeypatch)
  monkeypatch.setenv("REASONING_ENGINE_DEPLOYMENT", "True")
  monkeypatch.setenv("CHRONICLE_PROJECT_ID", "secops-tenant-proj")
  monkeypatch.setenv(
      "CHRONICLE_CUSTOMER_ID", "a1b2c3d4-e5f6-4321-abcd-ef1234567890"
  )

  # Default Gemini 3.8 Flash uses thinking_budget=1024 without thinking_level.
  default_agent = create_agent()
  assert default_agent.model.model == "gemini-3.8-flash"
  g3_cfg = default_agent.planner.thinking_config
  assert g3_cfg.thinking_budget == 1024
  assert g3_cfg.thinking_level is None
  assert g3_cfg.include_thoughts is False

  # Custom Gemini 3 thinking budget + include_thoughts.
  monkeypatch.setenv("SECOPS_THINKING_BUDGET", "2048")
  monkeypatch.setenv("SECOPS_INCLUDE_THOUGHTS", "true")
  custom_g3_agent = create_agent()
  assert custom_g3_agent.planner.thinking_config.thinking_budget == 2048
  assert custom_g3_agent.planner.thinking_config.include_thoughts is True

  # Gemini 4 uses thinking_level (default MEDIUM, overridable via SECOPS_THINKING_LEVEL)
  # and omits thinking_budget.
  monkeypatch.setenv("SECOPS_MODEL", "gemini-4-flash")
  g4_default_agent = create_agent()
  g4_cfg = g4_default_agent.planner.thinking_config
  assert g4_default_agent.model.model == "gemini-4-flash"
  assert g4_cfg.thinking_level == types.ThinkingLevel.MEDIUM
  assert g4_cfg.thinking_budget is None

  monkeypatch.setenv("SECOPS_THINKING_LEVEL", "high")
  g4_high_agent = create_agent()
  assert (
      g4_high_agent.planner.thinking_config.thinking_level
      == types.ThinkingLevel.HIGH
  )
  assert g4_high_agent.planner.thinking_config.thinking_budget is None

  # Verify cloudpickle serialization succeeds for Vertex AI Reasoning Engine deployment.
  serialized = cloudpickle.dumps(create_app())
  assert isinstance(serialized, bytes)
  assert len(serialized) > 0
