"""Unit test suite for oauth_flow_gemini_enterprise_secops_mcp."""

from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from oauth_flow_gemini_enterprise_secops_mcp.cli import app
from oauth_flow_gemini_enterprise_secops_mcp.core import get_secops_mcp_endpoint
from oauth_flow_gemini_enterprise_secops_mcp.core import run_pipeline
from secops_agent.secops_agent_app.agent import DISABLED_SECOPS_TOOLS
from secops_agent.secops_agent_app.agent import _requires_tool_confirmation
from secops_agent.secops_agent_app.agent import confirm_destructive_secops_tool
from secops_agent.secops_agent_app.agent import create_agent
from secops_agent.secops_agent_app.agent import create_app
from secops_agent.secops_agent_app.agent import get_secops_headers
from secops_agent.secops_agent_app.agent import handle_secops_tool_error
from secops_agent.secops_agent_app.agent import is_secops_tool_enabled

runner = CliRunner()


def test_run_pipeline() -> None:
  result = run_pipeline("developer")
  assert "developer" in result
  assert (
      "oauth_flow_gemini_enterprise_secops_mcp initialized successfully."
      in result
  )


def test_get_secops_mcp_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
  monkeypatch.setenv("CHRONICLE_REGION", "europe")
  assert (
      get_secops_mcp_endpoint()
      == "https://chronicle.europe.rep.googleapis.com/mcp"
  )
  assert (
      get_secops_mcp_endpoint("us")
      == "https://chronicle.us.rep.googleapis.com/mcp"
  )


def test_cli_info() -> None:
  result = runner.invoke(app, ["info"])
  assert result.exit_code == 0
  assert "oauth_flow_gemini_enterprise_secops_mcp" in result.stdout


def test_cli_version() -> None:
  result = runner.invoke(app, ["version"])
  assert result.exit_code == 0
  assert "0.1.0" in result.stdout


def test_get_secops_headers_with_oauth_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  monkeypatch.setenv("CHRONICLE_PROJECT_ID", "test-chronicle-project")
  monkeypatch.setenv(
      "CHRONICLE_CUSTOMER_ID", "00000000-0000-0000-0000-000000000000"
  )
  monkeypatch.setenv("GEMINI_AUTHORIZATION_ID", "test-auth-id")
  context = SimpleNamespace(
      state={"test-auth-id": "test-oauth-bearer-token-12345"}
  )

  headers = get_secops_headers(context)
  assert headers["x-goog-user-project"] == "test-chronicle-project"
  assert headers["Authorization"] == "Bearer test-oauth-bearer-token-12345"
  assert headers["Accept"] == "text/event-stream"


def test_adk_v2_create_app_and_agent_features(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  monkeypatch.setenv("REASONING_ENGINE_DEPLOYMENT", "True")
  monkeypatch.setenv("CHRONICLE_PROJECT_ID", "test-chronicle-project")
  monkeypatch.setenv(
      "CHRONICLE_CUSTOMER_ID", "00000000-0000-0000-0000-000000000000"
  )
  adk_app = create_app()
  assert adk_app.name == "secops_agent_app"
  assert adk_app.context_cache_config is not None
  assert adk_app.context_cache_config.min_tokens == 4096
  assert adk_app.context_cache_config.ttl_seconds == 1800
  assert adk_app.events_compaction_config is not None
  assert adk_app.events_compaction_config.compaction_interval == 10
  assert adk_app.resumability_config is not None
  assert adk_app.resumability_config.is_resumable is True

  agent = create_agent()
  assert agent.static_instruction is not None
  assert "Google ADK 2.x" in str(agent.static_instruction)
  assert agent.planner is not None
  assert agent.before_tool_callback is confirm_destructive_secops_tool
  assert agent.on_tool_error_callback is handle_secops_tool_error
  mcp_toolset = agent.tools[0]
  assert mcp_toolset._tool_list_cache_ttl_seconds == 300.0
  assert mcp_toolset._use_mcp_resources is False
  assert mcp_toolset.tool_filter is is_secops_tool_enabled


def test_disabled_feed_tools(monkeypatch: pytest.MonkeyPatch) -> None:
  monkeypatch.setenv("REASONING_ENGINE_DEPLOYMENT", "True")
  assert "create_feed" in DISABLED_SECOPS_TOOLS
  assert "update_feed" in DISABLED_SECOPS_TOOLS

  create_feed_tool = SimpleNamespace(name="create_feed")
  update_feed_tool = SimpleNamespace(name="update_feed")
  list_feeds_tool = SimpleNamespace(name="list_feeds")

  assert is_secops_tool_enabled(create_feed_tool) is False
  assert is_secops_tool_enabled(update_feed_tool) is False
  assert is_secops_tool_enabled(list_feeds_tool) is True

  agent = create_agent()
  mcp_toolset = agent.tools[0]
  assert mcp_toolset._is_tool_selected(create_feed_tool, None) is False
  assert mcp_toolset._is_tool_selected(update_feed_tool, None) is False
  assert mcp_toolset._is_tool_selected(list_feeds_tool, None) is True

  fake_ctx = SimpleNamespace(
      tool_confirmation=None,
      actions=SimpleNamespace(skip_summarization=False),
  )
  for disabled_tool in (create_feed_tool, update_feed_tool):
    resp = confirm_destructive_secops_tool(disabled_tool, {}, fake_ctx)
    assert resp is not None
    assert resp["status"] == "disabled"
    assert resp["tool"] == disabled_tool.name

  monkeypatch.setenv("SECOPS_DISABLED_TOOLS", "delete_feed, disable_feed")
  delete_feed_tool = SimpleNamespace(name="delete_feed")
  assert is_secops_tool_enabled(delete_feed_tool) is False
  assert is_secops_tool_enabled(create_feed_tool) is False


def test_adk_v2_tool_error_callback_and_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  fake_tool = SimpleNamespace(name="udm_search")
  err_resp = handle_secops_tool_error(
      fake_tool,
      {"query": "metadata.event_type = 'USER_LOGIN'"},
      None,
      RuntimeError("MCP stream timeout"),
  )
  assert err_resp == {
      "status": "error",
      "tool": "udm_search",
      "error_type": "RuntimeError",
      "message": "MCP stream timeout",
  }

  monkeypatch.setenv("SECOPS_REQUIRE_DESTRUCTIVE_CONFIRMATION", "true")
  assert _requires_tool_confirmation("delete_feed") is True
  assert _requires_tool_confirmation("udm_search") is False

  # 1. Non-destructive tool returns None immediately
  captured: list[dict[str, object]] = []
  fake_ctx = SimpleNamespace(
      tool_confirmation=None,
      actions=SimpleNamespace(skip_summarization=False),
      request_confirmation=lambda **kwargs: captured.append(kwargs),
  )
  assert (
      confirm_destructive_secops_tool(fake_tool, {"query": "x"}, fake_ctx)
      is None
  )
  assert len(captured) == 0

  # 2. Destructive tool without confirmation requests HITL confirmation and pauses
  destructive_tool = SimpleNamespace(name="delete_feed")
  pause_resp = confirm_destructive_secops_tool(
      destructive_tool,
      {"name": "feeds/123"},
      fake_ctx,
  )
  assert pause_resp is not None
  assert pause_resp["status"] == "confirmation_required"
  assert pause_resp["tool"] == "delete_feed"
  assert fake_ctx.actions.skip_summarization is True
  assert len(captured) == 1
  assert captured[0]["payload"] == {
      "tool_name": "delete_feed",
      "args": {"name": "feeds/123"},
  }

  # 3. Destructive tool with rejected confirmation returns rejected status
  rejected_ctx = SimpleNamespace(
      tool_confirmation=SimpleNamespace(confirmed=False),
      actions=SimpleNamespace(skip_summarization=False),
  )
  reject_resp = confirm_destructive_secops_tool(
      destructive_tool,
      {"name": "feeds/123"},
      rejected_ctx,
  )
  assert reject_resp is not None
  assert reject_resp["status"] == "rejected"

  # 4. Destructive tool with approved confirmation returns None (proceeds)
  approved_ctx = SimpleNamespace(
      tool_confirmation=SimpleNamespace(confirmed=True),
      actions=SimpleNamespace(skip_summarization=False),
  )
  assert (
      confirm_destructive_secops_tool(
          destructive_tool,
          {"name": "feeds/123"},
          approved_ctx,
      )
      is None
  )
