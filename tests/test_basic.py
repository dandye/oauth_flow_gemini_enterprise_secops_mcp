"""Unit test suite for oauth_flow_gemini_enterprise_secops_mcp."""

from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from oauth_flow_gemini_enterprise_secops_mcp.cli import app
from oauth_flow_gemini_enterprise_secops_mcp.core import get_secops_mcp_endpoint
from oauth_flow_gemini_enterprise_secops_mcp.core import run_pipeline
from secops_agent.secops_agent_app.agent import get_secops_headers

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
