"""Hermetic unit tests for cleanup, env validation, Vertex AI, Secret Manager, CLI, and Gemini Enterprise."""

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError
from typer.testing import CliRunner

from oauth_flow_gemini_enterprise_secops_mcp import agentspace
from oauth_flow_gemini_enterprise_secops_mcp import cli
from oauth_flow_gemini_enterprise_secops_mcp import env_validation
from oauth_flow_gemini_enterprise_secops_mcp import secret
from oauth_flow_gemini_enterprise_secops_mcp import vertex_ai
from secops_agent.secops_agent_app import agent as secops_agent_mod
from secops_agent.secops_agent_app.app_utils import telemetry
from secops_agent.secops_agent_app.app_utils import typing as app_typing

runner = CliRunner()

REPO_ROOT = Path(__file__).resolve().parents[1]
RFC4122_PLACEHOLDER_UUID = "a1b2c3d4-e5f6-4321-abcd-ef1234567890"


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
  """Clear project-specific env vars so hermetic .env fixtures control state."""
  keys_to_clear = [
      "GCP_PROJECT_ID",
      "GCP_PROJECT_NUMBER",
      "GCP_LOCATION",
      "GCP_STAGING_BUCKET",
      "GOOGLE_CLOUD_PROJECT",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "CHRONICLE_PROJECT_ID",
      "CHRONICLE_CUSTOMER_ID",
      "CHRONICLE_SERVICE_ACCOUNT_PATH",
      "SECOPS_SERVICE_ACCOUNT_PATH",
      "RAG_GCP_LOCATION",
      "RAG_CORPUS_ID",
      "GEMINI_ENTERPRISE_APP_ID",
      "GEMINI_ENTERPRISE_AGENT_ID",
      "GEMINI_ENTERPRISE_COLLECTION",
      "GEMINI_ENTERPRISE_ASSISTANT",
      "AGENTSPACE_APP_ID",
      "AGENTSPACE_AGENT_ID",
      "AGENTSPACE_COLLECTION",
      "AGENTSPACE_ASSISTANT",
      "AGENT_ENGINE_RESOURCE_NAME",
      "AGENT_ENGINE_ID",
      "OAUTH_AUTH_ID",
      "GEMINI_AUTHORIZATION_ID",
      "OAUTH_CLIENT_ID",
      "OAUTH_CLIENT_SECRET",
      "OAUTH_AUTH_URI",
      "OAUTH_TOKEN_URI",
      "LOGS_BUCKET_NAME",
      "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
      "OTEL_RESOURCE_ATTRIBUTES",
      "OTEL_INSTRUMENTATION_GENAI_UPLOAD_BASE_PATH",
  ]
  for key in keys_to_clear:
    monkeypatch.delenv(key, raising=False)


@pytest.fixture
def mock_adc(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
  """Mock google.auth.default so no real credentials are accessed."""
  fake_creds = SimpleNamespace(
      valid=True,
      token="fake-access-token",  # noqa: S106
      refresh=lambda req: None,
      service_account_email="secops-runner@my-proj.iam.gserviceaccount.com",
  )
  monkeypatch.setattr(
      agentspace.google.auth,
      "default",
      lambda scopes=None: (fake_creds, "my-proj"),
  )
  monkeypatch.setattr(
      vertex_ai,
      "default",
      lambda: (fake_creds, "my-proj"),
  )
  return fake_creds


def _write_valid_env(env_path: Path, extra: str = "") -> Path:
  content = (
      'GCP_PROJECT_ID="my-secops-proj"\n'
      'GCP_PROJECT_NUMBER="987654321098"\n'
      'GCP_LOCATION="us-central1"\n'
      'AGENT_ENGINE_RESOURCE_NAME="projects/987654321098/locations/us-central1/reasoningEngines/111"\n'
      'GEMINI_ENTERPRISE_APP_ID="secops-ge-app"\n'
      'OAUTH_AUTH_ID="secops-oauth-v1"\n'
      f"{extra}"
  )
  env_path.write_text(content, encoding="utf-8")
  return env_path


# ---------------------------------------------------------------------------
# 1. Scaffolding Cleanup & secops_agent Module Tests
# ---------------------------------------------------------------------------


def test_removed_scaffolding_and_dead_files() -> None:
  removed_paths = [
      REPO_ROOT / ".gitmodules",
      REPO_ROOT / "external" / "agent-starter-pack",
      REPO_ROOT
      / "src"
      / "oauth_flow_gemini_enterprise_secops_mcp"
      / "auth_uri.py",
      REPO_ROOT / "secops_agent" / "justfile",
      REPO_ROOT / "secops_agent" / "pyproject.toml",
      REPO_ROOT
      / "secops_agent"
      / "secops_agent_app"
      / "app_utils"
      / "deploy.py",
      REPO_ROOT / "secops_agent" / "tests" / "unit" / "test_dummy.py",
      REPO_ROOT / "secops_agent" / "tests" / "integration" / "test_agent.py",
      REPO_ROOT / "secops_agent" / "tests" / "eval" / "eval_config.json",
  ]
  for path in removed_paths:
    assert not path.exists(), f"Expected {path} to be removed"


def test_secops_agent_telemetry_and_typing(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
  del clean_env
  feedback = app_typing.Feedback(score=5, text="accurate triage")
  assert feedback.service_name == "secops-agent"
  assert feedback.log_type == "feedback"
  assert feedback.user_id
  assert feedback.session_id

  assert telemetry.setup_telemetry() is None

  monkeypatch.setenv("LOGS_BUCKET_NAME", "secops-telemetry-bucket")
  monkeypatch.setenv(
      "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "true"
  )
  monkeypatch.setenv("COMMIT_SHA", "abc1234")
  bucket = telemetry.setup_telemetry()
  assert bucket == "secops-telemetry-bucket"
  assert (
      "service.namespace=secops-agent,service.version=abc1234"
      == telemetry.os.environ["OTEL_RESOURCE_ATTRIBUTES"]
  )
  assert (
      telemetry.os.environ["OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"]
      == "NO_CONTENT"
  )
  assert callable(secops_agent_mod.create_agent)
  assert callable(secops_agent_mod.create_app)


# ---------------------------------------------------------------------------
# 2. .env.example & env_validation.py Tests
# ---------------------------------------------------------------------------


def test_dotenv_example_hygiene_and_quoting() -> None:
  dotenv_path = REPO_ROOT / ".env.example"
  lines = dotenv_path.read_text(encoding="utf-8").splitlines()
  assert lines[20] == "# Workstation mTLS client-certificate bypass"
  full_text = "\n".join(lines)
  legacy_host_label = "cloud" + "top"
  assert legacy_host_label not in full_text.lower()
  assert f'CHRONICLE_CUSTOMER_ID="{RFC4122_PLACEHOLDER_UUID}"' in full_text
  assert 'GEMINI_ENTERPRISE_APP_ID="your-gemini-enterprise-app-id"' in full_text
  assert 'AGENTSPACE_APP_ID="your-agentspace-app-id"' in full_text

  for line in lines:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
      continue
    key, value = stripped.split("=", 1)
    assert key.isupper() or "_" in key
    assert (
        len(value) >= 2 and value.startswith('"') and value.endswith('"')
    ), f"Unquoted .env.example assignment: {line}"


def test_env_validation_placeholders_and_aliases() -> None:
  removed_vars = {
      "RAG_CORPUS_ID",
      "SOAR_URL",
      "SOAR_APP_KEY",
      "GTI_API_KEY",
      "CHRONICLE_SERVICE_ACCOUNT_PATH",
  }
  assert removed_vars.isdisjoint(env_validation.PLACEHOLDER_PATTERNS.keys())

  for bad_uuid in (
      RFC4122_PLACEHOLDER_UUID,
      "00000000-0000-0000-0000-000000000000",
      "your-customer-uuid",
  ):
    is_ph, reason = env_validation.is_placeholder_value(
        "CHRONICLE_CUSTOMER_ID", bad_uuid
    )
    assert is_ph is True
    assert reason is not None

  is_ph, reason = env_validation.is_placeholder_value(
      "CHRONICLE_CUSTOMER_ID", "c81d4e2e-bcf2-41e6-869b-7df92a63d93b"
  )
  assert is_ph is False
  assert reason is None

  # GEMINI_ENTERPRISE_APP_ID preferred, AGENTSPACE_APP_ID fallback
  assert (
      env_validation.resolve_gemini_enterprise_app_id(
          {
              "GEMINI_ENTERPRISE_APP_ID": "ge-primary",
              "AGENTSPACE_APP_ID": "as-fallback",
          }
      )
      == "ge-primary"
  )
  assert (
      env_validation.resolve_gemini_enterprise_app_id(
          {
              "GEMINI_ENTERPRISE_APP_ID": "your-gemini-enterprise-app-id",
              "AGENTSPACE_APP_ID": "as-fallback",
          }
      )
      == "as-fallback"
  )
  assert (
      env_validation.resolve_gemini_enterprise_app_id(
          {
              "GEMINI_ENTERPRISE_APP_ID": "your-gemini-enterprise-app-id",
              "AGENTSPACE_APP_ID": "your-agentspace-app-id",
          }
      )
      is None
  )

  valid, errors = env_validation.validate_env_vars(
      ["GEMINI_ENTERPRISE_APP_ID", "CHRONICLE_CUSTOMER_ID"],
      {
          "AGENTSPACE_APP_ID": "legacy-app-ok",
          "CHRONICLE_CUSTOMER_ID": "c81d4e2e-bcf2-41e6-869b-7df92a63d93b",
      },
  )
  assert valid is True
  assert errors == []

  valid, errors = env_validation.validate_env_vars(
      ["GCP_PROJECT_ID", "GEMINI_ENTERPRISE_APP_ID", "CHRONICLE_CUSTOMER_ID"],
      {
          "GEMINI_ENTERPRISE_APP_ID": "your-gemini-enterprise-app-id",
          "CHRONICLE_CUSTOMER_ID": RFC4122_PLACEHOLDER_UUID,
      },
  )
  assert valid is False
  by_var = {err.variable: err.error_type for err in errors}
  assert by_var == {
      "GCP_PROJECT_ID": "missing",
      "GEMINI_ENTERPRISE_APP_ID": "placeholder",
      "CHRONICLE_CUSTOMER_ID": "placeholder",
  }
  formatted = env_validation.format_validation_errors(errors)
  assert "GCP_PROJECT_ID" in formatted
  assert "GEMINI_ENTERPRISE_APP_ID" in formatted
  assert env_validation.format_validation_errors([]) == ""


def test_validate_file_path_exists(tmp_path: Path) -> None:
  ph_err = env_validation.validate_file_path_exists(
      "OAUTH_CLIENT_FILE", "/path/to/client_secret.json"
  )
  assert ph_err is not None
  assert ph_err.error_type == "placeholder"

  missing_err = env_validation.validate_file_path_exists(
      "OAUTH_CLIENT_FILE", str(tmp_path / "missing.json")
  )
  assert missing_err is not None
  assert missing_err.error_type == "missing"

  real_file = tmp_path / "client_secret.json"
  real_file.write_text("{}", encoding="utf-8")
  assert (
      env_validation.validate_file_path_exists(
          "OAUTH_CLIENT_FILE", str(real_file)
      )
      is None
  )


# ---------------------------------------------------------------------------
# 3. vertex_ai.py Tests
# ---------------------------------------------------------------------------


def test_vertex_ai_manager_and_cli(
    tmp_path: Path,
    clean_env: None,
    mock_adc: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  del clean_env
  env_path = _write_valid_env(tmp_path / ".env")
  monkeypatch.setenv("RAG_GCP_LOCATION", "your-rag-location")

  init_calls: list[tuple[str | None, str | None]] = []
  monkeypatch.setattr(
      vertex_ai.vertexai,
      "init",
      lambda project=None, location=None, credentials=None: init_calls.append(
          (project, location)
      ),
  )

  fake_rm_client = MagicMock()
  fake_rm_client.get_project.return_value = SimpleNamespace(
      display_name="My SecOps Project"
  )
  fake_rm_client.get_iam_policy.return_value = SimpleNamespace(
      bindings=[
          SimpleNamespace(
              role="roles/aiplatform.user",
              members=[f"serviceAccount:{mock_adc.service_account_email}"],
          ),
          SimpleNamespace(
              role="roles/storage.admin",
              members=[f"serviceAccount:{mock_adc.service_account_email}"],
          ),
      ]
  )
  monkeypatch.setattr(
      "google.cloud.resourcemanager_v3.ProjectsClient",
      lambda credentials=None: fake_rm_client,
  )

  manager = vertex_ai.VertexAIManager(env_path)
  monkeypatch.setattr(manager, "_is_api_enabled", lambda api: True)
  assert manager.verify_setup() is True
  assert init_calls == [("my-secops-proj", "us-central1")]

  quota_res = runner.invoke(
      vertex_ai.app, ["check-quota", "--env-file", str(env_path)]
  )
  assert quota_res.exit_code == 0
  assert "RAG Service Quotas" not in quota_res.stdout
  assert "--project=my-secops-proj" in quota_res.stdout

  enable_res = runner.invoke(
      vertex_ai.app, ["enable-apis", "--env-file", str(env_path)]
  )
  assert enable_res.exit_code == 0
  assert "aiplatform.googleapis.com" in enable_res.stdout

  # Verify JWT id_token extraction and missing role branch
  payload = (
      base64.urlsafe_b64encode(
          json.dumps({"email": "analyst@example.com"}).encode("utf-8")
      )
      .decode("utf-8")
      .rstrip("=")
  )
  jwt_creds = SimpleNamespace(id_token=f"hdr.{payload}.sig")
  manager.credentials = jwt_creds
  fake_rm_client.get_iam_policy.return_value = SimpleNamespace(bindings=[])
  assert manager._check_permissions() is False

  # Verify auth failure branch
  def _raise_adc() -> None:
    raise DefaultCredentialsError("no adc")

  monkeypatch.setattr(vertex_ai, "default", _raise_adc)
  fail_res = runner.invoke(
      vertex_ai.app, ["verify", "--env-file", str(env_path)]
  )
  assert fail_res.exit_code == 1


def test_vertex_ai_verify_fails_fast_and_checks_permissions(
    tmp_path: Path,
    clean_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  del clean_env

  # Case 1: Placeholder GCP_PROJECT_ID fails fast before ADC or GCP calls.
  placeholder_env = tmp_path / "placeholder.env"
  placeholder_env.write_text(
      'GCP_PROJECT_ID="your-gcp-project-id"\nGCP_LOCATION="us-central1"\n',
      encoding="utf-8",
  )

  def _unexpected_default() -> None:
    raise AssertionError("default() must not run when env vars fail")

  def _unexpected_rm_client(*args: object, **kwargs: object) -> None:
    del args, kwargs
    raise AssertionError("ProjectsClient must not run when env vars fail")

  monkeypatch.setattr(vertex_ai, "default", _unexpected_default)
  monkeypatch.setattr(
      "google.cloud.resourcemanager_v3.ProjectsClient", _unexpected_rm_client
  )

  ph_res = runner.invoke(
      vertex_ai.app, ["verify", "--env-file", str(placeholder_env)]
  )
  assert ph_res.exit_code == 1
  assert "your-gcp-project-id" in ph_res.stdout
  assert "Verifying project access" not in ph_res.stdout

  # Case 2: Missing IAM roles fail verify_setup() and format SA member prefix.
  valid_env = _write_valid_env(tmp_path / "valid.env")
  sa_creds = SimpleNamespace(
      service_account_email="deployer@my-secops-proj.iam.gserviceaccount.com"
  )
  monkeypatch.setattr(
      vertex_ai, "default", lambda: (sa_creds, "my-secops-proj")
  )
  monkeypatch.setattr(
      vertex_ai.vertexai,
      "init",
      lambda project=None, location=None, credentials=None: None,
  )

  fake_rm_client = MagicMock()
  fake_rm_client.get_project.return_value = SimpleNamespace(
      display_name="My SecOps Project"
  )
  fake_rm_client.get_iam_policy.return_value = SimpleNamespace(bindings=[])
  monkeypatch.setattr(
      "google.cloud.resourcemanager_v3.ProjectsClient",
      lambda credentials=None: fake_rm_client,
  )
  monkeypatch.setattr(
      vertex_ai.VertexAIManager, "_is_api_enabled", lambda self, api: True
  )

  sa_fail_res = runner.invoke(
      vertex_ai.app, ["verify", "--env-file", str(valid_env)]
  )
  assert sa_fail_res.exit_code == 1
  assert "[OK] All checks passed!" not in sa_fail_res.stdout
  assert "[ERROR] Some checks failed" in sa_fail_res.stdout
  assert (
      "--member='serviceAccount:deployer@my-secops-proj.iam.gserviceaccount.com'"
      in sa_fail_res.stdout
  )
  assert "--member='user:deployer@" not in sa_fail_res.stdout

  # Case 3: Non-SA user email still formats --member='user:...'.
  payload = (
      base64.urlsafe_b64encode(
          json.dumps({"email": "analyst@example.com"}).encode("utf-8")
      )
      .decode("utf-8")
      .rstrip("=")
  )
  user_creds = SimpleNamespace(id_token=f"hdr.{payload}.sig")
  monkeypatch.setattr(
      vertex_ai, "default", lambda: (user_creds, "my-secops-proj")
  )

  user_fail_res = runner.invoke(
      vertex_ai.app, ["verify", "--env-file", str(valid_env)]
  )
  assert user_fail_res.exit_code == 1
  assert "--member='user:analyst@example.com'" in user_fail_res.stdout


# ---------------------------------------------------------------------------
# 4. agentspace.py (Gemini Enterprise) Tests
# ---------------------------------------------------------------------------


def test_agentspace_display_url_and_fallback(
    tmp_path: Path,
    clean_env: None,
    mock_adc: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
  del clean_env, mock_adc
  env_ge = _write_valid_env(tmp_path / "ge.env")
  mgr = agentspace.AgentSpaceManager(env_ge)
  mgr.display_url()
  out = capsys.readouterr().out
  assert (
      "https://console.cloud.google.com/gemini-enterprise/locations/global/"
      "engines/secops-ge-app?project=my-secops-proj" in out
  )
  assert "gen-ai-studio/agentspace" not in out

  # Fallback to AGENTSPACE_APP_ID when GEMINI_ENTERPRISE_APP_ID is placeholder
  env_legacy = tmp_path / "legacy.env"
  env_legacy.write_text(
      'GCP_PROJECT_ID="my-secops-proj"\n'
      'GEMINI_ENTERPRISE_APP_ID="your-gemini-enterprise-app-id"\n'
      'AGENTSPACE_APP_ID="legacy-secops-app"\n',
      encoding="utf-8",
  )
  mgr_legacy = agentspace.AgentSpaceManager(env_legacy)
  mgr_legacy.display_url()
  out_legacy = capsys.readouterr().out
  assert (
      "https://console.cloud.google.com/gemini-enterprise/locations/global/"
      "engines/legacy-secops-app?project=my-secops-proj" in out_legacy
  )

  # Missing configuration
  env_empty = tmp_path / "empty.env"
  env_empty.write_text(
      'GCP_PROJECT_ID="your-gcp-project-id"\n', encoding="utf-8"
  )
  mgr_empty = agentspace.AgentSpaceManager(env_empty)
  mgr_empty.display_url()
  out_empty = capsys.readouterr().out
  assert "[ERROR] Cannot generate URL" in out_empty


def test_agentspace_app_and_agent_crud_mocks(
    tmp_path: Path,
    clean_env: None,
    mock_adc: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  del clean_env, mock_adc
  env_path = _write_valid_env(tmp_path / ".env")
  mgr = agentspace.AgentSpaceManager(env_path)

  def _ok_resp(payload: dict[str, object], status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = json.dumps(payload)
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp

  # 1. create_app writes GEMINI_ENTERPRISE_APP_ID and AGENTSPACE_APP_ID
  monkeypatch.setattr(
      agentspace.requests,
      "request",
      lambda method, url, **kw: _ok_resp({"name": "engines/new-app"}, 201),
  )
  assert (
      mgr.create_app(
          app_name="SecOps App",
          solution_type="SOLUTION_TYPE_CHAT",
          enable_chat=True,
          skip_datastore=True,
          app_type="APP_TYPE_INTRANET",
          industry_vertical="GENERIC",
      )
      is True
  )
  saved_env = env_path.read_text(encoding="utf-8")
  assert 'GEMINI_ENTERPRISE_APP_ID="secops-app_' in saved_env
  assert 'AGENTSPACE_APP_ID="secops-app_' in saved_env

  created_app_id = mgr.env_vars["GEMINI_ENTERPRISE_APP_ID"]

  # 2. list_apps and get_app_details
  monkeypatch.setattr(
      agentspace.requests,
      "get",
      lambda url, **kw: _ok_resp(
          {
              "engines": [
                  {
                      "name": f"projects/1/engines/{created_app_id}",
                      "displayName": "SecOps App",
                      "solutionType": "SOLUTION_TYPE_CHAT",
                      "dataStoreIds": ["ds-1"],
                  }
              ],
              "name": f"projects/1/engines/{created_app_id}",
              "displayName": "SecOps App",
              "solutionType": "SOLUTION_TYPE_CHAT",
              "dataStoreIds": [],
          }
      ),
  )
  assert mgr.list_apps(show_raw=False) is True
  assert mgr.get_app_details(created_app_id) is True

  # 3. register_agent -> verify_agent -> update_agent -> list_agents
  monkeypatch.setattr(
      agentspace.requests,
      "post",
      lambda url, **kw: _ok_resp({"name": "projects/1/agents/agent-777"}),
  )
  assert mgr.register_agent(force=True) is True
  assert mgr.env_vars["AGENTSPACE_AGENT_ID"] == "agent-777"

  monkeypatch.setattr(
      agentspace.requests,
      "request",
      lambda method, url, **kw: _ok_resp({"name": "agent-777"}),
  )
  assert mgr.verify_agent() is True
  assert mgr.update_agent() is True

  monkeypatch.setattr(
      agentspace.requests,
      "get",
      lambda url, **kw: _ok_resp(
          {
              "agents": [
                  {
                      "name": "projects/1/agents/agent-777",
                      "displayName": "Google SecOps Security Agent",
                      "description": "SecOps agent",
                      "adk_agent_definition": {
                          "tool_settings": {"tool_description": "SIEM & SOAR"},
                          "provisioned_reasoning_engine": {
                              "reasoning_engine": "projects/1/reasoningEngines/2"
                          },
                      },
                  }
              ]
          }
      ),
  )
  assert mgr.list_agents(show_raw=False) is True

  # 4. link_agent_to_agentspace FAILED_PRECONDITION fallback to update_agent_config
  err_response = MagicMock()
  err_response.status_code = 400
  err_response.text = "FAILED_PRECONDITION: seat license required"

  def _raise_precondition(url: str, **kw: object) -> None:
    exc = requests.exceptions.HTTPError("400 Client Error")
    exc.response = err_response
    raise exc

  monkeypatch.setattr(agentspace.requests, "post", _raise_precondition)
  monkeypatch.setattr(
      agentspace.requests,
      "patch",
      lambda url, **kw: _ok_resp({"name": "projects/1/agents/agent-777"}),
  )
  assert mgr.link_agent_to_agentspace() is True

  # 5. search_agentspace + datastore check + unlink + delete_app
  def _search_router(method: str, url: str, **kw: object) -> MagicMock:
    if method == "GET" and "/engines/" in url:
      return _ok_resp({"name": "eng", "dataStoreIds": ["ds-1"]})
    if method == "GET" and "/dataStores/" in url:
      return _ok_resp({"displayName": "SecOps Store"})
    if method == "POST" and ":search" in url:
      return _ok_resp(
          {
              "totalSize": 1,
              "results": [
                  {
                      "document": {"title": "Runbook"},
                      "snippet": "Isolate host",
                      "relevanceScore": 0.99,
                  }
              ],
          }
      )
    return _ok_resp({}, 200)

  monkeypatch.setattr(agentspace.requests, "request", _search_router)
  assert mgr.search_agentspace("suspicious login") is True

  monkeypatch.setattr(
      agentspace.requests,
      "delete",
      lambda url, **kw: _ok_resp({}, 204),
  )
  assert mgr.unlink_agent_from_agentspace(force=True) is True
  assert mgr.env_vars["AGENTSPACE_AGENT_ID"] == ""

  assert mgr.delete_app(created_app_id, force=True) is True
  assert mgr.env_vars["GEMINI_ENTERPRISE_APP_ID"] == ""


# ---------------------------------------------------------------------------
# 5. secret.py Tests
# ---------------------------------------------------------------------------


def test_secret_upload_verify_and_url(
    tmp_path: Path,
    clean_env: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
  del clean_env
  secret.display_url(
      {
          "GCP_PROJECT_ID": "my-secops-proj",
          "AGENTSPACE_APP_ID": "legacy-app-99",
      }
  )
  url_out = capsys.readouterr().out
  assert (
      "https://console.cloud.google.com/gemini-enterprise/locations/global/"
      "engines/legacy-app-99?project=my-secops-proj" in url_out
  )

  sa_file = tmp_path / "sa.json"
  sa_payload = {
      "type": "service_account",
      "project_id": "my-secops-proj",
      "client_email": "secops@my-secops-proj.iam.gserviceaccount.com",
  }
  sa_file.write_text(json.dumps(sa_payload), encoding="utf-8")

  env_path = _write_valid_env(tmp_path / ".env")

  fake_sm = MagicMock()
  fake_sm.get_secret.side_effect = gcp_exceptions.NotFound("missing")
  fake_sm.create_secret.return_value = SimpleNamespace(
      name="projects/my-secops-proj/secrets/chronicle-service-account"
  )
  fake_sm.add_secret_version.return_value = SimpleNamespace(
      name="projects/my-secops-proj/secrets/chronicle-service-account/versions/1"
  )
  fake_sm.access_secret_version.return_value = SimpleNamespace(
      payload=SimpleNamespace(data=json.dumps(sa_payload).encode("utf-8"))
  )
  monkeypatch.setattr(
      secret.secretmanager,
      "SecretManagerServiceClient",
      lambda credentials=None: fake_sm,
  )

  up_res = runner.invoke(
      secret.app,
      [
          "upload",
          "--env-file",
          str(env_path),
          "--file",
          str(sa_file),
          "--force",
      ],
  )
  assert up_res.exit_code == 0
  assert "[OK] Upload Complete!" in up_res.stdout

  ver_res = runner.invoke(
      secret.app,
      ["verify", "--env-file", str(env_path)],
  )
  assert ver_res.exit_code == 0
  assert "[OK] Secret accessible!" in ver_res.stdout

  fake_sm.access_secret_version.side_effect = gcp_exceptions.PermissionDenied(
      "denied"
  )
  denied_res = runner.invoke(
      secret.app,
      ["verify", "--env-file", str(env_path)],
  )
  assert denied_res.exit_code == 1


# ---------------------------------------------------------------------------
# 6. cli.py Subcommand Alias & Workflow Tests
# ---------------------------------------------------------------------------


def test_cli_gemini_enterprise_and_agentspace_subcommands(
    tmp_path: Path,
    clean_env: None,
    mock_adc: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  del clean_env, mock_adc
  env_path = _write_valid_env(
      tmp_path / ".env",
      extra=(
          'OAUTH_CLIENT_ID="cid"\n'
          'OAUTH_CLIENT_SECRET="csec"\n'
          'OAUTH_AUTH_URI="https://accounts.google.com/o/oauth2/v2/auth"\n'
      ),
  )

  root_help = runner.invoke(cli.app, ["--help"])
  assert root_help.exit_code == 0
  assert "gemini-enterprise" in root_help.stdout
  assert "agentspace" in root_help.stdout

  for group_name in ("gemini-enterprise", "agentspace"):
    res = runner.invoke(
        cli.app, [group_name, "url", "--env-file", str(env_path)]
    )
    assert res.exit_code == 0
    assert (
        "https://console.cloud.google.com/gemini-enterprise/locations/global/"
        "engines/secops-ge-app?project=my-secops-proj" in res.stdout
    )

  demo_res = runner.invoke(cli.app, ["run-demo", "--name", "secops"])
  assert demo_res.exit_code == 0
  assert "secops" in demo_res.stdout

  new_env = tmp_path / "created.env"
  setup_res = runner.invoke(cli.app, ["setup", "--env-file", str(new_env)])
  assert setup_res.exit_code == 0
  assert new_env.exists()

  # Workflow status, full-deploy, and redeploy-all with mocked managers
  monkeypatch.setattr(
      agentspace.AgentSpaceManager, "verify_agent", lambda self: True
  )
  monkeypatch.setattr(
      agentspace.AgentSpaceManager,
      "link_agent_to_agentspace",
      lambda self: True,
  )
  monkeypatch.setattr(
      agentspace.AgentSpaceManager, "update_agent", lambda self: True
  )
  monkeypatch.setattr(cli.typer, "confirm", lambda prompt: True)

  from oauth_flow_gemini_enterprise_secops_mcp import oauth

  monkeypatch.setattr(
      oauth.OAuthManager,
      "create_authorization",
      lambda self, *args, **kwargs: True,
  )

  status_res = runner.invoke(
      cli.app, ["workflow", "status", "--env-file", str(env_path)]
  )
  assert status_res.exit_code == 0
  assert "Gemini Enterprise agent is verified and active" in status_res.stdout

  deploy_res = runner.invoke(
      cli.app, ["workflow", "full-deploy", "--env-file", str(env_path)]
  )
  assert deploy_res.exit_code == 0
  assert "Agent linked to Gemini Enterprise successfully" in deploy_res.stdout

  redeploy_res = runner.invoke(
      cli.app, ["workflow", "redeploy-all", "--env-file", str(env_path)]
  )
  assert redeploy_res.exit_code == 0
  assert "Gemini Enterprise updated successfully" in redeploy_res.stdout


def test_agentspace_cli_entrypoints_and_datastore_creation(
    tmp_path: Path,
    clean_env: None,
    mock_adc: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  del clean_env, mock_adc
  env_path = _write_valid_env(
      tmp_path / ".env",
      extra='AGENTSPACE_AGENT_ID="agent-999"\n',
  )

  # Conflicting --no-datastore and --data-store flags fail cleanly
  conflict = runner.invoke(
      agentspace.app,
      [
          "create-app",
          "--no-datastore",
          "--data-store",
          "ds-1",
          "--env-file",
          str(env_path),
      ],
  )
  assert conflict.exit_code == 1
  assert "Cannot specify both" in conflict.stdout

  def _ok(payload: dict[str, object], status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = json.dumps(payload)
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp

  # Exercise ensure-datastore when engine initially has empty dataStoreIds
  monkeypatch.setattr(
      agentspace.requests,
      "request",
      lambda method, url, **kw: _ok({"name": "eng", "dataStoreIds": []}),
  )
  monkeypatch.setattr(
      agentspace.requests,
      "post",
      lambda url, **kw: _ok({"name": "projects/1/agents/agent-999"}),
  )
  monkeypatch.setattr(
      agentspace.requests,
      "patch",
      lambda url, **kw: _ok({"name": "projects/1/agents/agent-999"}),
  )
  monkeypatch.setattr(
      agentspace.requests,
      "get",
      lambda url, **kw: _ok({"engines": [], "agents": [], "name": "eng"}),
  )
  monkeypatch.setattr(
      agentspace.requests,
      "delete",
      lambda url, **kw: _ok({}, 204),
  )

  for cmd_args in (
      ["ensure-datastore", "--env-file", str(env_path)],
      ["register", "--force", "--env-file", str(env_path)],
      ["update", "--env-file", str(env_path)],
      ["verify", "--env-file", str(env_path)],
      ["link-agent", "--env-file", str(env_path)],
      [
          "update-agent-config",
          "--display-name",
          "SecOps Updated",
          "--description",
          "Updated desc",
          "--tool-description",
          "Updated tools",
          "--env-file",
          str(env_path),
      ],
      ["list-apps", "--env-file", str(env_path)],
      ["list-agents", "--env-file", str(env_path)],
      ["get-app-details", "secops-ge-app", "--env-file", str(env_path)],
      [
          "create-app",
          "--name",
          "SecOps CLI App",
          "--no-datastore",
          "--app-type",
          "APP_TYPE_INTRANET",
          "--industry-vertical",
          "GENERIC",
          "--env-file",
          str(env_path),
      ],
      ["unlink-agent", "--force", "--env-file", str(env_path)],
      ["delete", "--force", "--env-file", str(env_path)],
      ["delete-app", "secops-ge-app", "--force", "--env-file", str(env_path)],
  ):
    res = runner.invoke(agentspace.app, cmd_args)
    assert res.exit_code == 0, f"Failed {cmd_args}: {res.stdout}"

  # Exercise secret.create_or_update_secret when secret already exists
  fake_sm = MagicMock()
  fake_sm.get_secret.return_value = SimpleNamespace(name="existing")
  fake_sm.add_secret_version.return_value = SimpleNamespace(
      name="projects/my-secops-proj/secrets/s1/versions/2"
  )
  monkeypatch.setattr(
      secret.secretmanager,
      "SecretManagerServiceClient",
      lambda credentials=None: fake_sm,
  )
  ver_name = secret.create_or_update_secret(
      "my-secops-proj",
      "s1",
      '{"type": "service_account"}',
      True,
  )
  assert ver_name.endswith("/versions/2")
