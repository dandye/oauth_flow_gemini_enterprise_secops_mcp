"""Hermetic unit tests for IAM role verification, OAuth PKCE, and docs."""

import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest
import requests
from google.iam.v1 import policy_pb2
from typer.testing import CliRunner

from oauth_flow_gemini_enterprise_secops_mcp import iam
from oauth_flow_gemini_enterprise_secops_mcp import oauth

runner = CliRunner()

REPO_ROOT = Path(__file__).resolve().parents[1]


class _FakeCredentials:
  """Fake Google Cloud credentials for hermetic tests."""

  def __init__(
      self, bearer_value: str | None = "fake-access-value", valid: bool = False
  ):
    self._initial_value = bearer_value
    self.token = bearer_value if valid else None
    self.valid = valid
    self.refreshed = False

  def refresh(self, request: object) -> None:
    del request
    self.refreshed = True
    self.valid = True
    self.token = self._initial_value


class _FakeProjectsClient:
  """In-memory Google Cloud Resource Manager ProjectsClient test double."""

  def __init__(self, policies: dict[str, policy_pb2.Policy] | None = None):
    self.policies: dict[str, policy_pb2.Policy] = policies or {}
    self.set_calls: list[tuple[str, policy_pb2.Policy]] = []

  def get_iam_policy(self, request: object) -> policy_pb2.Policy:
    resource = getattr(request, "resource", "")
    if resource not in self.policies:
      self.policies[resource] = policy_pb2.Policy()
    policy_copy = policy_pb2.Policy()
    policy_copy.CopyFrom(self.policies[resource])
    return policy_copy

  def set_iam_policy(self, request: object) -> policy_pb2.Policy:
    resource = getattr(request, "resource", "")
    policy = getattr(request, "policy", policy_pb2.Policy())
    stored = policy_pb2.Policy()
    stored.CopyFrom(policy)
    self.policies[resource] = stored
    self.set_calls.append((resource, stored))
    return stored


def _write_env_file(path: Path, values: dict[str, str]) -> Path:
  content = "\n".join(f"{k}={v}" for k, v in values.items()) + "\n"
  path.write_text(content)
  return path


def _patch_iam_env_and_client(
    monkeypatch: pytest.MonkeyPatch,
    fake_client: _FakeProjectsClient,
    project_id: str = "agent-host-proj",
    project_number: str = "123456789012",
    chronicle_project_id: str | None = "secops-tenant-proj",
) -> None:
  monkeypatch.setenv("GCP_PROJECT_ID", project_id)
  monkeypatch.setenv("GCP_PROJECT_NUMBER", project_number)
  if chronicle_project_id is not None:
    monkeypatch.setenv("CHRONICLE_PROJECT_ID", chronicle_project_id)
  else:
    monkeypatch.delenv("CHRONICLE_PROJECT_ID", raising=False)

  monkeypatch.setattr(
      iam, "default", lambda: (_FakeCredentials(valid=True), project_id)
  )
  monkeypatch.setattr(
      iam.resourcemanager_v3,
      "ProjectsClient",
      lambda credentials=None: fake_client,
  )


def test_normalize_principal() -> None:
  assert iam.normalize_principal("analyst@example.com") == (
      "user:analyst@example.com"
  )
  assert (
      iam.normalize_principal("  runner@my-proj.iam.gserviceaccount.com ")
      == "serviceAccount:runner@my-proj.iam.gserviceaccount.com"
  )
  assert (
      iam.normalize_principal("group:soc-team@example.com")
      == "group:soc-team@example.com"
  )
  assert (
      iam.normalize_principal("user:explicit@example.com")
      == "user:explicit@example.com"
  )
  with pytest.raises(ValueError, match="must not be empty"):
    iam.normalize_principal("   ")


def test_iam_constants_reflect_vertex_ai_gemini_enterprise_and_secops() -> None:
  purposes = {
      item["service"]: item["purpose"] for item in iam.SERVICE_AGENT_PERMISSIONS
  }
  assert purposes["aiplatform-re"] == (
      "Invoke Gemini models during Reasoning Engine execution"
  )
  assert purposes["discoveryengine"] == (
      "Invoke Reasoning Engine from Gemini Enterprise"
  )
  for item in iam.SERVICE_AGENT_PERMISSIONS:
    assert "RAG" not in item["purpose"]
    assert "AgentSpace" not in item["purpose"]
    assert "AgentSpace" not in item["name"]

  mcp_roles = [spec["role"] for spec in iam.SECOPS_MCP_ROLE_SPECS]
  assert mcp_roles == [
      "roles/mcp.toolUser",
      "roles/chronicle.viewer",
      "roles/serviceusage.serviceUsageConsumer",
  ]


def test_iam_manager_initialization_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  empty_env = tmp_path / "missing.env"
  monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
  monkeypatch.delenv("GCP_PROJECT_NUMBER", raising=False)

  res_no_proj = runner.invoke(iam.app, ["verify", "--env-file", str(empty_env)])
  assert res_no_proj.exit_code == 1
  assert "GCP_PROJECT_ID" in res_no_proj.output

  monkeypatch.setenv("GCP_PROJECT_ID", "agent-host-proj")
  res_no_num = runner.invoke(iam.app, ["verify", "--env-file", str(empty_env)])
  assert res_no_num.exit_code == 1
  assert "GCP_PROJECT_NUMBER" in res_no_num.output

  monkeypatch.setenv("GCP_PROJECT_NUMBER", "123456789012")

  def _raise_adc() -> tuple[object, str]:
    raise RuntimeError("ADC unavailable")

  monkeypatch.setattr(iam, "default", _raise_adc)
  res_adc_err = runner.invoke(iam.app, ["verify", "--env-file", str(empty_env)])
  assert res_adc_err.exit_code == 1
  assert "ADC unavailable" in res_adc_err.output


def test_iam_setup_dry_run_apply_and_remove_bindings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  fake_client = _FakeProjectsClient()
  _patch_iam_env_and_client(monkeypatch, fake_client)
  env_file = _write_env_file(
      tmp_path / ".env",
      {
          "GCP_PROJECT_ID": "agent-host-proj",
          "GCP_PROJECT_NUMBER": "123456789012",
          "CHRONICLE_PROJECT_ID": "secops-tenant-proj",
      },
  )

  dry_res = runner.invoke(
      iam.app, ["setup", "--dry-run", "--verbose", "--env-file", str(env_file)]
  )
  assert dry_res.exit_code == 0
  assert "Would add: 3" in dry_res.output
  assert len(fake_client.set_calls) == 0

  apply_res = runner.invoke(
      iam.app, ["setup", "--verbose", "--env-file", str(env_file)]
  )
  assert apply_res.exit_code == 0
  assert "Added: 3" in apply_res.output
  assert "roles/mcp.toolUser" in apply_res.output
  assert len(fake_client.set_calls) == 3

  repeat_res = runner.invoke(
      iam.app, ["setup", "--verbose", "--env-file", str(env_file)]
  )
  assert repeat_res.exit_code == 0
  assert "Already configured: 3" in repeat_res.output

  manager = iam.IAMManager(env_file)
  re_sa = manager._get_service_account_email("aiplatform-re")
  assert (
      manager._remove_role_binding(re_sa, "roles/aiplatform.user", dry_run=True)
      is True
  )
  assert (
      manager._remove_role_binding(
          re_sa, "roles/aiplatform.user", dry_run=False
      )
      is True
  )
  assert (
      manager._remove_role_binding(
          re_sa, "roles/nonexistent.role", dry_run=False
      )
      is False
  )


def test_iam_setup_exits_nonzero_on_policy_update_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  fake_client = _FakeProjectsClient()

  def _fail_set(request: object) -> policy_pb2.Policy:
    del request
    raise RuntimeError("permission denied")

  fake_client.set_iam_policy = _fail_set  # type: ignore[method-assign]
  _patch_iam_env_and_client(monkeypatch, fake_client)
  env_file = tmp_path / "missing.env"

  res = runner.invoke(iam.app, ["setup", "--env-file", str(env_file)])
  assert res.exit_code == 1
  assert "Failed: 3" in res.output


def test_iam_verify_service_agents_and_secops_mcp_principal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  agent_policy = policy_pb2.Policy(
      bindings=[
          policy_pb2.Binding(
              role="roles/aiplatform.user",
              members=[
                  "serviceAccount:service-123456789012@gcp-sa-aiplatform-re.iam.gserviceaccount.com",
                  "serviceAccount:service-123456789012@gcp-sa-discoveryengine.iam.gserviceaccount.com",
              ],
          ),
      ]
  )
  secops_policy = policy_pb2.Policy(
      bindings=[
          policy_pb2.Binding(
              role="roles/mcp.toolUser",
              members=[
                  "user:analyst@example.com",
                  "serviceAccount:caller@secops-tenant-proj.iam.gserviceaccount.com",
              ],
          ),
          policy_pb2.Binding(
              role="roles/chronicle.editor",
              members=["user:analyst@example.com"],
          ),
          policy_pb2.Binding(
              role="roles/chronicle.admin",
              members=[
                  "serviceAccount:caller@secops-tenant-proj.iam.gserviceaccount.com"
              ],
          ),
          policy_pb2.Binding(
              role="roles/serviceusage.serviceUsageConsumer",
              members=[
                  "user:analyst@example.com",
                  "serviceAccount:caller@secops-tenant-proj.iam.gserviceaccount.com",
              ],
          ),
      ]
  )
  fake_client = _FakeProjectsClient(
      policies={
          "projects/agent-host-proj": agent_policy,
          "projects/secops-tenant-proj": secops_policy,
      }
  )
  _patch_iam_env_and_client(monkeypatch, fake_client)
  env_file = tmp_path / "missing.env"

  missing_sa_res = runner.invoke(
      iam.app, ["verify", "--env-file", str(env_file)]
  )
  assert missing_sa_res.exit_code == 1
  assert "just iam-setup" in missing_sa_res.output
  assert "manage.py" not in missing_sa_res.output

  agent_policy.bindings.append(
      policy_pb2.Binding(
          role="roles/aiplatform.viewer",
          members=[
              "serviceAccount:service-123456789012@gcp-sa-discoveryengine.iam.gserviceaccount.com"
          ],
      )
  )
  fake_client.policies["projects/agent-host-proj"] = agent_policy

  ok_res = runner.invoke(iam.app, ["verify", "--env-file", str(env_file)])
  assert ok_res.exit_code == 0
  assert "All checked IAM permissions are configured." in ok_res.output
  assert "roles/mcp.toolUser" in ok_res.output

  user_ok = runner.invoke(
      iam.app,
      [
          "verify",
          "--principal",
          "analyst@example.com",
          "--env-file",
          str(env_file),
      ],
  )
  assert user_ok.exit_code == 0
  assert "user:analyst@example.com on secops-tenant-proj" in user_ok.output

  sa_ok = runner.invoke(
      iam.app,
      [
          "verify",
          "--principal",
          "caller@secops-tenant-proj.iam.gserviceaccount.com",
          "--env-file",
          str(env_file),
      ],
  )
  assert sa_ok.exit_code == 0

  missing_mcp = runner.invoke(
      iam.app,
      [
          "verify",
          "--principal",
          "unprovisioned@example.com",
          "--env-file",
          str(env_file),
      ],
  )
  assert missing_mcp.exit_code == 1
  assert "[MISSING] roles/mcp.toolUser" in missing_mcp.output
  assert "[MISSING] roles/chronicle.viewer" in missing_mcp.output
  assert (
      "[MISSING] roles/serviceusage.serviceUsageConsumer" in missing_mcp.output
  )
  assert (
      "gcloud projects add-iam-policy-binding secops-tenant-proj"
      in missing_mcp.output
  )

  empty_principal = runner.invoke(
      iam.app,
      ["verify", "--principal", "   ", "--env-file", str(env_file)],
  )
  assert empty_principal.exit_code == 1


def test_iam_list_roles_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  agent_policy = policy_pb2.Policy(
      bindings=[
          policy_pb2.Binding(
              role="roles/aiplatform.user",
              members=[
                  "serviceAccount:service-123456789012@gcp-sa-aiplatform-re.iam.gserviceaccount.com"
              ],
          )
      ]
  )
  fake_client = _FakeProjectsClient(
      policies={"projects/agent-host-proj": agent_policy}
  )
  _patch_iam_env_and_client(monkeypatch, fake_client)
  env_file = tmp_path / "missing.env"

  re_res = runner.invoke(
      iam.app, ["list-roles", "aiplatform-re", "--env-file", str(env_file)]
  )
  assert re_res.exit_code == 0
  assert "Granted Roles (1):" in re_res.output
  assert "roles/aiplatform.user" in re_res.output

  de_res = runner.invoke(
      iam.app, ["list-roles", "discoveryengine", "--env-file", str(env_file)]
  )
  assert de_res.exit_code == 0
  assert "No roles granted" in de_res.output

  bad_res = runner.invoke(
      iam.app, ["list-roles", "invalid-service", "--env-file", str(env_file)]
  )
  assert bad_res.exit_code == 1


def _write_client_secret(
    tmp_path: Path, client_type: str = "web", filename: str = "secret.json"
) -> Path:
  secret_file = tmp_path / filename
  payload = {
      client_type: {
          "client_id": "test-client-123.apps.googleusercontent.com",
          "client_secret": "test-secret-xyz",
          "auth_uri": "https://accounts.google.com/o/oauth2/auth",
          "token_uri": "https://oauth2.googleapis.com/token",
      }
  }
  secret_file.write_text(json.dumps(payload))
  return secret_file


def test_oauth_setup_without_and_with_pkce_has_no_visit_prompt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  monkeypatch.setattr(
      oauth.google.auth,
      "default",
      lambda scopes=None: (_FakeCredentials(), "agent-host-proj"),
  )
  secret_file = _write_client_secret(tmp_path, client_type="web")
  env_file = tmp_path / ".env"
  env_file.write_text("# Initial comment\nEXISTING_KEY=keep\n")

  res_default = runner.invoke(
      oauth.app,
      ["setup", str(secret_file), "--env-file", str(env_file)],
  )
  assert res_default.exit_code == 0
  assert "visit" not in res_default.output.lower()
  assert "make oauth-create-auth" not in res_default.output
  assert "just oauth-create-auth" in res_default.output
  assert "PKCE verification enabled: false" in res_default.output

  env_text = env_file.read_text()
  assert "EXISTING_KEY=keep" in env_text
  assert (
      "OAUTH_CLIENT_ID=test-client-123.apps.googleusercontent.com" in env_text
  )
  assert "OAUTH_CLIENT_SECRET=test-secret-xyz" in env_text
  assert "OAUTH_PKCE_ENABLED=false" in env_text

  auth_uri_line = [
      line
      for line in env_text.splitlines()
      if line.startswith("OAUTH_AUTH_URI=")
  ][0]
  auth_uri = auth_uri_line.split("=", 1)[1]
  query = parse_qs(urlsplit(auth_uri).query)
  assert query["client_id"] == ["test-client-123.apps.googleusercontent.com"]
  assert query["redirect_uri"] == [
      "https://vertexaisearch.cloud.google.com/oauth-redirect"
  ]
  assert "https://www.googleapis.com/auth/chronicle" in query["scope"][0]
  assert "state" not in query
  assert "code_challenge" not in query
  assert "code_challenge_method" not in query

  installed_secret = _write_client_secret(
      tmp_path, client_type="installed", filename="installed.json"
  )
  res_pkce = runner.invoke(
      oauth.app,
      [
          "setup",
          str(installed_secret),
          "--env-file",
          str(env_file),
          "--pkce",
          "--scopes",
          "https://www.googleapis.com/auth/chronicle, openid",
      ],
  )
  assert res_pkce.exit_code == 0
  assert "visit" not in res_pkce.output.lower()
  assert "PKCE verification enabled: true" in res_pkce.output
  assert "OAUTH_PKCE_ENABLED=true" in env_file.read_text()


def test_oauth_setup_error_handling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  monkeypatch.setattr(
      oauth.google.auth,
      "default",
      lambda scopes=None: (_FakeCredentials(), "agent-host-proj"),
  )
  env_file = tmp_path / ".env"

  missing_res = runner.invoke(
      oauth.app,
      ["setup", str(tmp_path / "nope.json"), "--env-file", str(env_file)],
  )
  assert missing_res.exit_code == 1
  assert "Client secret file not found" in missing_res.output

  invalid_secret = tmp_path / "invalid.json"
  invalid_secret.write_text(json.dumps({"other": {}}))
  invalid_res = runner.invoke(
      oauth.app,
      ["setup", str(invalid_secret), "--env-file", str(env_file)],
  )
  assert invalid_res.exit_code == 1
  assert "Invalid client secret file format" in invalid_res.output


def test_oauth_create_auth_verify_and_delete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  fake_creds = _FakeCredentials(bearer_value="fresh-bearer", valid=False)
  monkeypatch.setattr(
      oauth.google.auth,
      "default",
      lambda scopes=None: (fake_creds, "agent-host-proj"),
  )

  env_file = _write_env_file(
      tmp_path / ".env",
      {
          "GCP_PROJECT_NUMBER": "123456789012",
          "OAUTH_CLIENT_ID": "test-client-123.apps.googleusercontent.com",
          "OAUTH_CLIENT_SECRET": "test-secret-xyz",
          "OAUTH_AUTH_URI": (
              "https://accounts.google.com/o/oauth2/auth?response_type=code"
          ),
          "OAUTH_TOKEN_URI": "https://oauth2.googleapis.com/token",
          "OAUTH_PKCE_ENABLED": "true",
      },
  )
  monkeypatch.delenv("OAUTH_AUTH_ID", raising=False)

  captured_posts: list[dict[str, object]] = []

  def _fake_post(
      url: str,
      headers: dict[str, str],
      json: dict[str, object],
      params: dict[str, str],
      timeout: int = 60,
  ) -> object:
    captured_posts.append(
        {
            "url": url,
            "headers": headers,
            "json": json,
            "params": params,
            "timeout": timeout,
        }
    )
    return SimpleNamespace(
        status_code=200,
        raise_for_status=lambda: None,
        json=lambda: json,
    )

  monkeypatch.setattr(oauth.requests, "post", _fake_post)

  create_res = runner.invoke(
      oauth.app,
      ["create-auth", "--env-file", str(env_file)],
  )
  assert create_res.exit_code == 0
  assert fake_creds.refreshed is True
  assert len(captured_posts) == 1
  posted_body = captured_posts[0]["json"]
  assert isinstance(posted_body, dict)
  sso = posted_body["serverSideOauth2"]
  assert isinstance(sso, dict)
  assert sso["pkceVerificationEnabled"] is True
  generated_id = captured_posts[0]["params"]
  assert isinstance(generated_id, dict)
  assert generated_id["authorizationId"].startswith("auth-")
  assert "Gemini Enterprise" in create_res.output
  assert "AgentSpace" not in create_res.output

  override_res = runner.invoke(
      oauth.app,
      [
          "create-auth",
          "--auth-id",
          "explicit-auth-v1",
          "--no-pkce",
          "--env-file",
          str(env_file),
      ],
  )
  assert override_res.exit_code == 0
  override_body = captured_posts[1]["json"]
  assert isinstance(override_body, dict)
  override_sso = override_body["serverSideOauth2"]
  assert isinstance(override_sso, dict)
  assert override_sso["pkceVerificationEnabled"] is False
  assert "OAUTH_PKCE_ENABLED=false" in env_file.read_text()

  def _fake_get(url: str, headers: dict[str, str], timeout: int = 60) -> object:
    del headers, timeout
    return SimpleNamespace(
        status_code=200,
        raise_for_status=lambda: None,
        json=lambda: {"name": url, "serverSideOauth2": {"clientId": "abc"}},
    )

  monkeypatch.setattr(oauth.requests, "get", _fake_get)
  verify_res = runner.invoke(oauth.app, ["verify", "--env-file", str(env_file)])
  assert verify_res.exit_code == 0
  assert "explicit-auth-v1" in verify_res.output

  deleted_urls: list[str] = []

  def _fake_delete(
      url: str, headers: dict[str, str], timeout: int = 60
  ) -> object:
    del headers, timeout
    deleted_urls.append(url)
    return SimpleNamespace(status_code=200, raise_for_status=lambda: None)

  monkeypatch.setattr(oauth.requests, "delete", _fake_delete)

  cancel_del = runner.invoke(
      oauth.app, ["delete", "--env-file", str(env_file)], input="n\n"
  )
  assert cancel_del.exit_code == 0
  assert "Deletion cancelled." in cancel_del.output
  assert len(deleted_urls) == 0

  force_del = runner.invoke(
      oauth.app, ["delete", "--force", "--env-file", str(env_file)]
  )
  assert force_del.exit_code == 0
  assert "Authorization deleted successfully." in force_del.output
  assert len(deleted_urls) == 1


def test_oauth_http_and_env_failure_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  monkeypatch.setattr(
      oauth.google.auth,
      "default",
      lambda scopes=None: (
          _FakeCredentials(bearer_value="tok", valid=True),
          "proj",
      ),
  )
  empty_env = tmp_path / "empty.env"
  for key in (
      "GCP_PROJECT_NUMBER",
      "OAUTH_AUTH_ID",
      "OAUTH_CLIENT_ID",
      "OAUTH_CLIENT_SECRET",
      "OAUTH_AUTH_URI",
  ):
    monkeypatch.delenv(key, raising=False)

  no_creds_res = runner.invoke(
      oauth.app,
      ["create-auth", "--auth-id", "a1", "--env-file", str(empty_env)],
  )
  assert no_creds_res.exit_code == 1

  no_id_verify = runner.invoke(
      oauth.app, ["verify", "--env-file", str(empty_env)]
  )
  assert no_id_verify.exit_code == 1

  no_id_delete = runner.invoke(
      oauth.app, ["delete", "--force", "--env-file", str(empty_env)]
  )
  assert no_id_delete.exit_code == 1

  env_no_proj = _write_env_file(
      tmp_path / "noproj.env",
      {
          "OAUTH_AUTH_ID": "a1",
          "OAUTH_CLIENT_ID": "cid",
          "OAUTH_CLIENT_SECRET": "csec",
          "OAUTH_AUTH_URI": "https://accounts.google.com/o/oauth2/auth",
      },
  )
  assert (
      runner.invoke(
          oauth.app, ["create-auth", "--env-file", str(env_no_proj)]
      ).exit_code
      == 1
  )
  assert (
      runner.invoke(
          oauth.app, ["verify", "--env-file", str(env_no_proj)]
      ).exit_code
      == 1
  )
  assert (
      runner.invoke(
          oauth.app, ["delete", "--force", "--env-file", str(env_no_proj)]
      ).exit_code
      == 1
  )

  env_full = _write_env_file(
      tmp_path / "full.env",
      {
          "GCP_PROJECT_NUMBER": "123456789012",
          "OAUTH_AUTH_ID": "a1",
          "OAUTH_CLIENT_ID": "cid",
          "OAUTH_CLIENT_SECRET": "csec",
          "OAUTH_AUTH_URI": "https://accounts.google.com/o/oauth2/auth",
      },
  )

  err_response = SimpleNamespace(status_code=400, text="bad request")

  def _raise_req(*args: object, **kwargs: object) -> object:
    del args, kwargs
    exc = requests.exceptions.HTTPError("400 Client Error")
    exc.response = err_response  # type: ignore[assignment]
    raise exc

  monkeypatch.setattr(oauth.requests, "post", _raise_req)
  monkeypatch.setattr(oauth.requests, "get", _raise_req)
  monkeypatch.setattr(oauth.requests, "delete", _raise_req)

  assert (
      runner.invoke(
          oauth.app, ["create-auth", "--env-file", str(env_full)]
      ).exit_code
      == 1
  )
  assert (
      runner.invoke(
          oauth.app, ["verify", "--env-file", str(env_full)]
      ).exit_code
      == 1
  )
  assert (
      runner.invoke(
          oauth.app, ["delete", "--force", "--env-file", str(env_full)]
      ).exit_code
      == 1
  )


def test_oauth_manager_requests_cloud_platform_scope_for_verify(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
  captured_scopes: list[object] = []

  class _ScopedCredentials:

    def __init__(self) -> None:
      self.token: str | None = None
      self.valid = False
      self.refreshed = False

    def refresh(self, request: object) -> None:
      del request
      assert captured_scopes[-1] == [
          "https://www.googleapis.com/auth/cloud-platform"
      ]
      self.refreshed = True
      self.valid = True
      self.token = "scoped-bearer-value"  # noqa: S105

  fake_creds = _ScopedCredentials()

  def _fake_default(
      scopes: list[str] | None = None,
  ) -> tuple[_ScopedCredentials, str]:
    captured_scopes.append(scopes)
    return fake_creds, "agent-host-proj"

  monkeypatch.setattr(oauth.google.auth, "default", _fake_default)

  env_file = _write_env_file(
      tmp_path / ".env",
      {
          "GCP_PROJECT_NUMBER": "123456789012",
          "OAUTH_AUTH_ID": "scoped-auth-v1",
      },
  )

  seen_headers: list[dict[str, str]] = []

  def _fake_get(url: str, headers: dict[str, str], timeout: int = 60) -> object:
    del timeout
    seen_headers.append(headers)
    return SimpleNamespace(
        status_code=200,
        raise_for_status=lambda: None,
        json=lambda: {
            "name": url,
            "serverSideOauth2": {"pkceVerificationEnabled": True},
        },
    )

  monkeypatch.setattr(oauth.requests, "get", _fake_get)

  res = runner.invoke(
      oauth.app,
      ["verify", "--auth-id", "scoped-auth-v1", "--env-file", str(env_file)],
  )
  assert res.exit_code == 0
  assert captured_scopes == [["https://www.googleapis.com/auth/cloud-platform"]]
  assert fake_creds.refreshed is True
  assert seen_headers == [
      {
          "Authorization": "Bearer scoped-bearer-value",
          "X-Goog-User-Project": "123456789012",
      }
  ]
  assert "scoped-auth-v1" in res.output


def test_docs_prerequisites_locational_endpoint_and_hygiene() -> None:
  readme = (REPO_ROOT / "README.md").read_text()
  setup_doc = (REPO_ROOT / "docs" / "setup.md").read_text()
  design_spec = (REPO_ROOT / "docs" / "DESIGN_SPEC.md").read_text()

  for doc_text in (readme, setup_doc):
    assert "a1b2c3d4-e5f6-4321-abcd-ef1234567890" in doc_text
    assert "00000000-0000-0000-0000-000000000000" not in doc_text
    assert "roles/mcp.toolUser" in doc_text
    assert "roles/chronicle.viewer" in doc_text
    assert "roles/serviceusage.serviceUsageConsumer" in doc_text
    assert "x-goog-user-project" in doc_text
    assert "Settings > Access management > Group Mapping" in doc_text
    assert "Settings > Access management > User Management" in doc_text
    assert "401 You are not recognized." in doc_text

  assert "https://{region}-chronicle.googleapis.com/mcp" in design_spec
  assert "rep.googleapis.com" not in design_spec
  assert "make " not in design_spec

  owned_files = [
      REPO_ROOT / "src" / "oauth_flow_gemini_enterprise_secops_mcp" / "iam.py",
      REPO_ROOT
      / "src"
      / "oauth_flow_gemini_enterprise_secops_mcp"
      / "oauth.py",
      REPO_ROOT / "README.md",
      REPO_ROOT / "docs" / "setup.md",
      REPO_ROOT / "docs" / "DESIGN_SPEC.md",
      REPO_ROOT / "tests" / "test_iam_and_oauth.py",
  ]
  for file_path in owned_files:
    text = file_path.read_text()
    assert "\u2014" not in text, f"Found em-dash in {file_path}"
