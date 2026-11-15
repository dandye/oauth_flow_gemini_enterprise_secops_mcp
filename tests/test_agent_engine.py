"""Hermetic unit tests for the agent_engine CLI module."""

import inspect
import os
import sys
from pathlib import Path
from types import ModuleType
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock
from unittest.mock import create_autospec

import pytest
from google.cloud import aiplatform_v1beta1
from packaging.requirements import Requirement
from typer.testing import CliRunner

from oauth_flow_gemini_enterprise_secops_mcp import agent_engine

runner = CliRunner()

SAMPLE_RESOURCE_NAME = (
    "projects/123456789012/locations/us-central1/reasoningEngines/9876543210"
)
SAMPLE_CUSTOMER_ID = "a1b2c3d4-e5f6-4321-abcd-ef1234567890"


@pytest.fixture
def base_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
  """Configure clean baseline environment variables in a temporary directory."""
  monkeypatch.chdir(tmp_path)
  for key in (
      "GCP_PROJECT_ID",
      "GCP_LOCATION",
      "GCP_STAGING_BUCKET",
      "CHRONICLE_PROJECT_ID",
      "CHRONICLE_CUSTOMER_ID",
      "CHRONICLE_REGION",
      "OAUTH_AUTH_ID",
      "GEMINI_AUTHORIZATION_ID",
      "AGENT_ENGINE_RESOURCE_NAME",
      "AGENT_ENGINE_ID",
      "AGENT_ENGINE_MIN_INSTANCES",
      "AGENT_ENGINE_PYTHON_VERSION",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "DEBUG",
  ):
    monkeypatch.delenv(key, raising=False)

  monkeypatch.setenv("GCP_PROJECT_ID", "test-gcp-project")
  monkeypatch.setenv("GCP_LOCATION", "us-central1")
  monkeypatch.setenv("GCP_STAGING_BUCKET", "gs://test-staging-bucket")
  monkeypatch.setenv("CHRONICLE_PROJECT_ID", "test-secops-project")
  monkeypatch.setenv("CHRONICLE_CUSTOMER_ID", SAMPLE_CUSTOMER_ID)
  monkeypatch.setenv("CHRONICLE_REGION", "us")
  monkeypatch.setattr(agent_engine, "load_dotenv", lambda *a, **kw: False)
  monkeypatch.setattr(agent_engine.vertexai, "init", MagicMock())
  monkeypatch.setattr(agent_engine.aiplatform, "init", MagicMock())
  return tmp_path


def _make_mock_v1beta1_client(
    monkeypatch: pytest.MonkeyPatch,
    existing_env_vars: dict[str, str] | None = None,
) -> tuple[MagicMock, dict[str, Any]]:
  """Install a mocked ReasoningEngineServiceClient capturing update calls."""
  captured: dict[str, Any] = {}
  env_items = [
      aiplatform_v1beta1.EnvVar(name=key, value=val)
      for key, val in (existing_env_vars or {}).items()
  ]
  existing_engine = aiplatform_v1beta1.ReasoningEngine(
      name=SAMPLE_RESOURCE_NAME,
      spec=aiplatform_v1beta1.ReasoningEngineSpec(
          deployment_spec=aiplatform_v1beta1.ReasoningEngineSpec.DeploymentSpec(
              env=env_items,
              min_instances=1,
          )
      ),
  )

  mock_client = MagicMock()
  mock_client.get_reasoning_engine.return_value = existing_engine

  def _fake_update(
      *,
      reasoning_engine: aiplatform_v1beta1.ReasoningEngine,
      update_mask: Any,
  ) -> MagicMock:
    captured["reasoning_engine"] = reasoning_engine
    captured["update_mask"] = update_mask
    op = MagicMock()
    op.result.return_value = reasoning_engine
    return op

  mock_client.update_reasoning_engine.side_effect = _fake_update

  def _client_factory(*, client_options: dict[str, str]) -> MagicMock:
    captured["client_options"] = client_options
    return mock_client

  monkeypatch.setattr(
      agent_engine.aiplatform_v1beta1,
      "ReasoningEngineServiceClient",
      _client_factory,
  )
  return mock_client, captured


def test_module_hygiene_and_mtls_bypass() -> None:
  source_path = Path(inspect.getfile(agent_engine))
  source_text = source_path.read_text(encoding="utf-8")

  assert "# Bypass workstation mTLS client-certificate probe" in source_text
  assert "cert-provider subprocess crash" not in source_text
  assert "vertexai.preview" not in source_text
  assert not hasattr(agent_engine, "load_agent")
  assert not hasattr(agent_engine, "ReasoningEngine")
  assert agent_engine._mtls_helper.has_client_certificate() is False
  assert agent_engine._mtls_helper.get_client_cert_and_key() == (
      False,
      None,
      None,
  )
  assert agent_engine._mtls_helper.get_client_ssl_credentials() == (
      False,
      None,
      None,
      None,
  )


def test_get_env_vars_syncs_auth_ids_and_drops_none(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  monkeypatch.setenv("OAUTH_AUTH_ID", "secops-oauth-id")
  env_vars = agent_engine.get_env_vars()
  assert env_vars["CHRONICLE_PROJECT_ID"] == "test-secops-project"
  assert env_vars["CHRONICLE_CUSTOMER_ID"] == SAMPLE_CUSTOMER_ID
  assert env_vars["CHRONICLE_REGION"] == "us"
  assert env_vars["OAUTH_AUTH_ID"] == "secops-oauth-id"
  assert env_vars["GEMINI_AUTHORIZATION_ID"] == "secops-oauth-id"
  assert env_vars["GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY"] == "true"
  assert env_vars["SECOPS_USE_INTERACTIONS_API"] == "true"

  monkeypatch.delenv("OAUTH_AUTH_ID")
  monkeypatch.delenv("CHRONICLE_REGION")
  env_without_auth = agent_engine.get_env_vars()
  assert "OAUTH_AUTH_ID" not in env_without_auth
  assert "GEMINI_AUTHORIZATION_ID" not in env_without_auth
  assert "CHRONICLE_REGION" not in env_without_auth


def test_get_requirements_constrains_google_genai() -> None:
  reqs = [Requirement(item) for item in agent_engine.get_requirements()]
  genai_reqs = [req for req in reqs if req.name == "google-genai"]
  assert len(genai_reqs) == 1
  spec = genai_reqs[0].specifier
  assert "2.24.0" in spec
  assert "2.99.0" in spec
  assert "3.0.0" not in spec


def test_setup_vertex_ai_missing_project_and_local_adc(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  adc_file = base_env / ".gcloud" / "application_default_credentials.json"
  adc_file.parent.mkdir(parents=True)
  adc_file.write_text("{}", encoding="utf-8")

  project, location = agent_engine.setup_vertex_ai()
  assert project == "test-gcp-project"
  assert location == "us-central1"
  assert os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") == str(adc_file)

  monkeypatch.delenv("GCP_PROJECT_ID")
  with pytest.raises(agent_engine.typer.Exit) as exc_info:
    agent_engine.setup_vertex_ai()
  assert exc_info.value.exit_code == 1


def test_staging_bucket_validation_missing_vs_create_bucket(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  mock_create = create_autospec(agent_engine.agent_engines.create)
  monkeypatch.setattr(agent_engine.agent_engines, "create", mock_create)
  monkeypatch.setattr(agent_engine, "load_adk_app", lambda mod: MagicMock())

  # 1. Unset GCP_STAGING_BUCKET fails fast before deploy.
  monkeypatch.delenv("GCP_STAGING_BUCKET")
  res_unset = runner.invoke(agent_engine.app, ["deploy", "--no-test"])
  assert res_unset.exit_code == 1
  assert "GCP_STAGING_BUCKET is not set" in res_unset.output
  mock_create.assert_not_called()

  # 2. Invalid URI scheme fails fast.
  monkeypatch.setenv("GCP_STAGING_BUCKET", "http://bad-bucket")
  res_bad_scheme = runner.invoke(agent_engine.app, ["deploy", "--no-test"])
  assert res_bad_scheme.exit_code == 1
  assert "must start with 'gs://'" in res_bad_scheme.output
  mock_create.assert_not_called()

  # 3. Missing bucket with default --no-create-bucket fails with instructions.
  monkeypatch.setenv("GCP_STAGING_BUCKET", "gs://missing-staging-bucket")
  mock_storage_client = MagicMock()
  mock_storage_client.lookup_bucket.return_value = None
  monkeypatch.setattr(
      agent_engine.storage,
      "Client",
      MagicMock(return_value=mock_storage_client),
  )

  res_missing = runner.invoke(agent_engine.app, ["deploy", "--no-test"])
  assert res_missing.exit_code == 1
  assert "gs://missing-staging-bucket does not exist" in res_missing.output
  assert "--create-bucket" in res_missing.output
  mock_storage_client.create_bucket.assert_not_called()
  mock_create.assert_not_called()

  # 4. Missing bucket with --create-bucket creates bucket and deploys.
  mock_create.return_value = SimpleNamespace(resource_name=SAMPLE_RESOURCE_NAME)
  _make_mock_v1beta1_client(monkeypatch)
  res_created = runner.invoke(
      agent_engine.app, ["deploy", "--create-bucket", "--no-test"]
  )
  assert res_created.exit_code == 0, res_created.output
  mock_storage_client.create_bucket.assert_called_once_with(
      "missing-staging-bucket", location="us-central1"
  )
  mock_create.assert_called_once()


def test_deploy_min_instances_python_version_env_stripping_and_dotenv_writeback(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  dotenv_path = base_env / ".env"
  dotenv_path.write_text(
      "# Sample config\n"
      "GCP_PROJECT_ID=test-gcp-project\n"
      "AGENT_ENGINE_RESOURCE_NAME=\n"
      "AGENT_ENGINE_ID=\n"
      "UNCHANGED_KEY=keep-me\n",
      encoding="utf-8",
  )

  mock_storage_client = MagicMock()
  mock_storage_client.lookup_bucket.return_value = MagicMock()
  monkeypatch.setattr(
      agent_engine.storage,
      "Client",
      MagicMock(return_value=mock_storage_client),
  )
  monkeypatch.setattr(agent_engine, "load_adk_app", lambda mod: MagicMock())

  mock_create = create_autospec(agent_engine.agent_engines.create)
  mock_create.return_value = SimpleNamespace(resource_name=SAMPLE_RESOURCE_NAME)
  monkeypatch.setattr(agent_engine.agent_engines, "create", mock_create)

  _, captured = _make_mock_v1beta1_client(
      monkeypatch,
      existing_env_vars={
          "ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL": "true",
          "CUSTOM_VAR": "preserved",
      },
  )

  result = runner.invoke(agent_engine.app, ["deploy", "--no-test", "--debug"])
  assert result.exit_code == 0, result.output
  assert mock_create.call_args.kwargs["min_instances"] == 0
  assert "python_version" not in mock_create.call_args.kwargs

  updated_engine = captured["reasoning_engine"]
  assert updated_engine.spec.agent_framework == "google-adk"
  assert updated_engine.spec.deployment_spec.min_instances == 0
  env_names = {e.name: e.value for e in updated_engine.spec.deployment_spec.env}
  assert "ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL" not in env_names
  assert env_names["CUSTOM_VAR"] == "preserved"
  assert env_names["SECOPS_USE_INTERACTIONS_API"] == "true"
  assert list(captured["update_mask"].paths) == [
      "spec.agent_framework",
      "spec.deployment_spec.env",
      "spec.deployment_spec.min_instances",
  ]

  written = dotenv_path.read_text(encoding="utf-8")
  assert f'AGENT_ENGINE_RESOURCE_NAME="{SAMPLE_RESOURCE_NAME}"' in written
  assert 'AGENT_ENGINE_ID="9876543210"' in written
  assert "UNCHANGED_KEY=keep-me" in written
  assert "# Sample config" in written


def test_create_forwards_python_version_and_respects_no_write_env(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  # Verify .env is not created when absent, nor modified under --no-write-env.
  mock_storage_client = MagicMock()
  mock_storage_client.lookup_bucket.return_value = MagicMock()
  monkeypatch.setattr(
      agent_engine.storage,
      "Client",
      MagicMock(return_value=mock_storage_client),
  )
  monkeypatch.setattr(agent_engine, "load_adk_app", lambda mod: MagicMock())
  _make_mock_v1beta1_client(monkeypatch)

  captured_kwargs: dict[str, Any] = {}

  def _fake_create_with_py_version(
      agent_engine: Any = None,
      *,
      display_name: str | None = None,
      description: str | None = None,
      requirements: list[str] | None = None,
      extra_packages: list[str] | None = None,
      env_vars: dict[str, str] | None = None,
      min_instances: int | None = None,
      python_version: str | None = None,
  ) -> Any:
    captured_kwargs.update(
        min_instances=min_instances,
        python_version=python_version,
    )
    return SimpleNamespace(resource_name=SAMPLE_RESOURCE_NAME)

  monkeypatch.setattr(
      agent_engine.agent_engines, "create", _fake_create_with_py_version
  )
  monkeypatch.setenv("AGENT_ENGINE_MIN_INSTANCES", "2")
  monkeypatch.setenv("AGENT_ENGINE_PYTHON_VERSION", "3.12")

  result = runner.invoke(agent_engine.app, ["create", "--no-test"])
  assert result.exit_code == 0, result.output
  assert captured_kwargs["min_instances"] == 2
  assert captured_kwargs["python_version"] == "3.12"
  assert not (base_env / ".env").exists()

  # CLI flags override env vars, and --no-write-env skips .env write.
  dotenv_path = base_env / ".env"
  dotenv_path.write_text("AGENT_ENGINE_ID=old\n", encoding="utf-8")
  result_override = runner.invoke(
      agent_engine.app,
      [
          "create",
          "--min-instances",
          "0",
          "--python-version",
          "3.11",
          "--no-write-env",
          "--no-test",
      ],
  )
  assert result_override.exit_code == 0, result_override.output
  assert captured_kwargs["min_instances"] == 0
  assert captured_kwargs["python_version"] == "3.11"
  assert dotenv_path.read_text(encoding="utf-8") == "AGENT_ENGINE_ID=old\n"


def test_update_and_tag_as_adk_strip_env_and_apply_min_instances(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  monkeypatch.setenv("AGENT_ENGINE_RESOURCE_NAME", SAMPLE_RESOURCE_NAME)
  monkeypatch.setattr(agent_engine, "load_adk_app", lambda mod: MagicMock())

  mock_update = create_autospec(agent_engine.agent_engines.update)
  mock_update.return_value = SimpleNamespace(resource_name=SAMPLE_RESOURCE_NAME)
  monkeypatch.setattr(agent_engine.agent_engines, "update", mock_update)

  _, update_captured = _make_mock_v1beta1_client(
      monkeypatch,
      existing_env_vars={
          "ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL": "true",
          "KEEP_ENV": "1",
      },
  )

  res_update = runner.invoke(
      agent_engine.app, ["update", "--min-instances", "1"]
  )
  assert res_update.exit_code == 0, res_update.output
  assert mock_update.call_args.kwargs["min_instances"] == 1
  update_spec = update_captured["reasoning_engine"].spec
  assert update_spec.deployment_spec.min_instances == 1
  update_envs = {e.name for e in update_spec.deployment_spec.env}
  assert "ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL" not in update_envs
  assert "KEEP_ENV" in update_envs

  # Test tag-as-adk strips ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL and sets 0.
  _, tag_captured = _make_mock_v1beta1_client(
      monkeypatch,
      existing_env_vars={
          "ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL": "true",
          "ANOTHER_ENV": "ok",
      },
  )
  res_tag = runner.invoke(agent_engine.app, ["tag-as-adk"])
  assert res_tag.exit_code == 0, res_tag.output
  tag_spec = tag_captured["reasoning_engine"].spec
  assert tag_spec.deployment_spec.min_instances == 0
  tag_envs = {e.name for e in tag_spec.deployment_spec.env}
  assert "ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL" not in tag_envs
  assert "ANOTHER_ENV" in tag_envs
  assert list(tag_captured["update_mask"].paths) == [
      "spec.agent_framework",
      "spec.deployment_spec.env",
      "spec.deployment_spec.min_instances",
  ]


def test_invalid_min_instances_exits_cleanly(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  monkeypatch.setenv("AGENT_ENGINE_MIN_INSTANCES", "not-an-int")
  res_bad_env = runner.invoke(agent_engine.app, ["tag-as-adk"])
  assert res_bad_env.exit_code == 1
  assert "must be an integer" in res_bad_env.output

  monkeypatch.delenv("AGENT_ENGINE_MIN_INSTANCES")
  res_neg = runner.invoke(
      agent_engine.app, ["tag-as-adk", "--min-instances", "-1"]
  )
  assert res_neg.exit_code == 1
  assert "must be >= 0" in res_neg.output


def test_list_and_delete_commands_use_agent_engines_sdk(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  # Empty generator from agent_engines.list()
  monkeypatch.setattr(agent_engine.agent_engines, "list", lambda: iter(()))
  res_empty = runner.invoke(agent_engine.app, ["list"])
  assert res_empty.exit_code == 0
  assert "No Agent Engine instances found." in res_empty.output

  fake_engine = MagicMock()
  fake_engine.resource_name = SAMPLE_RESOURCE_NAME
  fake_engine.display_name = "SecOps Agent - agent"
  fake_engine.create_time = "2026-01-01T00:00:00Z"
  fake_engine.update_time = "2026-01-02T00:00:00Z"
  fake_engine.description = None
  fake_engine.gca_resource = SimpleNamespace(description="ADK SecOps Engine")

  monkeypatch.setattr(
      agent_engine.agent_engines, "list", lambda: iter([fake_engine])
  )
  res_verbose = runner.invoke(agent_engine.app, ["list", "--verbose"])
  assert res_verbose.exit_code == 0
  assert SAMPLE_RESOURCE_NAME in res_verbose.output
  assert "ADK SecOps Engine" in res_verbose.output

  # Delete without --index or --resource fails.
  res_no_args = runner.invoke(agent_engine.app, ["delete"])
  assert res_no_args.exit_code == 1
  assert "Must provide either --index or --resource" in res_no_args.output

  # Delete with out-of-range --index fails cleanly.
  res_bad_idx = runner.invoke(
      agent_engine.app, ["delete", "--index", "5", "--force"]
  )
  assert res_bad_idx.exit_code == 1
  assert "Invalid index 5" in res_bad_idx.output

  # Delete by --index cancelled when user declines confirmation.
  res_cancel = runner.invoke(
      agent_engine.app, ["delete", "--index", "1"], input="n\n"
  )
  assert res_cancel.exit_code == 0
  assert "Cancelled." in res_cancel.output
  fake_engine.delete.assert_not_called()

  # Delete by --resource with --force uses agent_engines.get and deletes.
  monkeypatch.setattr(
      agent_engine.agent_engines, "get", MagicMock(return_value=fake_engine)
  )
  res_del = runner.invoke(
      agent_engine.app,
      ["delete", "--resource", SAMPLE_RESOURCE_NAME, "--force"],
  )
  assert res_del.exit_code == 0, res_del.output
  fake_engine.delete.assert_called_once_with(force=True)


def test_test_and_warmup_commands_and_query_reasoning_engine(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  # Missing AGENT_ENGINE_RESOURCE_NAME exits 1.
  res_missing = runner.invoke(agent_engine.app, ["test"])
  assert res_missing.exit_code == 1
  assert "AGENT_ENGINE_RESOURCE_NAME not set" in res_missing.output

  monkeypatch.setenv("AGENT_ENGINE_RESOURCE_NAME", SAMPLE_RESOURCE_NAME)
  monkeypatch.setenv("GEMINI_AUTHORIZATION_ID", "secops-auth-id")

  fake_creds = MagicMock(**{"token": "sample-oauth-bearer"})
  monkeypatch.setattr(
      agent_engine.google.auth,
      "default",
      MagicMock(return_value=(fake_creds, "test-gcp-project")),
  )

  captured_queries: list[tuple[dict[str, str], str]] = []
  fake_remote = MagicMock()

  def _create_session(*, user_id: str, state: dict[str, str]) -> dict[str, str]:
    captured_queries.append((dict(state), ""))
    return {"id": "sess-123"}

  def _stream_query(
      *, user_id: str, session_id: str, message: str
  ) -> list[dict[str, Any]]:
    state, _ = captured_queries[-1]
    captured_queries[-1] = (state, message)
    return [
        {
            "content": {
                "parts": [{"text": "internal reasoning", "thought": True}]
            }
        },
        {"content": {"parts": [{"text": f"Ack: {message}"}]}},
    ]

  fake_remote.create_session.side_effect = _create_session
  fake_remote.stream_query.side_effect = _stream_query
  monkeypatch.setattr(
      agent_engine.agent_engines, "get", MagicMock(return_value=fake_remote)
  )

  # Default query
  res_default = runner.invoke(agent_engine.app, ["test"])
  assert res_default.exit_code == 0, res_default.output
  assert "Ack: Hello, test connection" in res_default.output
  assert "internal reasoning" not in res_default.output
  assert captured_queries[-1] == (
      {"secops-auth-id": "sample-oauth-bearer"},
      "Hello, test connection",
  )

  # --query option
  res_query = runner.invoke(
      agent_engine.app, ["test", "--query", "List recent alerts"]
  )
  assert res_query.exit_code == 0, res_query.output
  assert captured_queries[-1][1] == "List recent alerts"

  # Backward-compatible --input option
  res_input = runner.invoke(
      agent_engine.app, ["test", "--input", "Legacy input flag"]
  )
  assert res_input.exit_code == 0, res_input.output
  assert captured_queries[-1][1] == "Legacy input flag"

  # Warmup command
  res_warmup = runner.invoke(agent_engine.app, ["warmup"])
  assert res_warmup.exit_code == 0, res_warmup.output
  assert captured_queries[-1][1] == "Warmup query - please initialize tools"


def test_load_adk_app_variants_and_errors(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  monkeypatch.setattr(
      agent_engine,
      "AdkApp",
      lambda **kwargs: SimpleNamespace(**kwargs),
  )

  app_mod = ModuleType("custom_pkg.with_app")
  app_mod.create_app = lambda: "adk_app_obj"  # type: ignore[attr-defined]
  monkeypatch.setitem(sys.modules, "custom_pkg.with_app", app_mod)
  wrapped_app = agent_engine.load_adk_app("custom_pkg.with_app")
  assert wrapped_app.app == "adk_app_obj"

  agent_mod = ModuleType("secops_agent.secops_agent_app.only_agent")
  agent_mod.create_agent = lambda: "adk_agent_obj"  # type: ignore[attr-defined]
  monkeypatch.setitem(
      sys.modules, "secops_agent.secops_agent_app.only_agent", agent_mod
  )
  wrapped_agent = agent_engine.load_adk_app("only_agent")
  assert wrapped_agent.agent == "adk_agent_obj"

  empty_mod = ModuleType("custom_pkg.empty_mod")
  monkeypatch.setitem(sys.modules, "custom_pkg.empty_mod", empty_mod)
  with pytest.raises(agent_engine.typer.Exit) as exc_info:
    agent_engine.load_adk_app("custom_pkg.empty_mod")
  assert exc_info.value.exit_code == 1


def test_dotenv_append_and_quote_escaping(tmp_path: Path) -> None:
  env_file = tmp_path / ".env"
  env_file.write_text("GCP_PROJECT_ID=demo\n", encoding="utf-8")

  updated = agent_engine._update_dotenv_agent_engine(
      'projects/demo/locations/us-central1/reasoningEngines/12"34',
      env_path=env_file,
  )
  assert updated is True
  lines = env_file.read_text(encoding="utf-8").splitlines()
  assert lines == [
      "GCP_PROJECT_ID=demo",
      (
          'AGENT_ENGINE_RESOURCE_NAME="projects/demo/locations/us-central1/'
          'reasoningEngines/12\\"34"'
      ),
      'AGENT_ENGINE_ID="12\\"34"',
  ]


def test_error_and_fallback_branches(
    base_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
  assert agent_engine._supports_kwarg(42, "min_instances") is False

  # Empty bucket name after gs://
  monkeypatch.setenv("GCP_STAGING_BUCKET", "gs:///")
  res_empty_bucket = runner.invoke(agent_engine.app, ["deploy", "--no-test"])
  assert res_empty_bucket.exit_code == 1
  assert "missing a bucket name" in res_empty_bucket.output

  # Deploy with smoke test enabled, label warning, and smoke test warning.
  monkeypatch.setenv("GCP_STAGING_BUCKET", "gs://valid-bucket")
  mock_storage_client = MagicMock()
  mock_storage_client.lookup_bucket.return_value = MagicMock()
  monkeypatch.setattr(
      agent_engine.storage,
      "Client",
      MagicMock(return_value=mock_storage_client),
  )
  monkeypatch.setattr(agent_engine, "load_adk_app", lambda mod: MagicMock())
  mock_create = create_autospec(agent_engine.agent_engines.create)
  mock_create.return_value = SimpleNamespace(resource_name=SAMPLE_RESOURCE_NAME)
  monkeypatch.setattr(agent_engine.agent_engines, "create", mock_create)
  monkeypatch.setattr(
      agent_engine,
      "_apply_adk_deployment_spec",
      MagicMock(side_effect=RuntimeError("v1beta1 unavailable")),
  )
  monkeypatch.setattr(
      agent_engine,
      "query_reasoning_engine",
      MagicMock(side_effect=RuntimeError("smoke timeout")),
  )
  res_warn = runner.invoke(agent_engine.app, ["deploy", "--test"])
  assert res_warn.exit_code == 0, res_warn.output
  assert "Warning: Failed to apply ADK deployment spec" in res_warn.output
  assert "Warning: Smoke test failed" in res_warn.output

  # Update missing AGENT_ENGINE_RESOURCE_NAME and tag-as-adk missing resource
  res_upd_missing = runner.invoke(agent_engine.app, ["update"])
  assert res_upd_missing.exit_code == 1
  res_tag_missing = runner.invoke(agent_engine.app, ["tag-as-adk"])
  assert res_tag_missing.exit_code == 1

  # Delete by --index confirmed interactively (non-force path)
  fake_engine = MagicMock()
  fake_engine.resource_name = SAMPLE_RESOURCE_NAME
  monkeypatch.setattr(
      agent_engine.agent_engines, "list", lambda: iter([fake_engine])
  )
  res_del_confirm = runner.invoke(
      agent_engine.app, ["delete", "--index", "1"], input="y\n"
  )
  assert res_del_confirm.exit_code == 0, res_del_confirm.output
  fake_engine.delete.assert_called_once_with()
