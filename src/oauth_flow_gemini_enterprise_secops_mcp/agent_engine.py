#!/usr/bin/env python3
"""Agent Engine management CLI for the Google SecOps MCP agent."""

import importlib
import inspect
import logging
import os
import re
import sys
import traceback
from pathlib import Path
from typing import Annotated
from typing import Any

import google.auth
import google.auth.transport._mtls_helper as _mtls_helper
import google.auth.transport.requests
import typer
import vertexai
from dotenv import load_dotenv
from google.cloud import aiplatform
from google.cloud import aiplatform_v1beta1
from google.cloud import storage
from google.protobuf import field_mask_pb2
from vertexai import agent_engines
from vertexai.agent_engines import AdkApp

# Bypass workstation mTLS client-certificate probe
_mtls_helper.has_client_certificate = lambda: False
_mtls_helper.get_client_cert_and_key = lambda: (False, None, None)
_mtls_helper.get_client_ssl_credentials = lambda *args, **kwargs: (
    False,
    None,
    None,
    None,
)

logger = logging.getLogger(__name__)

app = typer.Typer(help="Manage Google SecOps MCP Agent Engine instances.")

ADK_TELEMETRY_ENV_VARS: dict[str, str] = {
    "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY": "true",
    "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "true",
    "OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT": "32768",
    "GOOGLE_CLOUD_LOCATION": "global",
    "SECOPS_USE_INTERACTIONS_API": "true",
}

STRIPPED_ENV_VARS: frozenset[str] = frozenset(
    {"ADK_DISABLE_JSON_SCHEMA_FOR_FUNC_DECL"}
)

_DOTENV_LINE_RE = re.compile(
    r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$"
)


def _supports_kwarg(func: Any, param_name: str) -> bool:
  """Return True if callable accepts param_name as a keyword argument."""
  try:
    params = inspect.signature(func).parameters
  except (TypeError, ValueError):
    return False
  if param_name in params:
    return params[param_name].kind != inspect.Parameter.POSITIONAL_ONLY
  return any(
      param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values()
  )


def _resolve_min_instances(min_instances: int | None = None) -> int:
  """Resolve minimum instance count from CLI option or environment."""
  if min_instances is not None:
    value = min_instances
  else:
    raw = os.environ.get("AGENT_ENGINE_MIN_INSTANCES", "0")
    try:
      value = int(raw)
    except ValueError as exc:
      typer.secho(
          "Error: AGENT_ENGINE_MIN_INSTANCES must be an integer"
          f" (got '{raw}').",
          fg=typer.colors.RED,
      )
      raise typer.Exit(1) from exc
  if value < 0:
    typer.secho(
        f"Error: min_instances must be >= 0 (got {value}).",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)
  return value


def _resolve_python_version(python_version: str | None = None) -> str:
  """Resolve target Python version from CLI option, environment, or runtime."""
  if python_version:
    return python_version
  return (
      os.environ.get("AGENT_ENGINE_PYTHON_VERSION")
      or f"{sys.version_info.major}.{sys.version_info.minor}"
  )


def _quote_dotenv_value(value: str) -> str:
  """Format a value as a safely double-quoted .env assignment string."""
  sanitized = (
      value.replace("\\", "\\\\")
      .replace('"', '\\"')
      .replace("\r", "")
      .replace("\n", "")
  )
  return f'"{sanitized}"'


def _update_dotenv_agent_engine(
    resource_name: str,
    env_path: Path = Path(".env"),
) -> bool:
  """Update AGENT_ENGINE_RESOURCE_NAME and AGENT_ENGINE_ID in an existing .env.

  Args:
    resource_name: Deployed Reasoning Engine resource name.
    env_path: Path to the .env file to update if it already exists.

  Returns:
    True if env_path existed and was updated, False otherwise.
  """
  if not env_path.exists():
    return False

  engine_id = resource_name.rstrip("/").split("/")[-1]
  updates = {
      "AGENT_ENGINE_RESOURCE_NAME": resource_name,
      "AGENT_ENGINE_ID": engine_id,
  }

  existing_lines = env_path.read_text(encoding="utf-8").splitlines()
  updated_lines: list[str] = []
  seen_keys: set[str] = set()

  for line in existing_lines:
    match = _DOTENV_LINE_RE.match(line)
    if match and match.group(2) in updates:
      prefix, key = match.group(1), match.group(2)
      if key not in seen_keys:
        updated_lines.append(
            f"{prefix}{key}={_quote_dotenv_value(updates[key])}"
        )
        seen_keys.add(key)
      continue
    updated_lines.append(line)

  for key in ("AGENT_ENGINE_RESOURCE_NAME", "AGENT_ENGINE_ID"):
    if key not in seen_keys:
      updated_lines.append(f"{key}={_quote_dotenv_value(updates[key])}")

  env_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
  return True


def _ensure_staging_bucket(
    project: str,
    location: str,
    staging_bucket: str | None,
    *,
    create_bucket: bool = False,
) -> str:
  """Verify that GCP_STAGING_BUCKET exists, optionally creating it.

  Args:
    project: Google Cloud project ID.
    location: Google Cloud region for bucket creation if missing.
    staging_bucket: Configured gs://<bucket> URI from GCP_STAGING_BUCKET.
    create_bucket: Whether to create the bucket when it does not exist.

  Returns:
    Validated bucket name without the gs:// scheme.
  """
  if not staging_bucket:
    typer.secho(
        "Error: GCP_STAGING_BUCKET is not set in .env.\n"
        "Set GCP_STAGING_BUCKET=gs://<your-staging-bucket> and create it:\n"
        "  gcloud storage buckets create gs://<your-staging-bucket>"
        f" --project={project} --location={location}\n"
        "or pass --create-bucket to create the bucket during deploy.",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)

  if not staging_bucket.startswith("gs://"):
    typer.secho(
        "Error: GCP_STAGING_BUCKET must start with 'gs://'"
        f" (got '{staging_bucket}').",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)

  bucket_name = staging_bucket[len("gs://") :].strip("/").split("/", 1)[0]
  if not bucket_name:
    typer.secho(
        f"Error: GCP_STAGING_BUCKET '{staging_bucket}' is missing a bucket"
        " name.",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)

  try:
    storage_client = storage.Client(project=project)
    existing_bucket = storage_client.lookup_bucket(bucket_name)
  except Exception as exc:
    typer.secho(
        f"Error checking staging bucket gs://{bucket_name}: {exc}",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1) from exc

  if existing_bucket is not None:
    return bucket_name

  if not create_bucket:
    typer.secho(
        f"Error: Staging bucket gs://{bucket_name} does not exist.\n"
        "Create it first with:\n"
        f"  gcloud storage buckets create gs://{bucket_name}"
        f" --project={project} --location={location}\n"
        "or re-run deploy with --create-bucket.",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)

  typer.echo(
      f"Staging bucket gs://{bucket_name} not found; creating in {location}..."
  )
  try:
    storage_client.create_bucket(bucket_name, location=location)
  except Exception as exc:
    typer.secho(
        f"Error creating staging bucket gs://{bucket_name}: {exc}",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1) from exc

  typer.secho(
      f"Created staging bucket gs://{bucket_name}",
      fg=typer.colors.GREEN,
  )
  return bucket_name


def _apply_adk_deployment_spec(
    resource_name: str,
    min_instances: int | None = None,
) -> None:
  """Apply ADK framework metadata, telemetry env vars, and scaling config."""
  resolved_min_instances = _resolve_min_instances(min_instances)
  location = os.environ.get("GCP_LOCATION", "us-central1")
  client_options = {"api_endpoint": f"{location}-aiplatform.googleapis.com"}
  client = aiplatform_v1beta1.ReasoningEngineServiceClient(
      client_options=client_options
  )

  existing_engine = client.get_reasoning_engine(name=resource_name)
  existing_envs = {
      env_var.name: env_var
      for env_var in existing_engine.spec.deployment_spec.env
      if env_var.name not in STRIPPED_ENV_VARS
  }
  for key, value in ADK_TELEMETRY_ENV_VARS.items():
    existing_envs[key] = aiplatform_v1beta1.EnvVar(name=key, value=value)

  new_spec = aiplatform_v1beta1.ReasoningEngineSpec(
      agent_framework="google-adk",
      deployment_spec=aiplatform_v1beta1.ReasoningEngineSpec.DeploymentSpec(
          env=list(existing_envs.values()),
          min_instances=resolved_min_instances,
      ),
  )
  update_mask = field_mask_pb2.FieldMask(
      paths=[
          "spec.agent_framework",
          "spec.deployment_spec.env",
          "spec.deployment_spec.min_instances",
      ]
  )
  reasoning_engine_resource = aiplatform_v1beta1.ReasoningEngine(
      name=resource_name,
      spec=new_spec,
  )
  client.update_reasoning_engine(
      reasoning_engine=reasoning_engine_resource,
      update_mask=update_mask,
  ).result()


def setup_vertex_ai() -> tuple[str, str]:
  """Initialize Vertex AI from environment."""
  load_dotenv()
  local_adc = Path.cwd() / ".gcloud" / "application_default_credentials.json"
  if (
      not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
      and local_adc.exists()
  ):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(local_adc)

  project = os.environ.get("GCP_PROJECT_ID")
  location = os.environ.get("GCP_LOCATION", "us-central1")
  staging_bucket = os.environ.get("GCP_STAGING_BUCKET")

  if not project:
    typer.secho("Error: GCP_PROJECT_ID not set in .env", fg=typer.colors.RED)
    raise typer.Exit(1)

  vertexai.init(
      project=project, location=location, staging_bucket=staging_bucket
  )
  aiplatform.init(
      project=project, location=location, staging_bucket=staging_bucket
  )
  return project, location


def get_env_vars() -> dict[str, str]:
  """Collect environment variables for injection."""
  auth_id = os.environ.get("OAUTH_AUTH_ID") or os.environ.get(
      "GEMINI_AUTHORIZATION_ID"
  )
  env_vars: dict[str, str | None] = {
      "CHRONICLE_PROJECT_ID": os.environ.get("CHRONICLE_PROJECT_ID"),
      "CHRONICLE_CUSTOMER_ID": os.environ.get("CHRONICLE_CUSTOMER_ID"),
      "CHRONICLE_REGION": os.environ.get("CHRONICLE_REGION"),
      "GEMINI_AUTHORIZATION_ID": auth_id,
      "OAUTH_AUTH_ID": auth_id,
      "GCP_PROJECT_ID": os.environ.get("GCP_PROJECT_ID"),
      "DEBUG": os.environ.get("DEBUG", "False"),
      **ADK_TELEMETRY_ENV_VARS,
  }
  return {key: val for key, val in env_vars.items() if val is not None}


def get_requirements() -> list[str]:
  """Return the list of requirements for the Reasoning Engine."""
  return [
      "google-adk>=2.0.0",
      "google-cloud-aiplatform[agent-engines,evaluation]>=1.130.0",
      "pydantic",
      "python-dotenv",
      "opentelemetry-sdk",
      "opentelemetry-instrumentation-google-genai",
      "opentelemetry-exporter-gcp-logging",
      "mcp>=1.0.0",
      "gcsfs>=2024.11.0",
      "google-cloud-logging>=3.12.0",
      "protobuf>=6.31.1,<7.0.0",
      "google-genai>=2.24.0,<3.0.0",
  ]


@app.command()
def deploy(
    agent_module: Annotated[
        str,
        typer.Option(
            "--agent-module",
            help="Module containing create_app() or create_agent()",
        ),
    ] = "agent",
    description: Annotated[
        str,
        typer.Option("--description", help="Agent description"),
    ] = "Google SecOps MCP Agent with OAuth Passthrough",
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Enable debug logging"),
    ] = False,
    run_test: Annotated[
        bool,
        typer.Option("--test/--no-test", help="Run a test query after deploy"),
    ] = True,
    min_instances: Annotated[
        int | None,
        typer.Option(
            "--min-instances",
            help=(
                "Minimum running instances (defaults to"
                " AGENT_ENGINE_MIN_INSTANCES or 0)"
            ),
        ),
    ] = None,
    python_version: Annotated[
        str | None,
        typer.Option(
            "--python-version",
            help=(
                "Target Python version (defaults to"
                " AGENT_ENGINE_PYTHON_VERSION or runtime version)"
            ),
        ),
    ] = None,
    create_bucket: Annotated[
        bool,
        typer.Option(
            "--create-bucket/--no-create-bucket",
            help="Create GCP_STAGING_BUCKET if it does not exist",
        ),
    ] = False,
    write_env: Annotated[
        bool,
        typer.Option(
            "--write-env/--no-write-env",
            help="Write AGENT_ENGINE_RESOURCE_NAME and AGENT_ENGINE_ID to .env",
        ),
    ] = True,
) -> None:
  """Deploy a new Agent Engine instance."""
  project, location = setup_vertex_ai()
  resolved_min_instances = _resolve_min_instances(min_instances)
  resolved_python_version = _resolve_python_version(python_version)
  _ensure_staging_bucket(
      project=project,
      location=location,
      staging_bucket=os.environ.get("GCP_STAGING_BUCKET"),
      create_bucket=create_bucket,
  )

  if debug:
    os.environ["DEBUG"] = "True"
    typer.echo("Debug logging enabled")

  typer.echo(f"Deploying ADK 2.x App from module: {agent_module}")
  app_instance = load_adk_app(agent_module)

  create_kwargs: dict[str, Any] = {
      "agent_engine": app_instance,
      "display_name": f"SecOps Agent - {agent_module}",
      "description": description,
      "requirements": get_requirements(),
      "extra_packages": ["secops_agent"],
      "env_vars": get_env_vars(),
  }
  if _supports_kwarg(agent_engines.create, "min_instances"):
    create_kwargs["min_instances"] = resolved_min_instances
  if _supports_kwarg(agent_engines.create, "python_version"):
    create_kwargs["python_version"] = resolved_python_version

  try:
    remote_app = agent_engines.create(**create_kwargs)
    try:
      typer.echo(
          "Tagging engine as 'google-adk' and applying deployment spec..."
      )
      _apply_adk_deployment_spec(
          remote_app.resource_name,
          min_instances=resolved_min_instances,
      )
      typer.secho("Tagging successful!", fg=typer.colors.GREEN)
    except Exception as label_err:
      typer.secho(
          f"Warning: Failed to apply ADK deployment spec: {label_err}",
          fg=typer.colors.YELLOW,
      )

    if write_env and _update_dotenv_agent_engine(remote_app.resource_name):
      typer.echo(
          "Updated AGENT_ENGINE_RESOURCE_NAME and AGENT_ENGINE_ID in .env"
      )

    typer.secho("\nDeployment successful!", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"Resource Name: {remote_app.resource_name}")

    if run_test:
      typer.echo("\nRunning smoke test...")
      try:
        response = query_reasoning_engine(remote_app, "Hello")
        typer.echo(f"Test response: {response}")
      except Exception as test_err:
        typer.secho(
            f"Warning: Smoke test failed: {test_err}", fg=typer.colors.YELLOW
        )

  except typer.Exit:
    raise
  except Exception as exc:
    typer.secho(f"\nDeployment failed: {exc}", fg=typer.colors.RED)
    traceback.print_exc()
    raise typer.Exit(1) from exc


@app.command()
def create(
    agent_module: Annotated[
        str,
        typer.Option(
            "--agent-module",
            help="Module containing create_app() or create_agent()",
        ),
    ] = "agent",
    description: Annotated[
        str,
        typer.Option("--description", help="Agent description"),
    ] = "Google SecOps MCP Agent with OAuth Passthrough",
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Enable debug logging"),
    ] = False,
    run_test: Annotated[
        bool,
        typer.Option("--test/--no-test", help="Run a test query after deploy"),
    ] = True,
    min_instances: Annotated[
        int | None,
        typer.Option(
            "--min-instances",
            help=(
                "Minimum running instances (defaults to"
                " AGENT_ENGINE_MIN_INSTANCES or 0)"
            ),
        ),
    ] = None,
    python_version: Annotated[
        str | None,
        typer.Option(
            "--python-version",
            help=(
                "Target Python version (defaults to"
                " AGENT_ENGINE_PYTHON_VERSION or runtime version)"
            ),
        ),
    ] = None,
    create_bucket: Annotated[
        bool,
        typer.Option(
            "--create-bucket/--no-create-bucket",
            help="Create GCP_STAGING_BUCKET if it does not exist",
        ),
    ] = False,
    write_env: Annotated[
        bool,
        typer.Option(
            "--write-env/--no-write-env",
            help="Write AGENT_ENGINE_RESOURCE_NAME and AGENT_ENGINE_ID to .env",
        ),
    ] = True,
) -> None:
  """Create a new Agent Engine instance (alias for deploy)."""
  deploy(
      agent_module=agent_module,
      description=description,
      debug=debug,
      run_test=run_test,
      min_instances=min_instances,
      python_version=python_version,
      create_bucket=create_bucket,
      write_env=write_env,
  )


@app.command()
def update(
    agent_module: Annotated[
        str,
        typer.Option(
            "--agent-module",
            help="Module containing create_app() or create_agent()",
        ),
    ] = "agent",
    description: Annotated[
        str | None,
        typer.Option("--description", help="Updated agent description"),
    ] = None,
    min_instances: Annotated[
        int | None,
        typer.Option(
            "--min-instances",
            help=(
                "Minimum running instances (defaults to"
                " AGENT_ENGINE_MIN_INSTANCES or 0)"
            ),
        ),
    ] = None,
) -> None:
  """Update an existing Agent Engine instance in-place."""
  setup_vertex_ai()
  resolved_min_instances = _resolve_min_instances(min_instances)
  resource_name = os.environ.get("AGENT_ENGINE_RESOURCE_NAME")

  if not resource_name:
    typer.secho(
        "Error: AGENT_ENGINE_RESOURCE_NAME not set in .env", fg=typer.colors.RED
    )
    raise typer.Exit(1)

  typer.echo(
      f"Updating agent {resource_name} with ADK 2.x App from module:"
      f" {agent_module}"
  )
  app_instance = load_adk_app(agent_module)

  update_kwargs: dict[str, Any] = {
      "resource_name": resource_name,
      "agent_engine": app_instance,
      "display_name": f"SecOps Agent - {agent_module}",
      "description": description,
      "requirements": get_requirements(),
      "extra_packages": ["secops_agent"],
      "env_vars": get_env_vars(),
  }
  if _supports_kwarg(agent_engines.update, "min_instances"):
    update_kwargs["min_instances"] = resolved_min_instances

  try:
    remote_app = agent_engines.update(**update_kwargs)
    try:
      typer.echo("Refreshing ADK tags and deployment spec...")
      _apply_adk_deployment_spec(
          remote_app.resource_name,
          min_instances=resolved_min_instances,
      )
    except Exception as label_err:
      typer.secho(
          f"Warning: Failed to update ADK deployment spec: {label_err}",
          fg=typer.colors.YELLOW,
      )

    typer.secho("\nUpdate successful!", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"Resource Name: {remote_app.resource_name}")
  except typer.Exit:
    raise
  except Exception as exc:
    typer.secho(f"\nUpdate failed: {exc}", fg=typer.colors.RED)
    traceback.print_exc()
    raise typer.Exit(1) from exc


@app.command()
def tag_as_adk(
    resource_name: Annotated[
        str | None,
        typer.Option(
            "--resource-name",
            help="Specific resource name to tag (defaults to .env value)",
        ),
    ] = None,
    min_instances: Annotated[
        int | None,
        typer.Option(
            "--min-instances",
            help=(
                "Minimum running instances (defaults to"
                " AGENT_ENGINE_MIN_INSTANCES or 0)"
            ),
        ),
    ] = None,
) -> None:
  """Tag the Reasoning Engine as an ADK agent and sync deployment spec."""
  setup_vertex_ai()
  resolved_min_instances = _resolve_min_instances(min_instances)
  name = resource_name or os.environ.get("AGENT_ENGINE_RESOURCE_NAME")

  if not name:
    typer.secho(
        "Error: No resource name provided and AGENT_ENGINE_RESOURCE_NAME not"
        " set in .env",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)

  try:
    typer.echo(
        f"Tagging engine {name} as 'google-adk' and applying deployment spec..."
    )
    _apply_adk_deployment_spec(name, min_instances=resolved_min_instances)
    typer.secho(
        "Tagging successful! Cloud Console metrics should now be available.",
        fg=typer.colors.GREEN,
        bold=True,
    )
  except typer.Exit:
    raise
  except Exception as exc:
    typer.secho(f"Tagging failed: {exc}", fg=typer.colors.RED)
    raise typer.Exit(1) from exc


@app.command(name="list")
def list_engines(
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Detailed output"),
    ] = False,
) -> None:
  """List all Agent Engine instances."""
  setup_vertex_ai()
  typer.echo("Listing Agent Engine instances...")

  try:
    engines = list(agent_engines.list())
    if not engines:
      typer.echo("No Agent Engine instances found.")
      return

    for i, engine in enumerate(engines, 1):
      typer.echo(f"{i}. Resource: {engine.resource_name}")
      typer.echo(f"   Display Name: {engine.display_name}")
      if verbose:
        description = (
            getattr(engine, "description", None)
            or getattr(
                getattr(engine, "gca_resource", None), "description", None
            )
            or "N/A"
        )
        typer.echo(f"   Create Time: {engine.create_time}")
        typer.echo(f"   Update Time: {engine.update_time}")
        typer.echo(f"   Description: {description}")
      typer.echo("-" * 40)
  except typer.Exit:
    raise
  except Exception as exc:
    typer.secho(f"Error listing engines: {exc}", fg=typer.colors.RED)
    raise typer.Exit(1) from exc


@app.command()
def delete(
    index: Annotated[
        int | None,
        typer.Option(
            "--index", help="Index of the engine to delete (from list)"
        ),
    ] = None,
    resource: Annotated[
        str | None,
        typer.Option(
            "--resource", help="Full resource name of the engine to delete"
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Skip confirmation prompt"),
    ] = False,
) -> None:
  """Delete an Agent Engine instance."""
  setup_vertex_ai()

  target_engine = None
  if resource:
    try:
      target_engine = agent_engines.get(resource)
    except Exception as exc:
      typer.secho(
          f"Error: Could not find engine with resource name {resource}: {exc}",
          fg=typer.colors.RED,
      )
      raise typer.Exit(1) from exc
  elif index is not None:
    try:
      engines = list(agent_engines.list())
    except Exception as exc:
      typer.secho(f"Error retrieving engine list: {exc}", fg=typer.colors.RED)
      raise typer.Exit(1) from exc
    if index < 1 or index > len(engines):
      typer.secho(
          f"Error: Invalid index {index}. Use 'list' to see valid indices.",
          fg=typer.colors.RED,
      )
      raise typer.Exit(1)
    target_engine = engines[index - 1]
  else:
    typer.secho(
        "Error: Must provide either --index or --resource", fg=typer.colors.RED
    )
    raise typer.Exit(1)

  if not force:
    if not typer.confirm(
        f"Are you sure you want to delete engine {target_engine.resource_name}?"
    ):
      typer.echo("Cancelled.")
      return

  typer.echo(f"Deleting engine: {target_engine.resource_name}...")
  try:
    if force and _supports_kwarg(target_engine.delete, "force"):
      target_engine.delete(force=True)
    else:
      target_engine.delete()
    typer.secho("Deletion successful!", fg=typer.colors.GREEN)
  except Exception as exc:
    typer.secho(f"Deletion failed: {exc}", fg=typer.colors.RED)
    raise typer.Exit(1) from exc


def query_reasoning_engine(engine_or_name: Any, prompt: str) -> str:
  """Query an ADK ReasoningEngine instance via vertexai.agent_engines."""
  resource_name = (
      engine_or_name
      if isinstance(engine_or_name, str)
      else getattr(engine_or_name, "resource_name", str(engine_or_name))
  )
  ae = agent_engines.get(resource_name)

  state: dict[str, str] = {}
  gemini_auth_id = os.environ.get("GEMINI_AUTHORIZATION_ID") or os.environ.get(
      "OAUTH_AUTH_ID"
  )
  if gemini_auth_id:
    try:
      creds, _ = google.auth.default(
          scopes=["https://www.googleapis.com/auth/cloud-platform"]
      )
      creds.refresh(google.auth.transport.requests.Request())
      if creds.token:
        state[gemini_auth_id] = creds.token
    except Exception as auth_err:
      logger.debug("Skipping local ADC token injection: %s", auth_err)

  session = ae.create_session(user_id="test_user", state=state)
  chunks = list(
      ae.stream_query(
          user_id="test_user", session_id=session["id"], message=prompt
      )
  )
  texts: list[str] = []
  for chunk in chunks:
    if isinstance(chunk, dict):
      parts = chunk.get("content", {}).get("parts", [])
      for part in parts:
        if (
            isinstance(part, dict)
            and part.get("text")
            and not part.get("thought")
        ):
          texts.append(part["text"])
    else:
      texts.append(str(chunk))
  return "".join(texts) if texts else str(chunks)


@app.command()
def test(
    query: Annotated[
        str,
        typer.Option(
            "--query",
            "--input",
            help="Input query to send to the agent",
        ),
    ] = "Hello, test connection",
) -> None:
  """Test the deployed agent engine."""
  setup_vertex_ai()
  resource_name = os.environ.get("AGENT_ENGINE_RESOURCE_NAME")
  if not resource_name:
    typer.secho(
        "Error: AGENT_ENGINE_RESOURCE_NAME not set in .env", fg=typer.colors.RED
    )
    raise typer.Exit(1)

  typer.echo(f"Testing engine: {resource_name}")
  try:
    response = query_reasoning_engine(resource_name, query)
    typer.echo(f"\nResponse: {response}")
    typer.secho("\nTest successful!", fg=typer.colors.GREEN, bold=True)
  except typer.Exit:
    raise
  except Exception as exc:
    typer.secho(f"\nTest failed: {exc}", fg=typer.colors.RED)
    raise typer.Exit(1) from exc


test.__test__ = False  # type: ignore[attr-defined]


@app.command()
def warmup() -> None:
  """Pre-warm MCP server connections to reduce cold start latency."""
  typer.echo("Pre-warming agent engine connections...")
  test(query="Warmup query - please initialize tools")


def load_adk_app(module_name: str) -> AdkApp:
  """Import module and return a GA Vertex AI AdkApp wrapping the ADK 2.x App."""
  root_path = os.path.abspath(os.getcwd())
  if root_path not in sys.path:
    sys.path.insert(0, root_path)

  if (
      not module_name.startswith("secops_agent.secops_agent_app.")
      and "." not in module_name
  ):
    module_name = f"secops_agent.secops_agent_app.{module_name}"

  os.environ["REASONING_ENGINE_DEPLOYMENT"] = "True"

  try:
    module = importlib.import_module(module_name)
    if hasattr(module, "create_app"):
      return AdkApp(app=module.create_app())
    if hasattr(module, "create_agent"):
      return AdkApp(agent=module.create_agent())
    typer.secho(
        f"Error: Module '{module_name}' has no create_app() or create_agent()",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)
  except typer.Exit:
    raise
  except Exception as exc:
    typer.secho(
        f"Error loading ADK 2.x app module '{module_name}': {exc}",
        fg=typer.colors.RED,
    )
    traceback.print_exc()
    raise typer.Exit(1) from exc


if __name__ == "__main__":
  app()
