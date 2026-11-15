#!/usr/bin/env python3
"""Upload Google Security Operations (SecOps) Credentials to Secret Manager.

This module uploads a Google Security Operations (SecOps) service account JSON
file to Google Cloud Secret Manager and verifies secret access.

Usage examples:
  just secret-upload --file /path/to/service-account.json
  just secret-verify
  uv run oauth-flow-gemini-enterprise-secops-mcp secret upload --force
"""

import json
import os
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from google.api_core import exceptions
from google.cloud import secretmanager

from oauth_flow_gemini_enterprise_secops_mcp.env_validation import (
    resolve_gemini_enterprise_app_id,
)

app = typer.Typer(
    add_completion=False,
    help=(
        "Upload and verify Google Security Operations (SecOps) credentials in"
        " Google Cloud Secret Manager."
    ),
)


def display_url(env_vars: dict[str, str] | None = None) -> None:
  """Display the Gemini Enterprise Cloud Console URL if configured.

  Args:
      env_vars: Optional environment dictionary (defaults to os.environ).
  """
  if env_vars is None:
    env_vars = dict(os.environ)

  project_id = env_vars.get("GCP_PROJECT_ID")
  app_id = resolve_gemini_enterprise_app_id(env_vars)
  if not project_id or not app_id:
    typer.secho(
        "[ERROR] Cannot generate Gemini Enterprise URL - missing"
        " GCP_PROJECT_ID or GEMINI_ENTERPRISE_APP_ID.",
        fg=typer.colors.RED,
    )
    return

  console_url = (
      "https://console.cloud.google.com/gemini-enterprise/locations/global/"
      f"engines/{app_id}?project={project_id}"
  )
  typer.echo("Gemini Enterprise UI URL:")
  typer.echo("=" * 80)
  typer.echo(console_url)
  typer.echo("=" * 80)


def create_or_update_secret(
    project_id: str,
    secret_id: str,
    secret_data: str,
    force: bool = False,
    credentials_path: Path | None = None,
) -> str:
  """Create or update a secret in Google Cloud Secret Manager.

  Args:
      project_id: Google Cloud project ID.
      secret_id: Name of the secret in Secret Manager.
      secret_data: Secret payload string (JSON).
      force: If True, add a new version without interactive confirmation.
      credentials_path: Optional path to a service account key file.

  Returns:
      Full secret version resource name.
  """
  if credentials_path:
    from google.oauth2 import service_account

    credentials = service_account.Credentials.from_service_account_file(
        str(credentials_path)
    )
    client = secretmanager.SecretManagerServiceClient(credentials=credentials)
    typer.echo(f"[INFO] Using credentials from: {credentials_path}")
  else:
    client = secretmanager.SecretManagerServiceClient()
    typer.echo("[INFO] Using Application Default Credentials (ADC)")

  parent = f"projects/{project_id}"
  secret_name = f"{parent}/secrets/{secret_id}"

  try:
    client.get_secret(name=secret_name)
    secret_exists = True
  except exceptions.NotFound:
    secret_exists = False

  if secret_exists:
    if not force:
      typer.secho(
          f"[WARNING] Secret '{secret_id}' already exists in project"
          f" '{project_id}'",
          fg=typer.colors.YELLOW,
      )
      if not typer.confirm("Do you want to add a new version?", default=True):
        typer.secho("[INFO] Cancelled.", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    typer.echo(f"[INFO] Adding new version to existing secret '{secret_id}'...")
  else:
    typer.echo(f"[INFO] Creating new secret '{secret_id}'...")
    secret = client.create_secret(
        request={
            "parent": parent,
            "secret_id": secret_id,
            "secret": {
                "replication": {
                    "automatic": {},
                },
            },
        }
    )
    typer.secho(f"[OK] Created secret: {secret.name}", fg=typer.colors.GREEN)

  version = client.add_secret_version(
      request={
          "parent": secret_name,
          "payload": {"data": secret_data.encode("UTF-8")},
      }
  )

  typer.secho(
      f"[OK] Added secret version: {version.name}", fg=typer.colors.GREEN
  )
  return version.name


@app.command()
def upload(
    env_file: Annotated[
        Path,
        typer.Option("--env-file", "-e", help="Path to .env file."),
    ] = Path(".env"),
    secret_id: Annotated[
        str,
        typer.Option(
            "--secret-id",
            "-s",
            help="Secret ID in Google Cloud Secret Manager.",
        ),
    ] = "chronicle-service-account",
    service_account_file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "--service-account-file",
            help=(
                "Path to Google SecOps service account JSON file (falls back"
                " to SECOPS_SERVICE_ACCOUNT_PATH or"
                " CHRONICLE_SERVICE_ACCOUNT_PATH)."
            ),
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation prompts."),
    ] = False,
    credentials: Annotated[
        Path | None,
        typer.Option(
            "--credentials",
            "-c",
            help=(
                "Path to service account key file for Secret Manager"
                " authentication (if different from ADC)."
            ),
        ),
    ] = None,
) -> None:
  """Upload Google Security Operations (SecOps) service account JSON to Secret Manager.

  Examples:
    just secret-upload --file /path/to/key.json
    uv run oauth-flow-gemini-enterprise-secops-mcp secret upload --force
  """
  typer.echo("\n" + "=" * 80)
  typer.secho(
      "Upload Google SecOps Service Account to Secret Manager",
      fg=typer.colors.BLUE,
      bold=True,
  )
  typer.echo("=" * 80 + "\n")

  if not env_file.exists():
    typer.secho(
        f"[ERROR] Environment file not found: {env_file}", fg=typer.colors.RED
    )
    raise typer.Exit(1)

  load_dotenv(env_file, override=True)

  project_id = os.environ.get("GCP_PROJECT_ID")
  sa_path_str = (
      str(service_account_file)
      if service_account_file
      else (
          os.environ.get("SECOPS_SERVICE_ACCOUNT_PATH")
          or os.environ.get("CHRONICLE_SERVICE_ACCOUNT_PATH")
      )
  )

  if not project_id:
    typer.secho("[ERROR] GCP_PROJECT_ID not set in .env", fg=typer.colors.RED)
    raise typer.Exit(1)

  if not sa_path_str:
    typer.secho(
        "[ERROR] Service account path not provided. Pass --file <key.json> or"
        " set CHRONICLE_SERVICE_ACCOUNT_PATH in .env.",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)

  sa_file = Path(sa_path_str)
  if not sa_file.exists():
    typer.secho(
        f"[ERROR] Service account file not found: {sa_path_str}",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)

  typer.echo(f"[INFO] Reading service account file: {sa_file}")
  try:
    with open(sa_file, encoding="utf-8") as f:
      sa_data = json.load(f)

    if sa_data.get("type") != "service_account":
      typer.secho(
          "[ERROR] File does not appear to be a service account JSON",
          fg=typer.colors.RED,
      )
      raise typer.Exit(1)

    sa_json_str = json.dumps(sa_data)

    typer.secho("[OK] Valid service account JSON", fg=typer.colors.GREEN)
    typer.echo(f"  Project: {sa_data.get('project_id', 'N/A')}")
    typer.echo(f"  Client Email: {sa_data.get('client_email', 'N/A')}")

  except json.JSONDecodeError as e:
    typer.secho(f"[ERROR] Invalid JSON file: {e}", fg=typer.colors.RED)
    raise typer.Exit(1)

  if credentials and not credentials.exists():
    typer.secho(
        f"[ERROR] Credentials file not found: {credentials}",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)

  typer.echo("\n[INFO] Uploading to Secret Manager...")
  typer.echo(f"  Project: {project_id}")
  typer.echo(f"  Secret ID: {secret_id}")
  if credentials:
    typer.echo(f"  Using credentials: {credentials}")

  try:
    create_or_update_secret(
        project_id=project_id,
        secret_id=secret_id,
        secret_data=sa_json_str,
        force=force,
        credentials_path=credentials,
    )

    typer.echo("\n" + "=" * 80)
    typer.secho("[OK] Upload Complete!", fg=typer.colors.GREEN, bold=True)
    typer.echo("=" * 80 + "\n")

    secret_resource = (
        f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    )
    typer.secho("Next Steps:", fg=typer.colors.YELLOW, bold=True)
    typer.echo("Add this to your .env file:")
    typer.echo()
    typer.secho(
        f'CHRONICLE_SERVICE_ACCOUNT_SECRET="{secret_resource}"',
        fg=typer.colors.CYAN,
    )
    typer.echo()
    typer.echo(
        "Verify access with: just secret-verify (or uv run"
        " oauth-flow-gemini-enterprise-secops-mcp secret verify)"
    )
    typer.echo()

  except typer.Exit:
    raise
  except Exception as e:
    typer.secho(f"[ERROR] Error uploading secret: {e}", fg=typer.colors.RED)
    raise typer.Exit(1)


@app.command()
def verify(
    env_file: Annotated[
        Path,
        typer.Option("--env-file", "-e", help="Path to .env file."),
    ] = Path(".env"),
    secret_id: Annotated[
        str,
        typer.Option(
            "--secret-id",
            "-s",
            help="Secret ID in Google Cloud Secret Manager.",
        ),
    ] = "chronicle-service-account",
    credentials: Annotated[
        Path | None,
        typer.Option(
            "--credentials",
            "-c",
            help=(
                "Path to service account key file for Secret Manager"
                " authentication (if different from ADC)."
            ),
        ),
    ] = None,
) -> None:
  """Verify that the Google SecOps secret exists and is accessible.

  Examples:
    just secret-verify
    uv run oauth-flow-gemini-enterprise-secops-mcp secret verify
  """
  typer.echo("\n" + "=" * 80)
  typer.secho("Verify Secret Access", fg=typer.colors.BLUE, bold=True)
  typer.echo("=" * 80 + "\n")

  if env_file.exists():
    load_dotenv(env_file, override=True)
  project_id = os.environ.get("GCP_PROJECT_ID")

  if not project_id:
    typer.secho("[ERROR] GCP_PROJECT_ID not set in .env", fg=typer.colors.RED)
    raise typer.Exit(1)

  if credentials and not credentials.exists():
    typer.secho(
        f"[ERROR] Credentials file not found: {credentials}",
        fg=typer.colors.RED,
    )
    raise typer.Exit(1)

  if credentials:
    from google.oauth2 import service_account

    creds = service_account.Credentials.from_service_account_file(
        str(credentials)
    )
    client = secretmanager.SecretManagerServiceClient(credentials=creds)
    typer.echo(f"[INFO] Using credentials from: {credentials}")
  else:
    client = secretmanager.SecretManagerServiceClient()
    typer.echo("[INFO] Using Application Default Credentials (ADC)")

  secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"

  try:
    typer.echo(f"[INFO] Accessing secret: {secret_name}")
    response = client.access_secret_version(request={"name": secret_name})

    secret_data = response.payload.data.decode("UTF-8")
    sa_json = json.loads(secret_data)

    typer.secho("[OK] Secret accessible!", fg=typer.colors.GREEN)
    typer.echo(f"  Project: {sa_json.get('project_id', 'N/A')}")
    typer.echo(f"  Client Email: {sa_json.get('client_email', 'N/A')}")
    typer.echo(f"  Size: {len(secret_data)} bytes")

  except exceptions.NotFound:
    typer.secho(f"[ERROR] Secret not found: {secret_name}", fg=typer.colors.RED)
    raise typer.Exit(1)
  except exceptions.PermissionDenied:
    typer.secho(
        "[ERROR] Permission denied accessing secret", fg=typer.colors.RED
    )
    typer.echo(
        "  Ensure your credentials have 'secretmanager.versions.access'"
        " permission"
    )
    raise typer.Exit(1)
  except Exception as e:
    typer.secho(f"[ERROR] Error accessing secret: {e}", fg=typer.colors.RED)
    raise typer.Exit(1)


if __name__ == "__main__":
  app()
