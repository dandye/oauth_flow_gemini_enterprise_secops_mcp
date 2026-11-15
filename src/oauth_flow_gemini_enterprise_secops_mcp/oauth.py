#!/usr/bin/env python3
"""OAuth Manager for Gemini Enterprise and Google SecOps MCP integration.

This module manages OAuth 2.0 authorization resources in Google Cloud Discovery
Engine for Gemini Enterprise, including generating OAuth authorization URIs,
configuring optional RFC 7636 PKCE verification, and creating, verifying, or
deleting Discovery Engine authorization resources.
"""

import json
import os
from pathlib import Path
from typing import Annotated
from typing import Any
from urllib.parse import parse_qsl
from urllib.parse import quote
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

import google.auth
import google_auth_oauthlib.flow
import requests
import typer
from dotenv import load_dotenv
from google.auth.transport import requests as google_requests

app = typer.Typer(
    add_completion=False,
    help="Manage OAuth authorizations for Gemini Enterprise integration.",
)

DISCOVERY_ENGINE_API_BASE = "https://discoveryengine.googleapis.com/v1alpha"
DEFAULT_REDIRECT_URI = "https://vertexaisearch.cloud.google.com/oauth-redirect"
DEFAULT_OAUTH_EXCHANGE_URI = "https://oauth2.googleapis.com/token"
DEFAULT_OAUTH_SCOPES: tuple[str, ...] = (
    "https://www.googleapis.com/auth/chronicle",
    "https://www.googleapis.com/auth/cloud-platform",
    "openid",
)

# Per-session OAuth query parameters generated dynamically by Gemini Enterprise
# at user sign-in time rather than baked statically into authorizationUri.
_DYNAMIC_OAUTH_QUERY_PARAMS = frozenset(
    {"state", "code_challenge", "code_challenge_method"}
)


def _parse_bool_env(value: str | None, default: bool = False) -> bool:
  """Parse a boolean environment variable string."""
  if value is None:
    return default
  normalized = value.strip().lower()
  if normalized in {"true", "1", "yes"}:
    return True
  if normalized in {"false", "0", "no"}:
    return False
  return default


class OAuthManager:
  """Manages OAuth configuration and Discovery Engine authorization resources."""

  def __init__(self, env_file: Path):
    """Initialize the OAuth manager.

    Args:
        env_file: Path to the environment file.
    """
    self.env_file = env_file
    self.env_vars = self._load_env_vars()
    self.creds, self.project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )

  def _load_env_vars(self) -> dict[str, str]:
    """Load environment variables from the .env file using python-dotenv."""
    if self.env_file.exists():
      load_dotenv(self.env_file, override=True)
    return dict(os.environ)

  def _update_env_var(self, key: str, value: str) -> None:
    """Update an environment variable in the .env file."""
    if not self.env_file.exists():
      self.env_file.touch()

    with open(self.env_file) as f:
      lines = f.readlines()

    if lines and not lines[-1].endswith("\n"):
      lines[-1] += "\n"

    key_found = False
    for i, line in enumerate(lines):
      if line.strip() and not line.strip().startswith("#") and "=" in line:
        existing_key = line.split("=", 1)[0].strip()
        if existing_key == key:
          lines[i] = f"{key}={value}\n"
          key_found = True
          break

    if not key_found:
      lines.append(f"{key}={value}\n")

    with open(self.env_file, "w") as f:
      f.writelines(lines)

    self.env_vars[key] = value

  def _get_access_token(self) -> str | None:
    """Get Google Cloud access token."""
    if not self.creds.valid:
      self.creds.refresh(google_requests.Request())
    return self.creds.token

  def generate_oauth_uri(
      self,
      client_secret_file: Path,
      scopes: list[str],
      redirect_uri: str = DEFAULT_REDIRECT_URI,
      pkce: bool = False,
  ) -> tuple[str, str, str]:
    """Generate OAuth authorization URI template from a client secret file.

    Gemini Enterprise invokes this authorization URI dynamically when an end
    user signs in. Static per-request parameters (`state`, `code_challenge`,
    and `code_challenge_method`) are omitted from the stored URI template so
    Discovery Engine can attach fresh values per sign-in request (including S256
    PKCE challenges when `pkceVerificationEnabled` is enabled).

    Args:
        client_secret_file: Path to the OAuth client secret JSON file.
        scopes: List of OAuth scopes to request.
        redirect_uri: OAuth redirect URI handled by Gemini Enterprise.
        pkce: Whether PKCE verification will be enabled on the Discovery Engine
          authorization resource (`OAUTH_PKCE_ENABLED`).

    Returns:
        Tuple of (authorization_url, client_id, client_secret).
    """
    del pkce  # Handled dynamically by Discovery Engine via pkceVerificationEnabled
    if not client_secret_file.exists():
      typer.echo(
          f"Error: Client secret file not found: {client_secret_file}", err=True
      )
      raise typer.Exit(1)

    with open(client_secret_file) as f:
      client_config = json.load(f)

    if "web" in client_config:
      client_id = client_config["web"]["client_id"]
      client_secret = client_config["web"]["client_secret"]
    elif "installed" in client_config:
      client_id = client_config["installed"]["client_id"]
      client_secret = client_config["installed"]["client_secret"]
    else:
      typer.echo("Error: Invalid client secret file format", err=True)
      raise typer.Exit(1)

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        str(client_secret_file),
        scopes=scopes,
        autogenerate_code_verifier=False,
    )
    flow.redirect_uri = redirect_uri

    raw_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    parsed = urlsplit(raw_url)
    filtered_params = [
        (k, v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if k not in _DYNAMIC_OAUTH_QUERY_PARAMS
    ]
    clean_query = urlencode(filtered_params, quote_via=quote)
    authorization_url = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, clean_query, "")
    )

    return authorization_url, client_id, client_secret

  def create_authorization(
      self,
      auth_id: str,
      client_id: str,
      client_secret: str,
      auth_uri: str,
      token_uri: str = DEFAULT_OAUTH_EXCHANGE_URI,
      pkce_enabled: bool | None = None,
  ) -> bool:
    """Create an OAuth authorization resource in Discovery Engine.

    Args:
        auth_id: Unique identifier for the authorization resource.
        client_id: OAuth client ID.
        client_secret: OAuth client secret.
        auth_uri: OAuth authorization URI template.
        token_uri: OAuth token exchange URI.
        pkce_enabled: Optional explicit override for RFC 7636 PKCE verification.
          Defaults to `OAUTH_PKCE_ENABLED` from the environment (`False` if
          unset).

    Returns:
        True if successful, False otherwise.
    """
    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    if not project_number:
      typer.echo("Error: GCP_PROJECT_NUMBER not found in environment", err=True)
      return False

    access_token = self._get_access_token()
    if not access_token:
      typer.echo("Error: Failed to get access token", err=True)
      return False

    use_pkce = (
        _parse_bool_env(self.env_vars.get("OAUTH_PKCE_ENABLED"), default=False)
        if pkce_enabled is None
        else pkce_enabled
    )

    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        "locations/global/authorizations"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "X-Goog-User-Project": project_number,
    }

    server_side_oauth2: dict[str, Any] = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "authorizationUri": auth_uri,
        "tokenUri": token_uri,
        "pkceVerificationEnabled": use_pkce,
    }

    data = {
        "name": (
            f"projects/{project_number}/locations/global/"
            f"authorizations/{auth_id}"
        ),
        "serverSideOauth2": server_side_oauth2,
    }

    params = {"authorizationId": auth_id}

    try:
      response = requests.post(
          url, headers=headers, json=data, params=params, timeout=60
      )
      response.raise_for_status()

      typer.echo(f"Successfully created OAuth authorization: {auth_id}")

      self._update_env_var("OAUTH_AUTH_ID", auth_id)
      self._update_env_var("OAUTH_CLIENT_ID", client_id)
      self._update_env_var("OAUTH_CLIENT_SECRET", client_secret)
      self._update_env_var("OAUTH_AUTH_URI", auth_uri)
      self._update_env_var("OAUTH_TOKEN_URI", token_uri)
      self._update_env_var(
          "OAUTH_PKCE_ENABLED", "true" if use_pkce else "false"
      )

      return True

    except requests.exceptions.RequestException as e:
      typer.echo(f"Error creating OAuth authorization: {e}", err=True)
      if e.response is not None and e.response.text:
        typer.echo(f"Response: {e.response.text}", err=True)
      return False

  def delete_authorization(self, auth_id: str) -> bool:
    """Delete an OAuth authorization resource from Discovery Engine.

    Args:
        auth_id: Authorization ID to delete.

    Returns:
        True if successful, False otherwise.
    """
    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    if not project_number:
      typer.echo("Error: GCP_PROJECT_NUMBER not found in environment", err=True)
      return False

    access_token = self._get_access_token()
    if not access_token:
      typer.echo("Error: Failed to get access token", err=True)
      return False

    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/authorizations/{auth_id}"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Goog-User-Project": project_number,
    }

    try:
      response = requests.delete(url, headers=headers, timeout=60)
      response.raise_for_status()

      typer.echo(f"Successfully deleted OAuth authorization: {auth_id}")
      return True

    except requests.exceptions.RequestException as e:
      typer.echo(f"Error deleting OAuth authorization: {e}", err=True)
      if e.response is not None and e.response.text:
        typer.echo(f"Response: {e.response.text}", err=True)
      return False

  def get_authorization(self, auth_id: str) -> dict[str, Any] | None:
    """Get OAuth authorization details from Discovery Engine.

    Args:
        auth_id: Authorization ID to retrieve.

    Returns:
        Authorization details if found, None otherwise.
    """
    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    if not project_number:
      typer.echo("Error: GCP_PROJECT_NUMBER not found in environment", err=True)
      return None

    access_token = self._get_access_token()
    if not access_token:
      typer.echo("Error: Failed to get access token", err=True)
      return None

    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/authorizations/{auth_id}"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Goog-User-Project": project_number,
    }

    try:
      response = requests.get(url, headers=headers, timeout=60)
      response.raise_for_status()
      return response.json()

    except requests.exceptions.RequestException as e:
      typer.echo(f"Error retrieving OAuth authorization: {e}", err=True)
      if e.response is not None and e.response.text:
        typer.echo(f"Response: {e.response.text}", err=True)
      return None


@app.command()
def setup(
    client_secret_file: Annotated[
        Path, typer.Argument(help="Path to OAuth client secret JSON file")
    ],
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to environment file")
    ] = Path(".env"),
    scopes: Annotated[
        str | None,
        typer.Option("--scopes", "-s", help="Comma-separated OAuth scopes"),
    ] = None,
    pkce: Annotated[
        bool,
        typer.Option(
            "--pkce/--no-pkce",
            help=(
                "Enable or disable RFC 7636 PKCE verification in the "
                "Discovery Engine OAuth configuration."
            ),
        ),
    ] = False,
) -> None:
  """Configure local OAuth credentials from a Google Cloud client secret file.

  Generates the OAuth authorization URI template and writes OAuth settings
  (including OAUTH_PKCE_ENABLED) to the environment file for registration in
  Discovery Engine. Gemini Enterprise invokes the authorization URI dynamically
  when end users sign in.
  """
  manager = OAuthManager(env_file)

  if not scopes:
    scopes_list = list(DEFAULT_OAUTH_SCOPES)
  else:
    scopes_list = [s.strip() for s in scopes.split(",") if s.strip()]

  typer.echo("Generating OAuth authorization configuration...")

  try:
    auth_uri, client_id, client_secret = manager.generate_oauth_uri(
        client_secret_file, scopes_list, pkce=pkce
    )

    manager._update_env_var("OAUTH_CLIENT_ID", client_id)
    manager._update_env_var("OAUTH_CLIENT_SECRET", client_secret)
    manager._update_env_var("OAUTH_AUTH_URI", auth_uri)
    manager._update_env_var("OAUTH_TOKEN_URI", DEFAULT_OAUTH_EXCHANGE_URI)
    manager._update_env_var("OAUTH_PKCE_ENABLED", "true" if pkce else "false")

    typer.echo("\nOAuth configuration saved to environment file.")
    typer.echo(f"PKCE verification enabled: {'true' if pkce else 'false'}")
    typer.echo(f"\nConfigured OAuth Authorization URI:\n{auth_uri}")
    typer.echo(
        "\nGemini Enterprise invokes this authorization URI automatically "
        "during end-user sign-in."
    )
    typer.echo(
        "Next step: run 'just oauth-create-auth' (or 'uv run "
        "oauth-flow-gemini-enterprise-secops-mcp oauth create-auth') to "
        "register the authorization in Discovery Engine."
    )

  except typer.Exit:
    raise
  except Exception as e:
    typer.echo(f"Error setting up OAuth: {e}", err=True)
    raise typer.Exit(1)


@app.command()
def create_auth(
    auth_id: Annotated[
        str | None, typer.Option("--auth-id", "-i", help="Authorization ID")
    ] = None,
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to environment file")
    ] = Path(".env"),
    pkce: Annotated[
        bool | None,
        typer.Option(
            "--pkce/--no-pkce",
            help=(
                "Override OAUTH_PKCE_ENABLED when registering the "
                "Discovery Engine authorization resource."
            ),
        ),
    ] = None,
) -> None:
  """Register the OAuth authorization resource in Discovery Engine."""
  manager = OAuthManager(env_file)

  if not auth_id:
    auth_id = manager.env_vars.get("OAUTH_AUTH_ID")
    if not auth_id:
      import uuid

      auth_id = f"auth-{uuid.uuid4().hex[:8]}"
      typer.echo(f"Generated authorization ID: {auth_id}")

  client_id = manager.env_vars.get("OAUTH_CLIENT_ID")
  client_secret = manager.env_vars.get("OAUTH_CLIENT_SECRET")
  auth_uri = manager.env_vars.get("OAUTH_AUTH_URI")
  token_uri = manager.env_vars.get(
      "OAUTH_TOKEN_URI", DEFAULT_OAUTH_EXCHANGE_URI
  )

  if not client_id or not client_secret or not auth_uri:
    typer.echo(
        "Error: OAuth credentials not found in environment. "
        "Run 'just run oauth setup <client_secret.json>' first.",
        err=True,
    )
    raise typer.Exit(1)

  if manager.create_authorization(
      auth_id,
      client_id,
      client_secret,
      auth_uri,
      token_uri,
      pkce_enabled=pkce,
  ):
    typer.echo(
        f"\nAuthorization ID '{auth_id}' has been saved to environment file."
    )
    typer.echo(
        "You can now register your agent with Gemini Enterprise using this "
        "authorization."
    )
  else:
    raise typer.Exit(1)


@app.command()
def verify(
    auth_id: Annotated[
        str | None, typer.Option("--auth-id", "-i", help="Authorization ID")
    ] = None,
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to environment file")
    ] = Path(".env"),
) -> None:
  """Verify OAuth authorization status in Discovery Engine."""
  manager = OAuthManager(env_file)

  if not auth_id:
    auth_id = manager.env_vars.get("OAUTH_AUTH_ID")
    if not auth_id:
      typer.echo(
          "Error: No authorization ID provided or found in environment",
          err=True,
      )
      raise typer.Exit(1)

  auth_details = manager.get_authorization(auth_id)

  if auth_details:
    typer.echo(f"\nOAuth Authorization '{auth_id}' exists:")
    typer.echo(json.dumps(auth_details, indent=2))
  else:
    typer.echo(f"OAuth Authorization '{auth_id}' not found", err=True)
    raise typer.Exit(1)


@app.command()
def delete(
    auth_id: Annotated[
        str | None, typer.Option("--auth-id", "-i", help="Authorization ID")
    ] = None,
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to environment file")
    ] = Path(".env"),
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation prompt")
    ] = False,
) -> None:
  """Delete an OAuth authorization resource from Discovery Engine."""
  manager = OAuthManager(env_file)

  if not auth_id:
    auth_id = manager.env_vars.get("OAUTH_AUTH_ID")
    if not auth_id:
      typer.echo(
          "Error: No authorization ID provided or found in environment",
          err=True,
      )
      raise typer.Exit(1)

  if not force:
    confirm = typer.confirm(
        f"Are you sure you want to delete authorization '{auth_id}'?"
    )
    if not confirm:
      typer.echo("Deletion cancelled.")
      raise typer.Exit(0)

  if manager.delete_authorization(auth_id):
    typer.echo("Authorization deleted successfully.")
  else:
    raise typer.Exit(1)


if __name__ == "__main__":
  app()
