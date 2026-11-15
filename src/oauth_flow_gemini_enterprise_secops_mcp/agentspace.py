#!/usr/bin/env python3
"""Gemini Enterprise Manager for Google Security Operations (SecOps) MCP Agent.

Manages Gemini Enterprise (Discovery Engine) operations including app creation,
agent registration, updates, verification, OAuth linking, and deletion.
"""

import json
import os
import time
from pathlib import Path
from typing import Annotated
from typing import Any

import google.auth
import requests
import typer
from dotenv import load_dotenv
from google.auth.transport import requests as google_requests

from oauth_flow_gemini_enterprise_secops_mcp.env_validation import (
    format_validation_errors,
)
from oauth_flow_gemini_enterprise_secops_mcp.env_validation import (
    is_placeholder_value,
)
from oauth_flow_gemini_enterprise_secops_mcp.env_validation import (
    resolve_gemini_enterprise_app_id,
)
from oauth_flow_gemini_enterprise_secops_mcp.env_validation import (
    validate_env_vars,
)

app = typer.Typer(
    add_completion=False,
    help=(
        "Manage Gemini Enterprise operations for the Google Security"
        " Operations (SecOps) MCP Agent."
    ),
)

DISCOVERY_ENGINE_API_BASE = "https://discoveryengine.googleapis.com/v1alpha"
DEFAULT_HTTP_TIMEOUT = 600


class AgentSpaceManager:
  """Manages Gemini Enterprise configuration and Discovery Engine operations."""

  def __init__(self, env_file: Path):
    """Initialize the Gemini Enterprise manager.

    Args:
        env_file: Path to the environment file.
    """
    self.env_file = env_file
    self.env_vars = self._load_env_vars()

    local_adc = (
        self.env_file.resolve().parent
        / ".gcloud"
        / "application_default_credentials.json"
    )
    if (
        not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        and local_adc.exists()
    ):
      os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(local_adc)

    self.creds, self.project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    if not self.project:
      self.project = self.env_vars.get("GOOGLE_CLOUD_PROJECT")
      if not self.project:
        creds_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if creds_path and Path(creds_path).exists():
          with open(creds_path, encoding="utf-8") as f:
            creds_info = json.load(f)
            self.project = creds_info.get("project_id") or creds_info.get(
                "quota_project_id"
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

    with open(self.env_file, encoding="utf-8") as f:
      lines = f.readlines()

    formatted_line = f'{key}="{value}"\n'
    key_found = False
    for i, line in enumerate(lines):
      if line.strip() and not line.strip().startswith("#") and "=" in line:
        existing_key = line.split("=", 1)[0].strip()
        if existing_key == key:
          lines[i] = formatted_line
          key_found = True
          break

    if not key_found:
      lines.append(formatted_line)

    with open(self.env_file, "w", encoding="utf-8") as f:
      f.writelines(lines)

    self.env_vars[key] = value

  def _get_app_id(self) -> str | None:
    """Resolve Gemini Enterprise app ID from GEMINI_ENTERPRISE_APP_ID or AGENTSPACE_APP_ID."""
    return resolve_gemini_enterprise_app_id(self.env_vars)

  def _get_agent_id(self) -> str | None:
    """Resolve registered agent ID from environment variables."""
    for key in ("GEMINI_ENTERPRISE_AGENT_ID", "AGENTSPACE_AGENT_ID"):
      val = self.env_vars.get(key, "")
      if val and not is_placeholder_value(key, val)[0]:
        return val
    return None

  def _get_collection(self) -> str:
    """Resolve Discovery Engine collection name."""
    collection = self.env_vars.get(
        "GEMINI_ENTERPRISE_COLLECTION", ""
    ) or self.env_vars.get("AGENTSPACE_COLLECTION", "")
    return collection or "default_collection"

  def _get_assistant(self) -> str:
    """Resolve Discovery Engine assistant name."""
    assistant = self.env_vars.get(
        "GEMINI_ENTERPRISE_ASSISTANT", ""
    ) or self.env_vars.get("AGENTSPACE_ASSISTANT", "")
    return assistant or "default_assistant"

  def _get_access_token(self) -> str | None:
    """Get Google Cloud access token."""
    if not self.creds.valid:
      self.creds.refresh(google_requests.Request())
    return self.creds.token

  def _validate_environment(self) -> tuple[bool, list]:
    """Validate required environment variables for Gemini Enterprise operations.

    Returns:
        Tuple of (is_valid, errors) where errors is a list of ValidationError.
    """
    required_vars = [
        "GCP_PROJECT_ID",
        "GCP_PROJECT_NUMBER",
        "GEMINI_ENTERPRISE_APP_ID",
        "AGENT_ENGINE_RESOURCE_NAME",
        "GCP_LOCATION",
    ]
    return validate_env_vars(required_vars, self.env_vars)

  def _make_request(
      self, method: str, url: str, **kwargs: Any
  ) -> requests.Response | None:
    """Make an authenticated request to the Discovery Engine API."""
    access_token = self._get_access_token()
    if not access_token:
      return None

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "X-Goog-User-Project": self.env_vars["GCP_PROJECT_NUMBER"],
    }
    headers.update(kwargs.pop("headers", {}))

    if "timeout" not in kwargs:
      kwargs["timeout"] = DEFAULT_HTTP_TIMEOUT

    debug = self.env_vars.get("DEBUG", "").lower() in ["true", "1", "yes"]
    if debug:
      typer.echo(f"[INFO] DEBUG: {method} {url}")
      if "json" in kwargs:
        typer.echo(
            f"[INFO] DEBUG: Request body: {json.dumps(kwargs['json'], indent=2)}"
        )
      typer.echo(f"[INFO] DEBUG: Timeout: {kwargs['timeout']}s")

    try:
      typer.echo(f"  Sending {method} request to API...")
      response = requests.request(method, url, headers=headers, **kwargs)
      if debug:
        typer.echo(f"[INFO] DEBUG: Response status: {response.status_code}")
        typer.echo(f"[INFO] DEBUG: Response body: {response.text[:500]}")
      response.raise_for_status()
      typer.echo(f"  API response received (status {response.status_code})")
      return response
    except requests.exceptions.Timeout:
      typer.secho(
          f"[ERROR] API request timed out after {kwargs['timeout']}s",
          fg=typer.colors.RED,
      )
      typer.secho(
          "  [INFO] CHAT apps may take longer to create (requires Dialogflow"
          " setup)",
          fg=typer.colors.YELLOW,
      )
      return None
    except requests.exceptions.RequestException as e:
      typer.secho(f"[ERROR] API request failed: {e}", fg=typer.colors.RED)
      if e.response is not None:
        typer.echo(f"  Response: {e.response.text}")
      return None

  def _get_agent_api_url(self, agent_id: str | None = None) -> str:
    """Construct the API URL for Gemini Enterprise agents."""
    project_number = self.env_vars["GCP_PROJECT_NUMBER"]
    app_id = self._get_app_id() or self.env_vars.get("AGENTSPACE_APP_ID", "")
    collection = self._get_collection()
    assistant = self._get_assistant()

    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/engines/{app_id}/"
        f"assistants/{assistant}/agents"
    )
    if agent_id:
      url += f"/{agent_id}"
    return url

  def _build_agent_config(self) -> dict[str, Any]:
    """Build the agent configuration payload."""
    config: dict[str, Any] = {
        "displayName": self.env_vars.get(
            "AGENT_DISPLAY_NAME", "Google SecOps Security Agent"
        ),
        "description": self.env_vars.get(
            "AGENT_DESCRIPTION",
            (
                "Security Operations agent with access to Google Security"
                " Operations (SecOps) SIEM, SOAR, and Google Threat"
                " Intelligence"
            ),
        ),
        "adk_agent_definition": {
            "tool_settings": {
                "tool_description": self.env_vars.get(
                    "AGENT_TOOL_DESCRIPTION",
                    (
                        "Tools from Google Security Operations (SecOps) SIEM,"
                        " SOAR, and Security Command Center"
                    ),
                )
            },
            "provisioned_reasoning_engine": {
                "reasoning_engine": self.env_vars["AGENT_ENGINE_RESOURCE_NAME"]
            },
        },
    }

    if oauth_auth_id := self.env_vars.get("OAUTH_AUTH_ID"):
      project_number = self.env_vars["GCP_PROJECT_NUMBER"]
      auth_resource = (
          f"projects/{project_number}/locations/global/"
          f"authorizations/{oauth_auth_id}"
      )
      config["authorization_config"] = {"tool_authorizations": [auth_resource]}
    else:
      config["authorization_config"] = {"tool_authorizations": []}

    return config

  def register_agent(
      self,
      force: bool = False,
      agent_engine_id: str | None = None,
      app_id: str | None = None,
  ) -> bool:
    """Register agent with Gemini Enterprise."""
    if agent_engine_id:
      self.env_vars["AGENT_ENGINE_RESOURCE_NAME"] = agent_engine_id
    if app_id:
      self.env_vars["GEMINI_ENTERPRISE_APP_ID"] = app_id
      self.env_vars["AGENTSPACE_APP_ID"] = app_id

    typer.echo("[INFO] Registering agent with Gemini Enterprise...")
    is_valid, errors = self._validate_environment()
    if not is_valid:
      typer.secho("[ERROR] Configuration Error", fg=typer.colors.RED, bold=True)
      typer.echo()
      typer.echo(format_validation_errors(errors))
      return False

    existing_agent_id = self._get_agent_id()
    if existing_agent_id and not force:
      typer.secho(
          "[WARNING] Agent already registered. Use --force to re-register.",
          fg=typer.colors.YELLOW,
      )
      return False

    api_url = self._get_agent_api_url()
    agent_config = self._build_agent_config()

    access_token = self._get_access_token()
    if not access_token:
      return False

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "X-Goog-User-Project": self.env_vars["GCP_PROJECT_NUMBER"],
    }

    try:
      response = requests.post(
          api_url,
          headers=headers,
          json=agent_config,
          timeout=DEFAULT_HTTP_TIMEOUT,
      )
      response.raise_for_status()
    except requests.exceptions.RequestException as e:
      if (
          e.response is not None
          and e.response.status_code == 400
          and "FAILED_PRECONDITION" in e.response.text
          and existing_agent_id
      ):
        typer.echo(
            "[INFO] Service account cannot create a new agent without a seat"
            f" license; updating existing agent {existing_agent_id}..."
        )
        return self.update_agent()
      typer.secho(f"[ERROR] API request failed: {e}", fg=typer.colors.RED)
      if e.response is not None:
        typer.echo(f"  Response: {e.response.text}")
      return False

    if response and response.status_code == 200:
      result = response.json()
      agent_name = result.get("name", "")
      agent_id = agent_name.split("/")[-1] if agent_name else ""
      typer.secho("[OK] Agent registered successfully!", fg=typer.colors.GREEN)
      typer.echo(f"  Agent Name: {agent_name}")
      typer.echo(f"  Agent ID: {agent_id}")
      if agent_id:
        self._update_env_var("AGENTSPACE_AGENT_ID", agent_id)
      return True
    return False

  def update_agent(self) -> bool:
    """Update existing Gemini Enterprise agent configuration."""
    typer.echo("[INFO] Updating Gemini Enterprise agent...")
    agent_id = self._get_agent_id()
    if not agent_id:
      typer.secho(
          "[ERROR] No agent registered yet. Run"
          " 'just gemini-enterprise-register' or 'uv run"
          " oauth-flow-gemini-enterprise-secops-mcp gemini-enterprise"
          " register' first.",
          fg=typer.colors.RED,
      )
      return False

    api_url = self._get_agent_api_url(agent_id)
    agent_config = self._build_agent_config()

    response = self._make_request("PATCH", api_url, json=agent_config)
    if response and response.status_code == 200:
      typer.secho("[OK] Agent updated successfully!", fg=typer.colors.GREEN)
      return True
    return False

  def verify_agent(self) -> bool:
    """Verify Gemini Enterprise agent configuration and status."""
    typer.echo("[INFO] Verifying Gemini Enterprise configuration...")
    is_valid, errors = self._validate_environment()
    if not is_valid:
      typer.secho("[ERROR] Configuration Error", fg=typer.colors.RED, bold=True)
      typer.echo()
      typer.echo(format_validation_errors(errors))
      return False

    agent_id = self._get_agent_id()
    if not agent_id:
      typer.secho("[WARNING] No agent registered yet.", fg=typer.colors.YELLOW)
      return False

    api_url = self._get_agent_api_url(agent_id)
    response = self._make_request("GET", api_url)
    if response and response.status_code == 200:
      typer.secho(
          "[OK] Gemini Enterprise agent verified successfully!",
          fg=typer.colors.GREEN,
      )
      return True
    return False

  def delete_agent(
      self, force: bool = False, agent_id: str | None = None
  ) -> bool:
    """Delete agent from Gemini Enterprise."""
    if not agent_id:
      agent_id = self._get_agent_id()

    if not agent_id:
      typer.secho(
          "[WARNING] No agent registered to delete.", fg=typer.colors.YELLOW
      )
      return True

    if not force and not typer.confirm(
        f"Are you sure you want to delete agent {agent_id}?"
    ):
      typer.echo("[INFO] Cancelled.")
      return False

    api_url = self._get_agent_api_url(agent_id)
    response = self._make_request("DELETE", api_url)
    if response and response.status_code in [200, 204]:
      typer.secho("[OK] Agent deleted successfully!", fg=typer.colors.GREEN)
      if agent_id == self.env_vars.get("AGENTSPACE_AGENT_ID"):
        self._update_env_var("AGENTSPACE_AGENT_ID", "")
      return True
    return False

  def create_app(
      self,
      app_name: str | None = None,
      solution_type: str = "SOLUTION_TYPE_SEARCH",
      data_store_ids: list[str] | None = None,
      enable_chat: bool = False,
      skip_datastore: bool = False,
      app_type: str | None = None,
      industry_vertical: str | None = None,
  ) -> bool:
    """Create a new Gemini Enterprise app (engine) in Discovery Engine.

    For apps to appear in the Gemini Enterprise web UI, pass
    app_type="APP_TYPE_INTRANET" and industry_vertical="GENERIC".

    Official documentation:
    https://cloud.google.com/gemini/enterprise/docs/create-app

    Args:
        app_name: Display name for the app (used to generate app_id).
        solution_type: Solution type (SOLUTION_TYPE_SEARCH, SOLUTION_TYPE_CHAT).
        data_store_ids: Optional list of data store IDs to associate.
        enable_chat: Whether to enable chat engine config.
        skip_datastore: Explicitly skip adding data stores.
        app_type: App type (e.g., APP_TYPE_INTRANET).
        industry_vertical: Industry vertical (e.g., GENERIC).

    Returns:
        True if successful, False otherwise.
    """
    typer.echo("[INFO] Creating new Gemini Enterprise app...")

    required_vars = ["GCP_PROJECT_NUMBER", "GCP_PROJECT_ID"]
    missing = [var for var in required_vars if not self.env_vars.get(var)]
    if missing:
      typer.secho(
          f"[ERROR] Missing required variables: {', '.join(missing)}",
          fg=typer.colors.RED,
      )
      return False

    if not app_type:
      typer.secho(
          "[WARNING] app_type not specified. Apps may not appear in the Gemini"
          " Enterprise web UI!",
          fg=typer.colors.YELLOW,
          bold=True,
      )
      typer.secho(
          "  RECOMMENDED: Use --app-type APP_TYPE_INTRANET --industry-vertical"
          " GENERIC",
          fg=typer.colors.YELLOW,
      )
      typer.secho(
          "  See: https://cloud.google.com/gemini/enterprise/docs/create-app",
          fg=typer.colors.CYAN,
      )
      typer.echo()

    if not app_name:
      app_name = "secops-mcp-app"
    app_id = f"{app_name.lower().replace(' ', '-')}_{int(time.time())}"

    project_number = self.env_vars["GCP_PROJECT_NUMBER"]
    collection = self._get_collection()

    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/engines"
    )

    app_config: dict[str, Any] = {
        "displayName": app_name,
        "solutionType": solution_type,
    }

    if app_type:
      app_config["appType"] = app_type
      typer.echo(f"  App Type: {app_type}")

    if industry_vertical:
      app_config["industryVertical"] = industry_vertical
      typer.echo(f"  Industry Vertical: {industry_vertical}")

    if skip_datastore:
      typer.echo("  Skipping data stores (for web UI compatibility)")
      if solution_type == "SOLUTION_TYPE_CHAT":
        typer.secho(
            "  [WARNING] SOLUTION_TYPE_CHAT typically requires data stores,"
            " creating without them for web UI compatibility",
            fg=typer.colors.YELLOW,
        )
    elif data_store_ids:
      app_config["dataStoreIds"] = data_store_ids
      typer.echo(f"  Including data stores: {data_store_ids}")
    elif solution_type == "SOLUTION_TYPE_CHAT":
      typer.secho(
          "  [WARNING] SOLUTION_TYPE_CHAT typically requires at least one data"
          " store",
          fg=typer.colors.YELLOW,
      )

    if enable_chat and solution_type == "SOLUTION_TYPE_CHAT":
      app_config["chatEngineConfig"] = {
          "agentCreationConfig": {
              "business": self.env_vars.get(
                  "AGENT_BUSINESS", "Security Operations"
              ),
              "defaultLanguageCode": self.env_vars.get("AGENT_LANGUAGE", "en"),
              "timeZone": self.env_vars.get(
                  "AGENT_TIMEZONE", "America/New_York"
              ),
          }
      }

    typer.echo(f"  Creating app with ID: {app_id}")
    typer.echo(f"  Solution type: {solution_type}")
    if "dataStoreIds" in app_config:
      typer.echo(f"  Data stores: {app_config['dataStoreIds']}")
    else:
      typer.echo(
          "  Data stores: None (app will be created without data stores)"
      )

    typer.echo("  Config being sent:")
    typer.echo(json.dumps(app_config, indent=2))

    response = self._make_request(
        "POST", url, json=app_config, params={"engineId": app_id}
    )

    if response and response.status_code in [200, 201]:
      typer.secho("[OK] App created successfully!", fg=typer.colors.GREEN)
      typer.echo(f"  App ID: {app_id}")
      typer.echo(f"  Display Name: {app_name}")

      self._update_env_var("GEMINI_ENTERPRISE_APP_ID", app_id)
      self._update_env_var("AGENTSPACE_APP_ID", app_id)

      typer.echo("\n" + "=" * 80)
      typer.echo("[INFO] Saved Gemini Enterprise App ID to .env:")
      typer.echo(f'GEMINI_ENTERPRISE_APP_ID="{app_id}"')
      typer.echo("=" * 80)
      return True

    typer.secho("[ERROR] Failed to create app", fg=typer.colors.RED)
    if response and hasattr(response, "text"):
      typer.echo(f"  Response: {response.text}")
    return False

  def delete_app(self, app_id: str, force: bool = False) -> bool:
    """Delete a Gemini Enterprise app (engine) from Discovery Engine.

    Args:
        app_id: The app ID to delete.
        force: Skip confirmation prompt.

    Returns:
        True if successful, False otherwise.
    """
    if not force and not typer.confirm(
        f"Are you sure you want to delete app '{app_id}'?"
    ):
      typer.echo("[INFO] Cancelled.")
      return False

    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    if not project_number:
      typer.secho(
          "[ERROR] Missing GCP_PROJECT_NUMBER in .env", fg=typer.colors.RED
      )
      return False

    collection = self._get_collection()
    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/engines/{app_id}"
    )

    typer.echo(f"[INFO] Deleting app: {app_id}")
    response = self._make_request("DELETE", url)

    if response and response.status_code in [200, 204]:
      typer.secho("[OK] App deleted successfully!", fg=typer.colors.GREEN)
      if self.env_vars.get("GEMINI_ENTERPRISE_APP_ID") == app_id:
        self._update_env_var("GEMINI_ENTERPRISE_APP_ID", "")
      if self.env_vars.get("AGENTSPACE_APP_ID") == app_id:
        self._update_env_var("AGENTSPACE_APP_ID", "")
      return True

    typer.secho("[ERROR] Failed to delete app", fg=typer.colors.RED)
    if response and hasattr(response, "text"):
      typer.echo(f"  Response: {response.text}")
    return False

  def display_url(self) -> None:
    """Display the Gemini Enterprise Cloud Console URL."""
    project_id = self.env_vars.get("GCP_PROJECT_ID")
    app_id = self._get_app_id()
    if (
        not project_id
        or is_placeholder_value("GCP_PROJECT_ID", project_id)[0]
        or not app_id
    ):
      typer.secho(
          "[ERROR] Cannot generate URL - missing GCP_PROJECT_ID or"
          " GEMINI_ENTERPRISE_APP_ID configuration.",
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

  def _ensure_data_store_exists(self) -> bool:
    """Ensure the Gemini Enterprise engine has at least one data store."""
    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    app_id = self._get_app_id()
    if not project_number or not app_id:
      typer.secho(
          "[ERROR] Missing GCP_PROJECT_NUMBER or GEMINI_ENTERPRISE_APP_ID",
          fg=typer.colors.RED,
      )
      return False

    collection = self._get_collection()
    engine_url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/engines/{app_id}"
    )

    response = self._make_request("GET", engine_url)
    if not response:
      typer.secho("[ERROR] Failed to get engine details", fg=typer.colors.RED)
      return False

    engine_data = response.json()
    data_store_ids = engine_data.get("dataStoreIds", [])

    typer.echo(f"  Engine info: {engine_data.get('name', 'unknown')}")
    typer.echo(f"  Display name: {engine_data.get('displayName', 'N/A')}")
    typer.echo(f"  Data stores: {data_store_ids}")

    if data_store_ids:
      typer.echo(
          f"  Engine has {len(data_store_ids)} data store(s) configured:"
          f" {', '.join(data_store_ids)}"
      )

      for ds_id in data_store_ids:
        ds_url = (
            f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
            f"locations/global/collections/{collection}/dataStores/{ds_id}"
        )
        ds_response = self._make_request("GET", ds_url)
        if ds_response:
          ds_data = ds_response.json()
          typer.echo(f"    - {ds_id}: {ds_data.get('displayName', 'exists')}")
        else:
          typer.echo(f"    - {ds_id}: NOT FOUND")

      typer.secho(
          "  [OK] Using existing data store(s) for search",
          fg=typer.colors.GREEN,
      )
      return True

    typer.secho(
        "[WARNING] No data stores found. Creating unstructured data store...",
        fg=typer.colors.YELLOW,
    )
    return self._create_website_datastore()

  def _create_website_datastore(self) -> bool:
    """Create an unstructured data store for search."""
    project_number = self.env_vars["GCP_PROJECT_NUMBER"]
    app_id = self._get_app_id()
    if not app_id:
      return False
    collection = self._get_collection()

    data_store_id = f"{app_id}_unstructured_datastore"
    data_store_url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/dataStores"
    )

    data_store_config = {
        "displayName": "Unstructured Data Store for SecOps Agent",
        "industryVertical": "GENERIC",
        "solutionTypes": ["SOLUTION_TYPE_SEARCH"],
        "contentConfig": "CONTENT_REQUIRED",
    }

    create_response = self._make_request(
        "POST",
        data_store_url,
        json=data_store_config,
        params={"dataStoreId": data_store_id},
    )

    if not create_response:
      typer.echo(
          "  [INFO] Data store may already exist, attempting to link:"
          f" {data_store_id}"
      )
    else:
      typer.echo(f"  [OK] Created data store: {data_store_id}")

    typer.echo("  [INFO] Linking data store to engine...")
    engine_url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/engines/{app_id}"
    )

    engine_response = self._make_request("GET", engine_url)
    existing_ids = []
    if engine_response:
      engine_data = engine_response.json()
      existing_ids = engine_data.get("dataStoreIds", [])

    all_data_stores = list(set(existing_ids + [data_store_id]))
    update_config = {"dataStoreIds": all_data_stores}

    patch_response = self._make_request(
        "PATCH",
        engine_url,
        json=update_config,
        params={"updateMask": "dataStoreIds"},
    )
    if patch_response:
      typer.secho(
          "[OK] Unstructured data store created and linked successfully!",
          fg=typer.colors.GREEN,
      )
      return True

    typer.secho(
        "[ERROR] Failed to link data store to engine", fg=typer.colors.RED
    )
    return False

  def link_agent_to_agentspace(
      self,
      display_name: str | None = None,
      description: str | None = None,
      tool_description: str | None = None,
      auth_id: str | None = None,
  ) -> bool:
    """Link an existing Agent Engine to Gemini Enterprise with OAuth authorization.

    Args:
        display_name: Display name for the agent in Gemini Enterprise.
        description: Description of the agent.
        tool_description: Description of what the agent tool does.
        auth_id: OAuth authorization ID.

    Returns:
        True if successful, False otherwise.
    """
    valid, errors = self._validate_environment()
    if not valid:
      typer.secho("[ERROR] Configuration Error", fg=typer.colors.RED, bold=True)
      typer.echo()
      typer.echo(format_validation_errors(errors))
      return False

    if not display_name:
      display_name = self.env_vars.get(
          "AGENT_DISPLAY_NAME", "Google SecOps MCP Agent"
      )
    if not description:
      description = self.env_vars.get(
          "AGENT_DESCRIPTION",
          (
              "Security operations agent with Google Security Operations"
              " (SecOps) MCP tools integration"
          ),
      )
    if not tool_description:
      tool_description = self.env_vars.get(
          "AGENT_TOOL_DESCRIPTION",
          "Google Security Operations (SecOps) agent for threat analysis and"
          " incident response",
      )
    if not auth_id:
      auth_id = self.env_vars.get("OAUTH_AUTH_ID")

    project_number = self.env_vars["GCP_PROJECT_NUMBER"]
    app_id = self._get_app_id()
    if not app_id:
      typer.echo("[ERROR] GEMINI_ENTERPRISE_APP_ID not configured", err=True)
      return False
    reasoning_engine = self.env_vars["AGENT_ENGINE_RESOURCE_NAME"]
    collection = self._get_collection()
    assistant = self._get_assistant()

    access_token = self._get_access_token()
    if not access_token:
      typer.echo("[ERROR] Failed to get access token", err=True)
      return False

    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/locations/"
        f"global/collections/{collection}/engines/{app_id}/assistants/"
        f"{assistant}/agents"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "X-Goog-User-Project": project_number,
    }

    data: dict[str, Any] = {
        "displayName": display_name,
        "description": description,
        "adk_agent_definition": {
            "tool_settings": {"tool_description": tool_description},
            "provisioned_reasoning_engine": {
                "reasoning_engine": reasoning_engine
            },
        },
    }

    if auth_id:
      data["authorization_config"] = {
          "tool_authorizations": [
              f"projects/{project_number}/locations/global/"
              f"authorizations/{auth_id}"
          ]
      }
    else:
      data["authorization_config"] = {"tool_authorizations": []}

    existing_agent_id = self._get_agent_id()
    try:
      response = requests.post(
          url, headers=headers, json=data, timeout=DEFAULT_HTTP_TIMEOUT
      )
      response.raise_for_status()

      result = response.json()
      agent_name = result.get("name", "")

      typer.echo("[OK] Successfully linked agent to Gemini Enterprise!")
      typer.echo(f"Agent name: {agent_name}")

      if "/" in agent_name:
        agent_id = agent_name.split("/")[-1]
        self._update_env_var("AGENTSPACE_AGENT_ID", agent_id)
        typer.echo(f"[INFO] Agent ID saved to environment: {agent_id}")

      return True

    except requests.exceptions.RequestException as e:
      if (
          e.response is not None
          and e.response.status_code == 400
          and "FAILED_PRECONDITION" in e.response.text
          and existing_agent_id
      ):
        typer.echo(
            "[INFO] Service account cannot create a new agent without a seat"
            f" license; updating existing agent {existing_agent_id}..."
        )
        return self.update_agent_config(
            agent_id=existing_agent_id,
            display_name=display_name,
            description=description,
            tool_description=tool_description,
            reasoning_engine=reasoning_engine,
            auth_id=auth_id,
        )
      typer.echo(
          f"[ERROR] Error linking agent to Gemini Enterprise: {e}", err=True
      )
      if e.response is not None and hasattr(e.response, "text"):
        typer.echo(f"Response: {e.response.text}", err=True)
      return False

  def unlink_agent_from_agentspace(
      self,
      agent_id: str | None = None,
      force: bool = False,
  ) -> bool:
    """Unlink (remove) an agent from Gemini Enterprise while keeping the app intact.

    Args:
        agent_id: ID of the agent to unlink (defaults to AGENTSPACE_AGENT_ID).
        force: Skip confirmation prompt if True.

    Returns:
        True if successful, False otherwise.
    """
    if not agent_id:
      agent_id = self._get_agent_id()

    if not agent_id:
      typer.secho("[ERROR] No agent ID found to unlink.", fg=typer.colors.RED)
      return False

    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    app_id = self._get_app_id()
    missing = []
    if not project_number:
      missing.append("GCP_PROJECT_NUMBER")
    if not app_id:
      missing.append("GEMINI_ENTERPRISE_APP_ID")
    if missing:
      typer.secho(
          f"[ERROR] Missing required variables: {', '.join(missing)}",
          fg=typer.colors.RED,
      )
      return False

    if not force and not typer.confirm(
        f"Are you sure you want to unlink agent {agent_id} from Gemini"
        " Enterprise?"
    ):
      typer.echo("[INFO] Cancelled.")
      return False

    collection = self._get_collection()
    assistant = self._get_assistant()

    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/engines/{app_id}/"
        f"assistants/{assistant}/agents/{agent_id}"
    )

    access_token = self._get_access_token()
    if not access_token:
      typer.echo("[ERROR] Failed to get access token", err=True)
      return False

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Goog-User-Project": project_number,
    }

    try:
      response = requests.delete(
          url, headers=headers, timeout=DEFAULT_HTTP_TIMEOUT
      )
      response.raise_for_status()

      typer.secho(
          "[OK] Agent unlinked successfully from Gemini Enterprise!",
          fg=typer.colors.GREEN,
      )
      typer.echo(f"  Agent ID {agent_id} removed from app {app_id}")
      typer.echo("  [INFO] The Gemini Enterprise app remains intact")

      if agent_id == self.env_vars.get("AGENTSPACE_AGENT_ID"):
        self._update_env_var("AGENTSPACE_AGENT_ID", "")
        typer.echo("  Cleared AGENTSPACE_AGENT_ID from environment")

      return True

    except requests.exceptions.RequestException as e:
      typer.echo(
          f"[ERROR] Error unlinking agent from Gemini Enterprise: {e}",
          err=True,
      )
      if e.response is not None and hasattr(e.response, "text"):
        typer.echo(f"Response: {e.response.text}", err=True)
      return False

  def update_agent_config(
      self,
      agent_id: str | None = None,
      display_name: str | None = None,
      description: str | None = None,
      tool_description: str | None = None,
      reasoning_engine: str | None = None,
      auth_id: str | None = None,
  ) -> bool:
    """Update an existing agent's configuration in Gemini Enterprise.

    Args:
        agent_id: ID of the agent to update.
        display_name: New display name for the agent.
        description: New description of the agent.
        tool_description: New description of what the agent tool does.
        reasoning_engine: Reasoning engine resource name to link.
        auth_id: OAuth authorization ID to link.

    Returns:
        True if successful, False otherwise.
    """
    if not agent_id:
      agent_id = self._get_agent_id()
      if not agent_id:
        typer.echo(
            "[ERROR] No agent ID provided or found in environment", err=True
        )
        return False

    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    if not project_number:
      typer.echo(
          "[ERROR] GCP_PROJECT_NUMBER not found in environment", err=True
      )
      return False

    app_id = self._get_app_id()
    if not app_id:
      typer.echo(
          "[ERROR] GEMINI_ENTERPRISE_APP_ID (or AGENTSPACE_APP_ID) not found"
          " in environment",
          err=True,
      )
      return False

    access_token = self._get_access_token()
    if not access_token:
      typer.echo("[ERROR] Failed to get access token", err=True)
      return False

    collection = self._get_collection()
    assistant = self._get_assistant()
    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/locations/"
        f"global/collections/{collection}/engines/{app_id}/assistants/"
        f"{assistant}/agents/{agent_id}"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "X-Goog-User-Project": project_number,
    }

    update_mask = []
    data: dict[str, Any] = {}

    if display_name:
      data["displayName"] = display_name
      update_mask.append("displayName")

    if description:
      data["description"] = description
      update_mask.append("description")

    if not reasoning_engine:
      reasoning_engine = self.env_vars.get("AGENT_ENGINE_RESOURCE_NAME")

    if tool_description or reasoning_engine:
      data["adkAgentDefinition"] = {}
      if tool_description:
        data["adkAgentDefinition"]["toolSettings"] = {
            "toolDescription": tool_description
        }
      if reasoning_engine:
        data["adkAgentDefinition"]["provisionedReasoningEngine"] = {
            "reasoningEngine": reasoning_engine
        }
      update_mask.append("adkAgentDefinition")

    if not auth_id:
      auth_id = self.env_vars.get("OAUTH_AUTH_ID")
    if auth_id:
      data["authorizationConfig"] = {
          "toolAuthorizations": [
              f"projects/{project_number}/locations/global/"
              f"authorizations/{auth_id}"
          ]
      }
      update_mask.append("authorizationConfig")

    if not update_mask:
      typer.echo("[WARNING] No fields to update", err=True)
      return True

    params = {"updateMask": ",".join(update_mask)}

    try:
      response = requests.patch(
          url,
          headers=headers,
          json=data,
          params=params,
          timeout=DEFAULT_HTTP_TIMEOUT,
      )
      response.raise_for_status()

      typer.echo("[OK] Successfully updated agent configuration!")
      return True

    except requests.exceptions.RequestException as e:
      typer.echo(f"[ERROR] Error updating agent configuration: {e}", err=True)
      if e.response is not None and hasattr(e.response, "text"):
        typer.echo(f"Response: {e.response.text}", err=True)
      return False

  def list_apps(self, show_raw: bool = True) -> bool:
    """List all apps in the Gemini Enterprise collection.

    Args:
        show_raw: If True, show raw JSON response for debugging.

    Returns:
        True if successful, False otherwise.
    """
    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    if not project_number:
      typer.echo(
          "[ERROR] GCP_PROJECT_NUMBER not found in environment", err=True
      )
      return False

    access_token = self._get_access_token()
    if not access_token:
      typer.echo("[ERROR] Failed to get access token", err=True)
      return False

    collection = self._get_collection()
    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/engines"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Goog-User-Project": project_number,
    }

    try:
      response = requests.get(
          url, headers=headers, timeout=DEFAULT_HTTP_TIMEOUT
      )
      response.raise_for_status()

      result = response.json()
      engines = result.get("engines", [])

      if show_raw:
        typer.echo("\n=== RAW JSON RESPONSE ===")
        typer.echo(json.dumps(result, indent=2))
        typer.echo("=== END RAW JSON ===\n")

      if not engines:
        typer.echo("[INFO] No apps found in Gemini Enterprise collection.")
        return True

      typer.echo(f"\nFound {len(engines)} app(s) in Gemini Enterprise:\n")
      for i, engine in enumerate(engines, 1):
        name = engine.get("name", "")
        app_id = name.split("/")[-1] if "/" in name else name
        display_name = engine.get("displayName", "N/A")
        solution_type = engine.get("solutionType", "N/A")
        data_store_ids = engine.get("dataStoreIds", [])
        create_time = engine.get("createTime", "N/A")

        typer.echo(f"{i}. App ID: {app_id}")
        typer.echo(f"   Display Name: {display_name}")
        typer.echo(f"   Solution Type: {solution_type}")

        if data_store_ids:
          typer.echo(f"   Data Stores: {', '.join(data_store_ids)}")
        else:
          typer.echo("   Data Stores: None")

        typer.echo(f"   Create Time: {create_time}")

        if show_raw:
          typer.echo("\n   === RAW ENGINE DATA ===")
          typer.echo(json.dumps(engine, indent=4))
          typer.echo("   === END ENGINE DATA ===")

        typer.echo()

      return True

    except requests.exceptions.RequestException as e:
      typer.echo(f"[ERROR] Error listing apps: {e}", err=True)
      if e.response is not None and hasattr(e.response, "text"):
        typer.echo(f"Response: {e.response.text}", err=True)
      return False

  def list_agents(self, show_raw: bool = True) -> bool:
    """List all agents in the Gemini Enterprise app.

    Args:
        show_raw: If True, show raw JSON response for debugging.

    Returns:
        True if successful, False otherwise.
    """
    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    if not project_number:
      typer.echo(
          "[ERROR] GCP_PROJECT_NUMBER not found in environment", err=True
      )
      return False

    app_id = self._get_app_id()
    if not app_id:
      typer.echo(
          "[ERROR] GEMINI_ENTERPRISE_APP_ID (or AGENTSPACE_APP_ID) not found"
          " in environment",
          err=True,
      )
      return False

    access_token = self._get_access_token()
    if not access_token:
      typer.echo("[ERROR] Failed to get access token", err=True)
      return False

    collection = self._get_collection()
    assistant = self._get_assistant()
    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/locations/"
        f"global/collections/{collection}/engines/{app_id}/assistants/"
        f"{assistant}/agents"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Goog-User-Project": project_number,
    }

    try:
      response = requests.get(
          url, headers=headers, timeout=DEFAULT_HTTP_TIMEOUT
      )
      response.raise_for_status()

      result = response.json()
      agents = result.get("agents", [])

      if show_raw:
        typer.echo("\n=== RAW JSON RESPONSE ===")
        typer.echo(json.dumps(result, indent=2))
        typer.echo("=== END RAW JSON ===\n")

      if not agents:
        typer.echo("[INFO] No agents found in Gemini Enterprise app.")
        return True

      engine_url = (
          f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
          f"locations/global/collections/{collection}/engines/{app_id}"
      )
      engine_response = self._make_request("GET", engine_url)
      solution_type = "N/A"
      if engine_response:
        engine_data = engine_response.json()
        solution_type = engine_data.get("solutionType", "N/A")

      typer.echo(f"\nFound {len(agents)} agent(s) in Gemini Enterprise:\n")
      typer.echo(f"Engine Solution Type: {solution_type}\n")
      for i, agent in enumerate(agents, 1):
        name = agent.get("name", "")
        agent_id = name.split("/")[-1] if "/" in name else name
        display_name = agent.get("displayName", "N/A")
        description = agent.get("description", "N/A")

        typer.echo(f"{i}. Agent ID: {agent_id}")
        typer.echo(f"   Display Name: {display_name}")
        typer.echo(f"   Description: {description}")

        adk_def = agent.get("adk_agent_definition", {})
        tool_settings = adk_def.get("tool_settings", {})
        if tool_settings.get("tool_description"):
          typer.echo(
              f"   Tool Description: {tool_settings['tool_description']}"
          )

        prov_engine = adk_def.get("provisioned_reasoning_engine", {})
        if prov_engine.get("reasoning_engine"):
          typer.echo(f"   Reasoning Engine: {prov_engine['reasoning_engine']}")

        if show_raw:
          typer.echo("\n   === RAW AGENT DATA ===")
          typer.echo(json.dumps(agent, indent=4))
          typer.echo("   === END AGENT DATA ===")

        typer.echo()

      return True

    except requests.exceptions.RequestException as e:
      typer.echo(f"[ERROR] Error listing agents: {e}", err=True)
      if e.response is not None and hasattr(e.response, "text"):
        typer.echo(f"Response: {e.response.text}", err=True)
      return False

  def get_app_details(self, app_id: str) -> bool:
    """Get detailed information about a specific Gemini Enterprise app.

    Args:
        app_id: The ID of the app to inspect.

    Returns:
        True if successful, False otherwise.
    """
    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    if not project_number:
      typer.echo(
          "[ERROR] GCP_PROJECT_NUMBER not found in environment", err=True
      )
      return False

    access_token = self._get_access_token()
    if not access_token:
      typer.echo("[ERROR] Failed to get access token", err=True)
      return False

    collection = self._get_collection()
    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/engines/{app_id}"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Goog-User-Project": project_number,
    }

    typer.echo(f"\n=== Getting details for app: {app_id} ===\n")
    typer.echo(f"API URL: {url}\n")

    try:
      response = requests.get(
          url, headers=headers, timeout=DEFAULT_HTTP_TIMEOUT
      )
      response.raise_for_status()

      result = response.json()

      typer.echo("App Details:")
      typer.echo(f"  Name: {result.get('name', 'N/A')}")
      typer.echo(f"  Display Name: {result.get('displayName', 'N/A')}")
      typer.echo(f"  Solution Type: {result.get('solutionType', 'N/A')}")

      data_store_ids = result.get("dataStoreIds", [])
      if data_store_ids:
        typer.echo(f"  Data Stores: {', '.join(data_store_ids)}")
      else:
        typer.echo("  Data Stores: None (empty list or field not present)")

      typer.echo(f"  Create Time: {result.get('createTime', 'N/A')}")
      typer.echo(f"  Update Time: {result.get('updateTime', 'N/A')}")

      if "chatEngineConfig" in result:
        typer.echo("  Chat Engine Config: Present")
      if "searchEngineConfig" in result:
        typer.echo("  Search Engine Config: Present")
      if "commonConfig" in result:
        typer.echo("  Common Config: Present")

      typer.echo("\n=== RAW JSON RESPONSE ===")
      typer.echo(json.dumps(result, indent=2))
      typer.echo("=== END RAW JSON ===\n")

      if "dataStoreIds" in result:
        if not result["dataStoreIds"]:
          typer.echo("[INFO] dataStoreIds field is present but empty []")
      else:
        typer.echo("[INFO] dataStoreIds field is NOT present in the response")

      return True

    except requests.exceptions.RequestException as e:
      typer.echo(f"[ERROR] Error getting app details: {e}", err=True)
      if e.response is not None and hasattr(e.response, "text"):
        typer.echo(f"Response: {e.response.text}", err=True)
      return False

  def search_agentspace(self, query: str = "test query") -> bool:
    """Test Gemini Enterprise search functionality via Discovery Engine API."""
    typer.echo(f"[INFO] Testing Gemini Enterprise search with query: '{query}'")

    project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    app_id = self._get_app_id()
    missing = []
    if not project_number:
      missing.append("GCP_PROJECT_NUMBER")
    if not app_id:
      missing.append("GEMINI_ENTERPRISE_APP_ID")
    if missing:
      typer.secho(
          f"[ERROR] Missing required variables: {', '.join(missing)}",
          fg=typer.colors.RED,
      )
      return False

    if not self._ensure_data_store_exists():
      typer.secho(
          "[ERROR] Cannot search without a data store", fg=typer.colors.RED
      )
      return False

    collection = self._get_collection()
    url = (
        f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
        f"locations/global/collections/{collection}/engines/{app_id}/"
        f"servingConfigs/default_search:search"
    )

    search_payload = {
        "query": query,
        "pageSize": 10,
        "spellCorrectionSpec": {"mode": "AUTO"},
        "languageCode": "en-US",
        "relevanceScoreSpec": {"returnRelevanceScore": True},
        "userInfo": {"timeZone": "America/New_York"},
        "contentSearchSpec": {"snippetSpec": {"returnSnippet": True}},
        "naturalLanguageQueryUnderstandingSpec": {
            "filterExtractionCondition": "ENABLED"
        },
    }

    response = self._make_request("POST", url, json=search_payload)
    if response and response.status_code == 200:
      result = response.json()
      typer.secho(
          "[OK] Gemini Enterprise search test successful!",
          fg=typer.colors.GREEN,
      )

      results = result.get("results", [])
      total_size = result.get("totalSize", 0)

      typer.echo(f"  Total results: {total_size}")
      typer.echo(f"  Returned results: {len(results)}")

      if results:
        typer.echo("  Search results:")
        for i, result_item in enumerate(results[:3], 1):
          document = result_item.get("document", {})
          title = document.get("title", "No title")
          snippet = result_item.get("snippet", "No snippet available")
          relevance = result_item.get("relevanceScore", "N/A")

          typer.echo(f"    {i}. Title: {title}")
          typer.echo(f"       Relevance: {relevance}")
          suffix = "..." if len(snippet) > 100 else ""
          typer.echo(f"       Snippet: {snippet[:100]}{suffix}")
          typer.echo("")
      else:
        typer.echo("  No search results returned")

      return True

    typer.secho(
        "[ERROR] Gemini Enterprise search test failed!", fg=typer.colors.RED
    )
    return False


GeminiEnterpriseManager = AgentSpaceManager


@app.command()
def register(
    force: Annotated[
        bool,
        typer.Option("--force", help="Force re-registration if agent exists."),
    ] = False,
    agent_engine_id: Annotated[
        str | None,
        typer.Option(
            "--agent-engine-id", help="Reasoning Engine resource name."
        ),
    ] = None,
    app_id: Annotated[
        str | None, typer.Option("--app-id", help="Gemini Enterprise App ID.")
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Register the agent with Gemini Enterprise."""
  manager = AgentSpaceManager(env_file)
  if not manager.register_agent(force, agent_engine_id, app_id):
    raise typer.Exit(code=1)


@app.command()
def update(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Update the existing Gemini Enterprise agent configuration."""
  manager = AgentSpaceManager(env_file)
  if not manager.update_agent():
    raise typer.Exit(code=1)


@app.command()
def verify(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Verify the Gemini Enterprise agent configuration and status."""
  manager = AgentSpaceManager(env_file)
  if not manager.verify_agent():
    raise typer.Exit(code=1)


@app.command()
def delete(
    force: Annotated[
        bool,
        typer.Option("--force", help="Force deletion without confirmation."),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Delete the agent from Gemini Enterprise."""
  manager = AgentSpaceManager(env_file)
  if not manager.delete_agent(force):
    raise typer.Exit(code=1)


@app.command()
def url(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Display the Gemini Enterprise Cloud Console URL."""
  manager = AgentSpaceManager(env_file)
  manager.display_url()


@app.command()
def search(
    query: Annotated[
        str, typer.Option("--query", help="Search query to test with.")
    ] = "test security operations",
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Test Gemini Enterprise search functionality via Discovery Engine API."""
  manager = AgentSpaceManager(env_file)
  if not manager.search_agentspace(query):
    raise typer.Exit(code=1)


@app.command()
def ensure_datastore(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Ensure the Gemini Enterprise engine has a data store configured."""
  manager = AgentSpaceManager(env_file)
  if not manager._ensure_data_store_exists():
    raise typer.Exit(code=1)


@app.command()
def link_agent(
    display_name: Annotated[
        str | None,
        typer.Option("--display-name", help="Display name for the agent."),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", help="Description of the agent."),
    ] = None,
    tool_description: Annotated[
        str | None,
        typer.Option(
            "--tool-description",
            help="Description of what the agent tool does.",
        ),
    ] = None,
    auth_id: Annotated[
        str | None, typer.Option("--auth-id", help="OAuth authorization ID.")
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Link an existing Agent Engine to Gemini Enterprise with OAuth authorization."""
  manager = AgentSpaceManager(env_file)
  if not manager.link_agent_to_agentspace(
      display_name, description, tool_description, auth_id
  ):
    raise typer.Exit(code=1)


@app.command()
def unlink_agent(
    agent_id: Annotated[
        str | None,
        typer.Option(
            "--agent-id",
            help="ID of the agent to unlink (defaults to env var).",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Force unlinking without confirmation."),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Unlink (remove) an agent from Gemini Enterprise while keeping the app intact."""
  manager = AgentSpaceManager(env_file)
  if not manager.unlink_agent_from_agentspace(agent_id, force):
    raise typer.Exit(code=1)


@app.command()
def update_agent_config(
    agent_id: Annotated[
        str | None,
        typer.Option("--agent-id", help="ID of the agent to update."),
    ] = None,
    display_name: Annotated[
        str | None,
        typer.Option("--display-name", help="New display name for the agent."),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", help="New description of the agent."),
    ] = None,
    tool_description: Annotated[
        str | None,
        typer.Option(
            "--tool-description",
            help="New description of what the agent tool does.",
        ),
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """Update an existing agent's configuration in Gemini Enterprise."""
  manager = AgentSpaceManager(env_file)
  if not manager.update_agent_config(
      agent_id, display_name, description, tool_description
  ):
    raise typer.Exit(code=1)


@app.command()
def list_apps(
    raw: Annotated[
        bool,
        typer.Option(
            "--raw",
            help="Show raw JSON response for debugging and bug reports.",
        ),
    ] = True,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """List all apps in the Gemini Enterprise collection."""
  manager = AgentSpaceManager(env_file)
  if not manager.list_apps(show_raw=raw):
    raise typer.Exit(code=1)


@app.command()
def list_agents(
    raw: Annotated[
        bool,
        typer.Option(
            "--raw",
            help="Show raw JSON response for debugging and bug reports.",
        ),
    ] = True,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  """List all agents in the Gemini Enterprise app."""
  manager = AgentSpaceManager(env_file)
  manager.list_agents(show_raw=raw)


@app.command()
def get_app_details(
    app_id: Annotated[
        str,
        typer.Argument(help="The ID of the app to get details for."),
    ],
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  r"""Get detailed information about a specific Gemini Enterprise app.

  Example:
      uv run oauth-flow-gemini-enterprise-secops-mcp gemini-enterprise \
        get-app-details my-secops-app_1763471046
  """
  manager = AgentSpaceManager(env_file)
  if not manager.get_app_details(app_id):
    raise typer.Exit(code=1)


@app.command()
def create_app(
    app_name: Annotated[
        str | None, typer.Option("--name", help="Display name for the app.")
    ] = None,
    solution_type: Annotated[
        str,
        typer.Option(
            "--type",
            help="Solution type (SOLUTION_TYPE_SEARCH, SOLUTION_TYPE_CHAT).",
        ),
    ] = "SOLUTION_TYPE_SEARCH",
    data_store_id: Annotated[
        str | None,
        typer.Option(
            "--data-store", help="Data store ID to associate with the app."
        ),
    ] = None,
    no_datastore: Annotated[
        bool,
        typer.Option(
            "--no-datastore",
            help=(
                "Explicitly create app without data stores (required for web UI"
                " visibility)."
            ),
        ),
    ] = False,
    app_type: Annotated[
        str | None,
        typer.Option(
            "--app-type",
            help=(
                "App type (e.g., APP_TYPE_INTRANET). Required for web UI"
                " visibility."
            ),
        ),
    ] = None,
    industry_vertical: Annotated[
        str | None,
        typer.Option(
            "--industry-vertical",
            help=(
                "Industry vertical (e.g., GENERIC). Required with --app-type"
                " for web UI visibility."
            ),
        ),
    ] = None,
    enable_chat: Annotated[
        bool,
        typer.Option(
            "--enable-chat",
            help=(
                "Enable chat features (requires Dialogflow API for CHAT type)."
            ),
        ),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  r"""Create a new Gemini Enterprise app in Discovery Engine.

  For apps to appear in the Gemini Enterprise web UI, pass
  --app-type APP_TYPE_INTRANET and --industry-vertical GENERIC.

  Official documentation: https://cloud.google.com/gemini/enterprise/docs/create-app

  Examples:
      uv run oauth-flow-gemini-enterprise-secops-mcp gemini-enterprise create-app \
        --name "SecOps App" \
        --type SOLUTION_TYPE_CHAT \
        --no-datastore \
        --app-type APP_TYPE_INTRANET \
        --industry-vertical GENERIC

      uv run oauth-flow-gemini-enterprise-secops-mcp gemini-enterprise create-app \
        --name "SecOps App" --data-store my-store-id
  """
  manager = AgentSpaceManager(env_file)

  if no_datastore and data_store_id:
    typer.secho(
        "[ERROR] Cannot specify both --no-datastore and --data-store",
        fg=typer.colors.RED,
    )
    typer.echo(
        "Choose one: either explicitly skip data stores or provide a data store"
        " ID"
    )
    raise typer.Exit(code=1)

  data_store_ids = [data_store_id] if data_store_id else None

  if not manager.create_app(
      app_name=app_name,
      solution_type=solution_type,
      data_store_ids=data_store_ids,
      enable_chat=enable_chat,
      skip_datastore=no_datastore,
      app_type=app_type,
      industry_vertical=industry_vertical,
  ):
    raise typer.Exit(code=1)


@app.command()
def delete_app(
    app_id: Annotated[
        str, typer.Argument(help="App ID to delete (e.g., my-app_1234567890)")
    ],
    force: Annotated[
        bool,
        typer.Option("--force", help="Force deletion without confirmation."),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
  r"""Delete a Gemini Enterprise app (engine) from Discovery Engine.

  Examples:
      uv run oauth-flow-gemini-enterprise-secops-mcp gemini-enterprise \
        delete-app my-app_1234567890

      uv run oauth-flow-gemini-enterprise-secops-mcp gemini-enterprise \
        delete-app my-app_1234567890 --force
  """
  manager = AgentSpaceManager(env_file)
  if not manager.delete_app(app_id, force):
    raise typer.Exit(code=1)


if __name__ == "__main__":
  app()
