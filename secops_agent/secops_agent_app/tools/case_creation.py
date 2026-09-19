"""Chronicle REST API Case Creation MCP Tools.

Provides MCP tools and Python functions supporting case creation endpoints
across Google SecOps / Chronicle REST API and legacy SOAR endpoints:
1. legacyCases:createCase (v1alpha)
2. legacyCases:createManualCase (v1alpha)
3. legacyCreateOrUpdateCase (v1alpha)
4. /api/external/v1/cases/CreateManualCase (Legacy SOAR API)
"""

import json
import os
from typing import Any, Dict, List, Optional, Union
import httpx
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP Server for case creation tools
mcp = FastMCP("ChronicleCaseCreation")


def _get_auth_token(provided_token: Optional[str] = None) -> Optional[str]:
    """Resolves OAuth access token from explicit parameter, environment, or Google auth."""
    if provided_token:
        return provided_token
    env_token = os.environ.get("CHRONICLE_AUTH_TOKEN") or os.environ.get("GEMINI_AUTHORIZATION_TOKEN")
    if env_token:
        return env_token
    try:
        import google.auth
        import google.auth.transport.requests

        credentials, _ = google.auth.default(
            scopes=[
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/chronicle",
            ]
        )
        auth_req = google.auth.transport.requests.Request()
        credentials.refresh(auth_req)
        return credentials.token
    except Exception:
        return None


def _get_headers(
    auth_token: Optional[str] = None,
    project_id: Optional[str] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Constructs request headers including OAuth Authorization and project routing headers."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    token = _get_auth_token(auth_token)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    proj = project_id or os.environ.get("CHRONICLE_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if proj:
        headers["x-goog-user-project"] = proj

    if extra_headers:
        headers.update(extra_headers)

    return headers


def _get_base_url(region: Optional[str] = None) -> str:
    """Builds the base host URL for regional Chronicle API endpoints."""
    reg = region or os.environ.get("CHRONICLE_REGION", "us").lower()
    if "." in reg:
        if not reg.startswith("http://") and not reg.startswith("https://"):
            return f"https://{reg}"
        return reg

    if reg in ("us", "", "global"):
        return "https://us-chronicle.googleapis.com"
    return f"https://{reg}-chronicle.googleapis.com"


def _build_v1alpha_endpoint(
    method_name: str,
    project_id: Optional[str] = None,
    location: Optional[str] = None,
    instance_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Constructs full regional URL for Chronicle v1alpha legacyCases endpoints."""
    base_url = _get_base_url(region)
    proj = project_id or os.environ.get("CHRONICLE_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT") or "default"
    loc = location or os.environ.get("CHRONICLE_LOCATION") or os.environ.get("CHRONICLE_REGION") or "us"
    inst = instance_id or os.environ.get("CHRONICLE_CUSTOMER_ID") or os.environ.get("CHRONICLE_INSTANCE_ID") or "default"

    return f"{base_url}/v1alpha/projects/{proj}/locations/{loc}/instances/{inst}/legacyCases:{method_name}"


@mcp.tool()
def create_case(
    payload: Union[Dict[str, Any], str],
    instance_id: Optional[str] = None,
    project_id: Optional[str] = None,
    location: Optional[str] = None,
    region: Optional[str] = None,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingests a package of cases and alerts into Chronicle data processing engine (legacyCases:createCase).

    Requires IAM Permission: chronicle.legacyCases.ingest

    Args:
        payload: Dict or JSON string containing the package of cases and alerts to ingest.
        instance_id: Optional Chronicle instance/customer ID.
        project_id: Optional Google Cloud Project ID.
        location: Optional regional location (e.g., 'us', 'europe').
        region: Optional Chronicle API region prefix.
        auth_token: Optional OAuth 2.0 access token.

    Returns:
        API response dictionary or error details.
    """
    url = _build_v1alpha_endpoint(
        method_name="createCase",
        project_id=project_id,
        location=location,
        instance_id=instance_id,
        region=region,
    )
    headers = _get_headers(auth_token=auth_token, project_id=project_id)

    if isinstance(payload, str):
        try:
            body = json.loads(payload)
        except Exception:
            body = {"payload": payload}
    else:
        body = payload or {}

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            return resp.json() if resp.text else {"status": "success", "status_code": resp.status_code}
    except httpx.HTTPStatusError as exc:
        return {
            "error": "HTTP error during createCase execution",
            "status_code": exc.response.status_code,
            "details": exc.response.text,
        }
    except Exception as exc:
        return {
            "error": "Failed to call legacyCases:createCase",
            "details": str(exc),
        }


@mcp.tool()
def create_manual_case(
    title: Optional[str] = None,
    description: Optional[str] = None,
    priority: Optional[str] = None,
    tags: Optional[List[str]] = None,
    custom_properties: Optional[Dict[str, Any]] = None,
    attached_playbooks: Optional[List[str]] = None,
    payload: Optional[Dict[str, Any]] = None,
    instance_id: Optional[str] = None,
    project_id: Optional[str] = None,
    location: Optional[str] = None,
    region: Optional[str] = None,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Programmatically creates a manual case with properties, priority, tags, playbooks (legacyCases:createManualCase).

    Requires IAM Permission: chronicle.legacyCases.createManual

    Args:
        title: Title of the manual case.
        description: Detailed description of the case.
        priority: Case priority (e.g., "LOW", "MEDIUM", "HIGH", "CRITICAL").
        tags: List of tags associated with the case.
        custom_properties: Key-value dictionary of custom case properties.
        attached_playbooks: List of playbook IDs or names to attach.
        payload: Optional raw dictionary payload overriding constructed properties.
        instance_id: Optional Chronicle instance/customer ID.
        project_id: Optional Google Cloud Project ID.
        location: Optional regional location.
        region: Optional region prefix.
        auth_token: Optional OAuth 2.0 access token.

    Returns:
        API response dictionary or error details.
    """
    url = _build_v1alpha_endpoint(
        method_name="createManualCase",
        project_id=project_id,
        location=location,
        instance_id=instance_id,
        region=region,
    )
    headers = _get_headers(auth_token=auth_token, project_id=project_id)

    if payload and isinstance(payload, dict):
        body = payload
    else:
        case_data: Dict[str, Any] = {}
        if title:
            case_data["title"] = title
        if description:
            case_data["description"] = description
        if priority:
            case_data["priority"] = priority
        if tags:
            case_data["tags"] = tags
        if custom_properties:
            case_data["customProperties"] = custom_properties
        if attached_playbooks:
            case_data["attachedPlaybooks"] = attached_playbooks

        body = {"case": case_data} if case_data else {}

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            return resp.json() if resp.text else {"status": "success", "status_code": resp.status_code}
    except httpx.HTTPStatusError as exc:
        return {
            "error": "HTTP error during createManualCase execution",
            "status_code": exc.response.status_code,
            "details": exc.response.text,
        }
    except Exception as exc:
        return {
            "error": "Failed to call legacyCases:createManualCase",
            "details": str(exc),
        }


@mcp.tool()
def create_or_update_case(
    payload: Union[Dict[str, Any], str],
    case_id: Optional[str] = None,
    instance_id: Optional[str] = None,
    project_id: Optional[str] = None,
    location: Optional[str] = None,
    region: Optional[str] = None,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates a new case or updates an existing case using legacy case schema payloads (legacyCreateOrUpdateCase).

    Requires IAM Permission: chronicle.legacyCases.ingest or case admin

    Args:
        payload: Dict or JSON string containing legacy case schema payload.
        case_id: Optional ID of an existing case to update.
        instance_id: Optional Chronicle instance/customer ID.
        project_id: Optional Google Cloud Project ID.
        location: Optional regional location.
        region: Optional region prefix.
        auth_token: Optional OAuth 2.0 access token.

    Returns:
        API response dictionary or error details.
    """
    url = _build_v1alpha_endpoint(
        method_name="createOrUpdateCase",
        project_id=project_id,
        location=location,
        instance_id=instance_id,
        region=region,
    )
    headers = _get_headers(auth_token=auth_token, project_id=project_id)

    if isinstance(payload, str):
        try:
            body = json.loads(payload)
        except Exception:
            body = {"case": {"raw": payload}}
    else:
        body = payload or {}

    if case_id and isinstance(body, dict):
        if "case" in body and isinstance(body["case"], dict):
            body["case"]["id"] = case_id
        else:
            body["caseId"] = case_id

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            return resp.json() if resp.text else {"status": "success", "status_code": resp.status_code}
    except httpx.HTTPStatusError as exc:
        return {
            "error": "HTTP error during createOrUpdateCase execution",
            "status_code": exc.response.status_code,
            "details": exc.response.text,
        }
    except Exception as exc:
        return {
            "error": "Failed to call legacyCreateOrUpdateCase",
            "details": str(exc),
        }


@mcp.tool()
def create_manual_case_soar(
    title: Optional[str] = None,
    description: Optional[str] = None,
    priority: Optional[Union[str, int]] = None,
    custom_fields: Optional[Dict[str, Any]] = None,
    payload: Optional[Dict[str, Any]] = None,
    soar_url: Optional[str] = None,
    app_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Legacy endpoint for direct manual case creation on standalone SOAR environments (/api/external/v1/cases/CreateManualCase).

    Requires SOAR API Key (AppKey).

    Args:
        title: Case title.
        description: Case description.
        priority: Priority value.
        custom_fields: Dictionary of custom fields.
        payload: Optional raw payload dictionary overriding field arguments.
        soar_url: Base URL of the SOAR environment (e.g., https://soar.example.com).
        app_key: SOAR API Key (AppKey).

    Returns:
        API response dictionary or error details.
    """
    base_soar_url = (
        soar_url
        or os.environ.get("CHRONICLE_SOAR_URL")
        or os.environ.get("SOAR_URL")
        or "https://soar.chronicle.security"
    ).rstrip("/")

    url = f"{base_soar_url}/api/external/v1/cases/CreateManualCase"

    key = app_key or os.environ.get("CHRONICLE_SOAR_APP_KEY") or os.environ.get("SOAR_APP_KEY") or ""

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "AppKey": key,
        "app-key": key,
    }

    if payload and isinstance(payload, dict):
        body = payload
    else:
        body = {}
        if title:
            body["Title"] = title
        if description:
            body["Description"] = description
        if priority is not None:
            body["Priority"] = priority
        if custom_fields:
            body["CustomFields"] = custom_fields

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            return resp.json() if resp.text else {"status": "success", "status_code": resp.status_code}
    except httpx.HTTPStatusError as exc:
        return {
            "error": "HTTP error during CreateManualCase legacy SOAR call",
            "status_code": exc.response.status_code,
            "details": exc.response.text,
        }
    except Exception as exc:
        return {
            "error": "Failed to call legacy SOAR CreateManualCase endpoint",
            "details": str(exc),
        }
