"""Unit tests for Chronicle Case Creation MCP Tools."""

import json
from unittest.mock import MagicMock, patch
import httpx
import pytest

from secops_agent_app.tools.case_creation import (
    _build_v1alpha_endpoint,
    _get_base_url,
    _get_headers,
    create_case,
    create_manual_case,
    create_manual_case_soar,
    create_or_update_case,
    mcp,
)


def test_get_base_url_defaults_and_custom():
    assert _get_base_url("us") == "https://us-chronicle.googleapis.com"
    assert _get_base_url("europe") == "https://europe-chronicle.googleapis.com"
    assert _get_base_url("asia-east1.rep.googleapis.com") == "https://asia-east1.rep.googleapis.com"


def test_build_v1alpha_endpoint():
    url = _build_v1alpha_endpoint(
        method_name="createCase",
        project_id="my-project",
        location="us",
        instance_id="my-instance",
        region="us",
    )
    expected = (
        "https://us-chronicle.googleapis.com/v1alpha/projects/my-project/"
        "locations/us/instances/my-instance/legacyCases:createCase"
    )
    assert url == expected


def test_get_headers_with_token_and_project():
    headers = _get_headers(auth_token="test-token", project_id="my-proj")
    assert headers["Authorization"] == "Bearer test-token"
    assert headers["x-goog-user-project"] == "my-proj"
    assert headers["Content-Type"] == "application/json"


@patch("httpx.Client.post")
def test_create_case_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = json.dumps({"name": "operations/12345", "done": True})
    mock_resp.json.return_value = {"name": "operations/12345", "done": True}
    mock_post.return_value = mock_resp

    payload = {"cases": [{"id": "C-101", "alerts": [{"id": "A-01"}]}]}
    res = create_case(
        payload=payload,
        instance_id="inst-1",
        project_id="proj-1",
        location="us",
        auth_token="token-1",
    )

    assert res == {"name": "operations/12345", "done": True}
    assert mock_post.called
    args, kwargs = mock_post.call_args
    assert "legacyCases:createCase" in args[0]
    assert kwargs["headers"]["Authorization"] == "Bearer token-1"
    assert kwargs["json"] == payload


@patch("httpx.Client.post")
def test_create_case_http_error(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.text = "Permission denied: chronicle.legacyCases.ingest"
    mock_post.side_effect = httpx.HTTPStatusError(
        "403 Forbidden", request=MagicMock(), response=mock_response
    )

    res = create_case(
        payload={"test": "data"},
        instance_id="inst-1",
        project_id="proj-1",
        auth_token="token-1",
    )

    assert "error" in res
    assert res["status_code"] == 403
    assert "Permission denied" in res["details"]


@patch("httpx.Client.post")
def test_create_manual_case_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = json.dumps({"case": {"id": "case-999", "title": "Suspicious Login"}})
    mock_resp.json.return_value = {"case": {"id": "case-999", "title": "Suspicious Login"}}
    mock_post.return_value = mock_resp

    res = create_manual_case(
        title="Suspicious Login",
        description="Multiple failed SSH attempts",
        priority="HIGH",
        tags=["auth", "ssh"],
        custom_properties={"env": "prod"},
        attached_playbooks=["pb-ssh-triage"],
        instance_id="inst-1",
        project_id="proj-1",
        auth_token="token-1",
    )

    assert res["case"]["id"] == "case-999"
    assert mock_post.called
    args, kwargs = mock_post.call_args
    assert "legacyCases:createManualCase" in args[0]
    body = kwargs["json"]
    assert body["case"]["title"] == "Suspicious Login"
    assert body["case"]["priority"] == "HIGH"
    assert body["case"]["tags"] == ["auth", "ssh"]
    assert body["case"]["customProperties"] == {"env": "prod"}
    assert body["case"]["attachedPlaybooks"] == ["pb-ssh-triage"]


@patch("httpx.Client.post")
def test_create_or_update_case_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = json.dumps({"case": {"id": "case-123", "status": "UPDATED"}})
    mock_resp.json.return_value = {"case": {"id": "case-123", "status": "UPDATED"}}
    mock_post.return_value = mock_resp

    payload = {"case": {"title": "Updated Case"}}
    res = create_or_update_case(
        payload=payload,
        case_id="case-123",
        instance_id="inst-1",
        project_id="proj-1",
        auth_token="token-1",
    )

    assert res["case"]["status"] == "UPDATED"
    assert mock_post.called
    args, kwargs = mock_post.call_args
    assert "legacyCases:createOrUpdateCase" in args[0]
    assert kwargs["json"]["case"]["id"] == "case-123"


@patch("httpx.Client.post")
def test_create_manual_case_soar_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = json.dumps({"caseId": 888, "isSuccess": True})
    mock_resp.json.return_value = {"caseId": 888, "isSuccess": True}
    mock_post.return_value = mock_resp

    res = create_manual_case_soar(
        title="SOAR Incident",
        description="Malware detected",
        priority=2,
        custom_fields={"host": "host-01"},
        soar_url="https://soar.example.com",
        app_key="soar-secret-appkey",
    )

    assert res == {"caseId": 888, "isSuccess": True}
    assert mock_post.called
    args, kwargs = mock_post.call_args
    assert args[0] == "https://soar.example.com/api/external/v1/cases/CreateManualCase"
    assert kwargs["headers"]["AppKey"] == "soar-secret-appkey"
    assert kwargs["json"]["Title"] == "SOAR Incident"
    assert kwargs["json"]["Priority"] == 2


@pytest.mark.asyncio
async def test_mcp_server_tools_registered():
    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]
    assert "create_case" in tool_names
    assert "create_manual_case" in tool_names
    assert "create_or_update_case" in tool_names
    assert "create_manual_case_soar" in tool_names
