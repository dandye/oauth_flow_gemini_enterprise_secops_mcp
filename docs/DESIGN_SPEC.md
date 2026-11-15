# DESIGN_SPEC.md

## Overview

This ADK agent connects to the Google Security Operations (SecOps) remote MCP server from Vertex AI Agent Engine and integrates with Gemini Enterprise. It uses Gemini Enterprise OAuth passthrough so every request to the remote Google SecOps MCP endpoint executes under the signed-in end user's own credentials.

## Example Use Cases

- **List Cases**: A user asks "Show me recent cases". The agent calls the Google SecOps MCP `list_cases` tool using the user's OAuth bearer token and summarizes active cases.
- **Search Events**: A user asks "Search UDM events for IP 1.2.3.4". The agent calls `udm_search` on the Google SecOps MCP server.

## Tools Required

- **McpToolset**: Connects over streamable HTTP to the locational Google SecOps remote MCP endpoint (`https://{region}-chronicle.googleapis.com/mcp`, overridable via `SECOPS_MCP_URL`).
  - **Authentication**: Uses Gemini Enterprise managed OAuth passthrough.
  - **Tenant Context**: Uses `CHRONICLE_PROJECT_ID`, `CHRONICLE_CUSTOMER_ID`, and `CHRONICLE_REGION` to route requests to the target Google SecOps tenant.

## Constraints & Safety Rules

- The agent relies exclusively on the remote Google SecOps MCP server for SIEM and SOAR operations.
- The agent never logs raw OAuth tokens or client secrets in standard output or application logs.
- The agent follows Vertex AI Agent Engine deployment practices without hardcoding local session storage in agent definitions.

## Success Criteria

- The agent initializes and connects to `https://{region}-chronicle.googleapis.com/mcp`.
- The agent executes Google SecOps MCP tools such as `udm_search` and `list_cases` on behalf of the authorized user.
- The signed-in user's OAuth token flows from Gemini Enterprise through Vertex AI Agent Engine to the Google SecOps MCP server with `x-goog-user-project` set to `CHRONICLE_PROJECT_ID`.

## Edge Cases & Runtime Prerequisites

- **Missing Tenant Configuration**: When `CHRONICLE_PROJECT_ID`, `CHRONICLE_CUSTOMER_ID`, or `CHRONICLE_REGION` is unset, the agent logs a clear configuration error rather than sending unroutable tool calls.
- **Missing OAuth Token**: When an authorization ID is configured and the session state lacks a user OAuth token, the agent does not silently fall back to service account credentials in production; Gemini Enterprise prompts the user to sign in.
- **Google Cloud IAM Requirements**: Authorizing end users must hold `roles/mcp.toolUser`, `roles/chronicle.viewer` (or higher), and `roles/serviceusage.serviceUsageConsumer` on `CHRONICLE_PROJECT_ID`.
- **Google SecOps SOAR Provisioning**: Calling SOAR-backed tools (`list_cases`, `list_integrations`, `list_playbooks`) requires the OAuth user to match an access rule in `Settings > Access management > Group Mapping` and to have signed in to the Google SecOps web UI at least once so their profile exists in `Settings > Access management > User Management`; otherwise SOAR endpoints return `401 You are not recognized.`.

## Design Considerations: Gemini Enterprise OAuth Passthrough

Gemini Enterprise OAuth passthrough enforces per-user access control so analysts only query Google SecOps data permitted by their own IAM and SOAR roles.

### Architecture

1. **Authorization Resource**: `just oauth-create-auth` registers an OAuth 2.0 configuration in Google Cloud Discovery Engine (`projects.locations.authorizations`) with the OAuth Client ID, Client Secret, `https://www.googleapis.com/auth/chronicle` scope, and optional RFC 7636 PKCE verification (`pkceVerificationEnabled`).
2. **Agent Registration**: `just agentspace-register` (or `just run agentspace register`) links the deployed Vertex AI Reasoning Engine with the Gemini Enterprise app and attaches the Discovery Engine authorization resource in `authorization_config.tool_authorizations`.
3. **UI Sign-In Orchestration**: When a user chats with the agent in Gemini Enterprise, Gemini Enterprise redirects the browser through the registered `authorizationUri` and exchanges the authorization code for an OAuth access token.
4. **Token Handoff**: Gemini Enterprise forwards the user's OAuth access token to Vertex AI Agent Engine in the request authorization context.
5. **Session State Injection**: Vertex AI Agent Engine injects the token into `context.state` under `temp:{auth_id}` (or `{auth_id}`).
6. **Header Provider**: `get_secops_headers` reads the user token from `context.state` and attaches `Authorization: Bearer <token>` and `x-goog-user-project: <CHRONICLE_PROJECT_ID>` to outgoing MCP requests.

### Implementation Note

The agent does not enable ADK's interactive `auth_scheme` (`adk_request_credential`) loop because Gemini Enterprise completes the OAuth 2.0 consent flow before invoking the Reasoning Engine. Instead, `get_secops_headers` consumes the pre-authorized token injected into session state.
