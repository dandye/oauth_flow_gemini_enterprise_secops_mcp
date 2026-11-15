# Architecture overview

## System overview

This repository deploys a Google Agent Development Kit (ADK) 2.x agent to Vertex AI Agent Engine (`ReasoningEngine`) and registers it with Gemini Enterprise (`DiscoveryEngine`). At runtime, Gemini Enterprise forwards the signed-in user's OAuth 2.0 access token in session state so the agent authenticates requests to the Google Security Operations (SecOps) remote Model Context Protocol (MCP) server (`https://<REGION>-chronicle.googleapis.com/mcp`, or an explicit `SECOPS_MCP_URL` override) as that user.

When `GEMINI_AUTHORIZATION_ID` or `OAUTH_AUTH_ID` is configured, `get_secops_headers()` requires a delegated user token in `context.state` (`temp:<auth_id>` or `<auth_id>`) and skips Application Default Credentials (ADC) unless `SECOPS_ALLOW_ADC_FALLBACK=true` is explicitly set for local CLI testing.

## Component boundaries

- `src/oauth_flow_gemini_enterprise_secops_mcp/`: Core endpoint helpers (`core.py`), unified management CLI (`cli.py`), and provisioning modules for Vertex AI Agent Engine (`agent_engine.py`), Gemini Enterprise (`agentspace.py`), OAuth 2.0 authorization resources (`oauth.py`), IAM verification (`iam.py`), Secret Manager (`secret.py`), Vertex AI APIs (`vertex_ai.py`), and environment validation (`env_validation.py`).
- `secops_agent/`: ADK 2.x runtime package (`secops_agent_app/agent.py`) defining `SecOpsMcpToolset`, `get_secops_headers`, `strip_mcp_output_schemas`, `create_mcp_toolset`, `create_agent`, and `create_app`.
- `tests/`: Hermetic unit test suites covering CLI commands, Google SecOps MCP endpoint resolution, OAuth header guards, schema stripping, tool filtering, and planner configuration.
- `docs/`: Architectural decision records (`DESIGN_SPEC.md`), architecture overview (`architecture.md`), and operator setup instructions (`setup.md`).
