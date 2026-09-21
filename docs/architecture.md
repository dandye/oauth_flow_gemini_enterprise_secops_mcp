# Architecture Overview - oauth_flow_gemini_enterprise_secops_mcp

## System Overview
This repository provides a Google ADK agent deployed on Vertex AI Agent Engine (`ReasoningEngine`) and integrated with Gemini Enterprise (`DiscoveryEngine`), utilizing OAuth passthrough to authenticate requests to the Google Cloud Remote MCP Server for SecOps (`https://chronicle.<REGION>.rep.googleapis.com/mcp`) as the logged-in end-user.

## Component Boundaries
- `src/oauth_flow_gemini_enterprise_secops_mcp/`: Core configuration utilities, unified management CLI (`cli.py`), and domain modules (`agent_engine.py`, `agentspace.py`, `oauth.py`, `iam.py`, `vertex_ai.py`, `secret.py`, `env_validation.py`, `auth_uri.py`).
- `secops_agent/`: ADK 2.x agent package containing `get_secops_headers`, `create_mcp_toolset`, `create_agent`, and `create_app`.
- `tests/`: Unit test suites validating CLI, core utilities, OAuth header injection, and MCP toolset configuration.
- `docs/`: Architectural decision records (`DESIGN_SPEC.md`, `architecture.md`) and setup documentation (`setup.md`).
