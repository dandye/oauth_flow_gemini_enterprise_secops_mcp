# Architecture Overview - oauth_flow_gemini_enterprise_secops_mcp

## System Overview
This repository provides a Google ADK agent deployed on Vertex AI Agent Engine (`ReasoningEngine`) and integrated with Gemini Enterprise (`DiscoveryEngine`), utilizing OAuth passthrough to authenticate requests to the Google Cloud Remote MCP Server for SecOps (`https://chronicle.<REGION>.rep.googleapis.com/mcp`) as the logged-in end-user.

## Component Boundaries
- `src/oauth_flow_gemini_enterprise_secops_mcp/`: Core configuration utilities and unified management CLI (`cli.py`).
- `secops_agent/`: ADK agent package containing `get_secops_headers`, `create_mcp_toolset`, and `create_agent`.
- `installation_scripts/`: Deployment and lifecycle automation for Vertex AI Agent Engine, Gemini Enterprise (AgentSpace), OAuth authorizations, and IAM.
- `tests/`: Unit test suites validating CLI, core utilities, OAuth header injection, and MCP toolset configuration.
- `docs/`: Architectural decision records and setup documentation.
