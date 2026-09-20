# secops_agent

SecOps Remote MCP ReAct Agent built with Google ADK (`google-adk`).

## Project Structure

```text
secops_agent/
├── secops_agent_app/          # Core agent package
│   ├── agent.py               # Main ADK LlmAgent & McpToolset logic
│   ├── agent_engine_app.py    # Vertex AI Agent Engine application wrapper
│   └── app_utils/             # Deployment and telemetry utilities
├── tests/                     # Unit, integration, and eval tests
├── AGENTS.md                  # AI-assisted development guide
├── justfile                   # Task runner commands
└── pyproject.toml             # Sub-package metadata and configuration
```

## Quick Start

Install required packages and launch the local development playground from the repository root or `secops_agent/`:

```bash
just install && just playground
```

## Commands

| Command | Description |
| --- | --- |
| `just install` | Install dependencies using `uv` |
| `just playground` | Launch local ADK web playground |
| `just lint` | Run code quality checks (`ruff` and `pyink`) |
| `just format` | Format code (`ruff --fix` and `pyink`) |
| `just test` | Run unit and integration tests |
| `just eval` | Run ADK agent evaluation |
| `just deploy` | Deploy agent to Vertex AI Agent Engine |
| `just register-gemini-enterprise` | Register deployed agent with Gemini Enterprise |

For full command options and usage, refer to [justfile](justfile) or the root [justfile](../justfile).
