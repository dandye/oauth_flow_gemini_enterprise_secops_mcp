# secops_agent

Google Security Operations (SecOps) Remote MCP Agent built with the Google Agent Development Kit (`google-adk`).

## Package Structure

```text
secops_agent/
|-- __init__.py
|-- AGENTS.md                  # AI-assisted development guidelines
|-- README.md                  # Package overview and commands
|-- ruff.toml                  # Ruff lint configuration inheriting ../pyproject.toml
'-- secops_agent_app/
    |-- __init__.py
    |-- agent.py               # ADK Agent & App factories (create_agent, create_app)
    '-- app_utils/
        |-- __init__.py
        |-- telemetry.py       # OpenTelemetry and GenAI logging helpers
        '-- typing.py          # Feedback Pydantic schema
```

## Core Entrypoints (`secops_agent_app/agent.py`)

- `create_agent() -> google.adk.agents.Agent`: Builds the SecOps ADK `Agent` connected to the remote Google Security Operations (SecOps) MCP server via `McpToolset`, forwarding per-user OAuth bearer tokens from Gemini Enterprise (`GEMINI_AUTHORIZATION_ID` / `OAUTH_AUTH_ID`), filtering high-volume feed/parser tools (`DISABLED_SECOPS_TOOLS`), and enforcing optional human-in-the-loop confirmation on destructive tools (`confirm_destructive_secops_tool`).
- `create_app() -> google.adk.apps.App`: Wraps `create_agent()` in an ADK `App` container configured with `EventsCompactionConfig`, `ResumabilityConfig`, and conditional `ContextCacheConfig` for deployment to Vertex AI Agent Engine (`AdkApp`).

## Root Task Runner Commands

Run all development, testing, and deployment workflows from the repository root using the root [justfile](../justfile):

| Command | Description |
| --- | --- |
| `just setup` | Create `.env` from `.env.example` and synchronize `uv` dependencies |
| `just sync` | Synchronize virtual environment dependencies via `uv` |
| `just test` | Run hermetic unit tests with `pytest` |
| `just lint` | Run `ruff` and `pyink --check` code quality checks |
| `just format` | Format code in-place with `ruff --fix` and `pyink` |
| `just typecheck` | Run static type checking with `pytype` |
| `just agent-engine-deploy` | Deploy `secops_agent` to Vertex AI Agent Engine |
| `just agent-engine-update` | Update an existing Vertex AI Agent Engine deployment |
| `just agent-engine-test` | Send a test query to the deployed Agent Engine |
| `just gemini-enterprise-link-agent` | Link the deployed Agent Engine to Gemini Enterprise with OAuth |

To launch the local ADK web playground from the repository root:

```bash
uv run adk web secops_agent --port 8501
```
