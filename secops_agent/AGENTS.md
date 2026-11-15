# Coding Agent Guide (`secops_agent`)

## Reference Documentation

- **ADK Documentation**: https://google.github.io/adk-docs/
- **Package Overview**: [README.md](README.md)
- **Root Task Runner**: [../justfile](../justfile)

---

## Development Workflow

1. **Understand Requirements**: Review `secops_agent_app/agent.py` (`create_agent()` and `create_app()`) and root CLI integration in `src/oauth_flow_gemini_enterprise_secops_mcp/` before making changes.
2. **Implement & Test Locally**: Add or update hermetic unit tests under `tests/` at the repository root and run `just test`.
3. **Verify Style & Types**: Run `uv run ruff check . secops_agent`, `uv run pyink --check --diff . secops_agent`, and `just typecheck` from the repository root.
4. **Deploy (Requires Explicit User Approval)**: Deploy or update Vertex AI Agent Engine from the repository root with `just agent-engine-deploy` or `just agent-engine-update`.

## Operational Guidelines

- **Style**: Follow the Google Python Style Guide (2-space indentation, 80-column line length, Pyink formatting, Google docstrings, `%s` logging placeholders).
- **Hygiene**: Never include emojis, decorative Unicode symbols, em-dashes, or internal environment references in code, comments, documentation, logs, or commit messages.
- **Dependencies**: Manage all dependencies through the root `pyproject.toml` and `uv.lock` using `uv`.
