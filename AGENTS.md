# AGENTS.md

Guidance for coding assistants and contributors working in this repository.

## Runtime and toolchain

- **Python**: Target Python **3.12** for local development, static analysis, and GitHub Actions CI (`uv python install 3.12`, `uv sync --python 3.12 --all-groups --frozen`). `pyproject.toml` maintains `requires-python = ">=3.11"` for downstream package compatibility.
- **Package management**: Always manage virtual environments and dependencies through `uv` and `uv.lock` resolved from the public PyPI index (`https://pypi.org/simple`). Never add unpinned package installation commands in scripts or CI workflows.
- **Task runner**: Use `just` (`just --list`) with `set positional-arguments := true` so quoted arguments containing spaces pass through to `"$@"` intact.

## Google Python Style Guide standards

This repository enforces the Google Python Style Guide:
- **Indentation (Section 3.4)**: Use 2 spaces per indentation level. Never use tabs.
- **Line length (Section 3.2)**: Maximum 80 characters per line.
- **Formatter**: Format with `pyink` (`--pyink-indentation 2`) and lint with `ruff`.
- **Docstrings (Section 3.8)**: Use Google docstring sections (`Args:`, `Returns:`, `Raises:`). Test functions are exempt (Section 3.8.2.1).
- **Logging (Section 3.10.1)**: Never use f-strings in logging calls. Pass `%s` format placeholders (`logger.info("Value is %s", val)`).
- **Imports (Section 3.13)**: Use single-line module imports without parentheses, sorted by Ruff (`force-single-line = true`).
- **Static typing**: Check `src/` with `pytype` using the `.venv` Python 3.12 interpreter (`PATH="$PWD/.venv/bin:$PATH" uv run pytype src` or `just typecheck`).

## Public repository hygiene and style

- **Zero emojis or decorative symbols**: Never place emojis, decorative Unicode symbols, or em-dashes in code, comments, documentation, commit messages, pull request descriptions, or review comments. Keep source and documentation files clean ASCII.
- **Public-safe examples and identifiers**: Use generic placeholder values in documentation, tests, and templates, such as `your-gcp-project-id`, `123456789012`, and the RFC 4122 UUID `a1b2c3d4-e5f6-4321-abcd-ef1234567890`.
- **No private environment details**: Never commit `.env` files, `.gcloud` credentials, service account keys, local workstation filesystem paths, private corporate hostnames or proxy URLs, internal issue tracker shortlinks, or non-public codenames.
- **GitHub Actions hardening**: Every workflow in `.github/workflows/` must declare least-privilege `permissions: contents: read` and pin every `uses:` action to a full 40-character lowercase commit SHA with an inline release tag comment.
- **Shell examples**: Define environment variables before referencing them (`PROJECT_ID="your-gcp-project-id"`, then `"$PROJECT_ID"`).

## Git worktree and path conventions

- Keep sibling linked worktrees under `oauth_flow_gemini_enterprise_secops_mcp__worktrees/` rather than committing directly on `main`.
- Resolve repository-internal paths relative to `Path(__file__).resolve().parents[...]` so code and tests behave identically from any sibling worktree.
- Stage modified files by explicit path after reviewing `git status` and `git diff`.

## Project structure

```text
.
+-- .env.example          # Environment variable template
+-- .gitignore            # Git ignore configuration
+-- .github/
|   +-- workflows/
|       +-- ci.yml        # GitHub Actions CI (SHA-pinned, Python 3.12)
+-- AGENTS.md             # Contributor and coding assistant guidelines
+-- README.md             # Project overview and quickstart
+-- justfile              # Grouped task runner recipes
+-- pyproject.toml        # PEP 621 metadata, PEP 735 groups, Ruff/Pyink/Pytype config
+-- uv.lock               # Deterministic PyPI dependency lockfile
+-- docs/                 # Architecture and setup documentation
|   +-- DESIGN_SPEC.md
|   +-- architecture.md
|   +-- setup.md
+-- scripts/
|   +-- setup_env.sh      # Environment bootstrap using uv sync --frozen
+-- secops_agent/         # Google SecOps MCP ADK agent package for Agent Engine
|   +-- secops_agent_app/
+-- src/
|   +-- oauth_flow_gemini_enterprise_secops_mcp/
|       +-- __init__.py
|       +-- __main__.py
|       +-- agent_engine.py   # Vertex AI Agent Engine deployment and management
|       +-- agentspace.py     # Gemini Enterprise registration and OAuth linking
|       +-- cli.py            # Unified Typer CLI entrypoint
|       +-- core.py           # Core endpoint and pipeline helpers
|       +-- env_validation.py # Environment configuration validation
|       +-- iam.py            # Service agent IAM role management
|       +-- oauth.py          # Discovery Engine OAuth authorization management
|       +-- py.typed          # PEP 561 marker
|       +-- secret.py         # Secret Manager credential helpers
|       +-- vertex_ai.py      # Vertex AI API and permission checks
+-- tests/                # Hermetic pytest unit and repository hygiene suites
```

## Common commands

| Group | Command | Description |
| :--- | :--- | :--- |
| `setup` | `just setup` | Create `.env` from `.env.example` if absent and sync `uv` dependencies |
| `setup` | `just sync` | Synchronize `.venv` with all dependency groups via `uv sync --all-groups` |
| `setup` | `just clean` | Remove bytecode, test caches, coverage artifacts, and build directories |
| `quality` | `just test` | Run pytest suite (`just test -k "expr"` forwards arguments intact) |
| `quality` | `just test-cov` | Run pytest with terminal and HTML coverage reports |
| `quality` | `just format` | Apply Ruff fixes and format in place with Pyink |
| `quality` | `just format-check` | Verify Pyink formatting without modifying files |
| `quality` | `just lint` | Run Ruff lint checks and Pyink format verification |
| `quality` | `just typecheck` | Run Pytype against `src/` with `.venv/bin` on `PATH` |
| `agent-engine` | `just agent-engine-deploy` | Deploy the Google SecOps MCP ADK agent to Vertex AI Agent Engine |
| `agent-engine` | `just agent-engine-update` | Update an existing Agent Engine deployment in place |
| `agent-engine` | `just agent-engine-test` | Run a smoke query against the deployed Agent Engine |
| `gemini-enterprise` | `just gemini-enterprise-register` | Register the deployed agent with Gemini Enterprise |
| `gemini-enterprise` | `just gemini-enterprise-link-agent` | Link the deployed agent to Gemini Enterprise with OAuth |
| `gemini-enterprise` | `just gemini-enterprise-update` | Update Gemini Enterprise agent settings |
| `gemini-enterprise` | `just gemini-enterprise-verify` | Verify Gemini Enterprise agent registration status |
| `gemini-enterprise` | `just gemini-enterprise-url` | Print the Gemini Enterprise console URL |
| `oauth` | `just oauth-setup <file>` | Configure OAuth client settings from `client_secret.json` |
| `oauth` | `just oauth-create-auth` | Create the Discovery Engine OAuth authorization resource |
| `oauth` | `just oauth-verify` | Verify Discovery Engine OAuth authorization status |
| `secret` | `just secret-upload` | Upload Google Security Operations credentials to Secret Manager |
| `vertex-ai` | `just vertex-ai-verify` | Check Vertex AI APIs, authentication, and IAM readiness |
| `iam` | `just iam-setup` | Grant required IAM roles to Reasoning Engine and Discovery Engine agents |
| `workflow` | `just run info` | Run the unified CLI with arbitrary subcommands |
| `workflow` | `just workflow-full-deploy` | Guided end-to-end Agent Engine, OAuth, and Gemini Enterprise workflow |
| `workflow` | `just workflow-redeploy-all` | Guided Agent Engine redeployment and Gemini Enterprise update |
| `workflow` | `just workflow-status` | Check overall environment and Gemini Enterprise agent status |
