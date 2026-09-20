# Coding Agent Guide (`secops_agent`)

## Reference Documentation

If you have ADK skills available, use those instead of fetching the URLs below.

Otherwise, reference these resources in `../external/agent-starter-pack/` or online:
- **ADK Cheatsheet**: `../external/agent-starter-pack/agent_starter_pack/resources/docs/adk-cheatsheet.md`
- **Evaluation Guide**: `../external/agent-starter-pack/agent_starter_pack/resources/docs/adk-eval-guide.md`
- **Deployment Guide**: `../external/agent-starter-pack/agent_starter_pack/resources/docs/adk-deploy-guide.md`
- **Development Guide**: `../external/agent-starter-pack/docs/guide/development-guide.md`
- **ADK Docs**: https://google.github.io/adk-docs/llms.txt

---

## Development Phases

### Phase 1: Understand Requirements
Before writing any code, understand the project's requirements, constraints, and success criteria.

### Phase 2: Build and Implement
Implement agent logic in `secops_agent_app/`. Use `just playground` for interactive testing. Iterate based on user feedback.

### Phase 3: The Evaluation Loop (Main Iteration Phase)
Start with 1-2 eval cases, run `just eval`, iterate. Expect 5-10+ iterations. See the **Evaluation Guide** for metrics, evalset schema, LLM-as-judge config, and common gotchas.

### Phase 4: Pre-Deployment Tests
Run `just test`. Fix issues until all tests pass.

### Phase 5: Deploy to Dev
**Requires explicit human approval.** Run `just deploy` (or `just agent-engine-deploy` from repository root) only after user confirms.

## Development Commands

| Command | Purpose |
| --- | --- |
| `just playground` | Interactive local testing |
| `just test` | Run unit and integration tests |
| `just eval` | Run evaluation against evalsets |
| `just eval-all` | Run all evalsets |
| `just lint` | Check code quality |
| `just format` | Format code (`ruff` + `pyink`) |
| `just deploy` | Deploy to Vertex AI Agent Engine |

---

## Operational Guidelines for Coding Agents

- **Style**: Follow the Google Python Style Guide (2-space indentation, 80-column line length, Pyink formatting, Google docstrings, `%s` logging placeholders).
- **Never use emojis** anywhere in code, comments, documentation, logs, or commit messages.
- **Code preservation**: Only modify code directly targeted by the user's request. Preserve all surrounding code, config values (e.g., `model`), comments, and formatting.
- **Run Python with `uv`**: `uv run python script.py`. Run `just install` first.
