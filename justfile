set dotenv-load := true
set positional-arguments := true

# Default environment file
env_file := ".env"

# Default recipe: list available commands
[private]
[group('setup')]
default:
  @just --list

# ------------------------------------------------------------------------------
# Setup and Environment Management
# ------------------------------------------------------------------------------

# Initialize local .env from template and synchronize uv dependencies
[group('setup')]
setup:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -f "{{ env_file }}" ]; then
    echo "Creating {{ env_file }} from template..."
    cp .env.example "{{ env_file }}"
    echo "Created {{ env_file }}. Update placeholder values before deploying."
  fi
  just sync

# Synchronize virtual environment and dependency groups via uv
[group('setup')]
sync:
  uv sync --all-groups

# Clean build artifacts, bytecode, and test caches
[group('setup')]
clean:
  find . -type f -name "*.pyc" -delete
  find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  rm -rf .pytest_cache .pytype .mypy_cache .ruff_cache .coverage htmlcov dist build *.egg-info

# ------------------------------------------------------------------------------
# Quality and Testing (Google Python Style Guide)
# ------------------------------------------------------------------------------

# Run unit tests with pytest
[group('quality')]
test *args:
  uv run pytest "$@"

# Run tests with coverage report
[group('quality')]
test-cov:
  uv run pytest --cov=src --cov-report=term-missing --cov-report=html

# Check formatting with Pyink (Google Style: 2-space, 80-col)
[group('quality')]
format-check:
  uv run pyink --check --diff .

# Format code in-place with Pyink and apply Ruff fixes
[group('quality')]
format:
  uv run ruff check --fix .
  uv run pyink .

# Lint code against Google Python Style Guide
[group('quality')]
lint:
  uv run ruff check .
  uv run pyink --check .

# Static type analysis with Google Pytype using the .venv interpreter
[group('quality')]
typecheck:
  PATH="$PWD/.venv/bin:$PATH" uv run pytype src

# ------------------------------------------------------------------------------
# Vertex AI Agent Engine
# ------------------------------------------------------------------------------

# Deploy agent engine to Vertex AI
[group('agent-engine')]
agent-engine-deploy agent_module="agent":
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine deploy --agent-module "$1"

# Update existing agent engine in-place
[group('agent-engine')]
agent-engine-update agent_module="agent":
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine update --agent-module "$1"

# Test deployed agent engine
[group('agent-engine')]
agent-engine-test *args:
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine test "$@"

# Warmup deployed agent engine MCP connections
[group('agent-engine')]
agent-engine-warmup:
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine warmup

# List deployed agent engine instances
[group('agent-engine')]
agent-engine-list:
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine list

# ------------------------------------------------------------------------------
# Gemini Enterprise Registration and Linking
# ------------------------------------------------------------------------------

# Register agent with Gemini Enterprise
[group('gemini-enterprise')]
gemini-enterprise-register *args:
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace register "$@"

alias agentspace-register := gemini-enterprise-register

# Link deployed agent to Gemini Enterprise with OAuth
[group('gemini-enterprise')]
gemini-enterprise-link-agent:
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace link-agent

alias agentspace-link-agent := gemini-enterprise-link-agent

# Update Gemini Enterprise agent configuration
[group('gemini-enterprise')]
gemini-enterprise-update:
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace update

alias agentspace-update := gemini-enterprise-update

# Verify Gemini Enterprise agent status
[group('gemini-enterprise')]
gemini-enterprise-verify:
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace verify

alias agentspace-verify := gemini-enterprise-verify

# Display Gemini Enterprise console URL
[group('gemini-enterprise')]
gemini-enterprise-url:
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace url

alias agentspace-url := gemini-enterprise-url

# ------------------------------------------------------------------------------
# OAuth Authorization Management
# ------------------------------------------------------------------------------

# Interactive OAuth client setup from client_secret.json
[group('oauth')]
oauth-setup *args:
  uv run oauth-flow-gemini-enterprise-secops-mcp oauth setup "$@"

# Create OAuth authorization in Discovery Engine
[group('oauth')]
oauth-create-auth *args:
  uv run oauth-flow-gemini-enterprise-secops-mcp oauth create-auth "$@"

# Verify OAuth authorization status
[group('oauth')]
oauth-verify *args:
  uv run oauth-flow-gemini-enterprise-secops-mcp oauth verify "$@"

# ------------------------------------------------------------------------------
# Secret Manager Credentials
# ------------------------------------------------------------------------------

# Upload Google Security Operations service account credentials to Secret Manager
[group('secret')]
secret-upload *args:
  uv run oauth-flow-gemini-enterprise-secops-mcp secret upload "$@"

# Verify Secret Manager credentials
[group('secret')]
secret-verify *args:
  uv run oauth-flow-gemini-enterprise-secops-mcp secret verify "$@"

# ------------------------------------------------------------------------------
# Vertex AI Configuration
# ------------------------------------------------------------------------------

# Verify Vertex AI APIs, authentication, and permissions
[group('vertex-ai')]
vertex-ai-verify:
  uv run oauth-flow-gemini-enterprise-secops-mcp vertex verify

# Enable required Vertex AI APIs
[group('vertex-ai')]
vertex-ai-enable-apis:
  uv run oauth-flow-gemini-enterprise-secops-mcp vertex enable-apis

# ------------------------------------------------------------------------------
# IAM Service Agent Configuration
# ------------------------------------------------------------------------------

# Configure IAM permissions for Reasoning Engine and Discovery Engine service agents
[group('iam')]
iam-setup:
  uv run oauth-flow-gemini-enterprise-secops-mcp iam setup

# Verify IAM permissions for service agents
[group('iam')]
iam-verify *args:
  uv run oauth-flow-gemini-enterprise-secops-mcp iam verify "$@"

# ------------------------------------------------------------------------------
# Workflows and CLI Execution
# ------------------------------------------------------------------------------

# Run project CLI with arbitrary arguments
[group('workflow')]
run *args:
  uv run oauth-flow-gemini-enterprise-secops-mcp "$@"

# Complete end-to-end deployment workflow with OAuth and Gemini Enterprise linking
[group('workflow')]
workflow-full-deploy:
  uv run oauth-flow-gemini-enterprise-secops-mcp workflow full-deploy

alias full-deploy-with-oauth := workflow-full-deploy

# Redeploy Agent Engine and update Gemini Enterprise configuration
[group('workflow')]
workflow-redeploy-all:
  uv run oauth-flow-gemini-enterprise-secops-mcp workflow redeploy-all

alias redeploy-all := workflow-redeploy-all

# Check overall deployment status
[group('workflow')]
workflow-status:
  uv run oauth-flow-gemini-enterprise-secops-mcp workflow status

alias status := workflow-status
