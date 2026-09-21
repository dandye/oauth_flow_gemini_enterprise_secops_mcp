set dotenv-load := true

# Default environment file
env_file := ".env"

# Default recipe: list available commands
default:
  @just --list

# ------------------------------------------------------------------------------
# Setup & Environment Management
# ------------------------------------------------------------------------------

# Setup local environment (.env from template and sync uv dependencies)
setup:
  #!/usr/bin/env bash
  set -e
  if [ ! -f "{{ env_file }}" ]; then
    echo "Creating {{ env_file }} from template..."
    cp .env.example "{{ env_file }}"
    echo "Created {{ env_file }} - please update values as needed."
  fi
  just sync

# Synchronize virtual environment and lock dependencies via uv
sync:
  uv sync --all-groups

# ------------------------------------------------------------------------------
# Quality & Testing (Google Python Style Guide)
# ------------------------------------------------------------------------------

# Run unit tests with pytest
test *args="":
  uv run pytest {{ args }}

# Run tests with coverage report
test-cov:
  uv run pytest --cov=src --cov-report=term-missing --cov-report=html

# Check formatting with Pyink (Google Style: 2-space, 80-col)
format-check:
  uv run pyink --check --diff .

# Format code in-place with Pyink and apply Ruff fixes
format:
  uv run ruff check --fix .
  uv run pyink .

# Lint code against Google Python Style Guide
lint:
  uv run ruff check .
  uv run pyink --check .

# Static type analysis with Google Pytype
typecheck:
  uv run pytype src

# ------------------------------------------------------------------------------
# Execution & CLI Helpers
# ------------------------------------------------------------------------------

# Run project CLI
run *args="":
  uv run oauth-flow-gemini-enterprise-secops-mcp {{ args }}

# Deploy agent engine to Vertex AI
agent-engine-deploy agent_module="agent":
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine deploy --agent-module {{ agent_module }}

# Update existing agent engine in-place
agent-engine-update agent_module="agent":
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine update --agent-module {{ agent_module }}

# Test deployed agent engine
agent-engine-test *args="":
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine test {{ args }}

# Warmup deployed agent engine MCP connections
agent-engine-warmup:
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine warmup

# List deployed agent engine instances
agent-engine-list:
  uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine list

# Register agent with Gemini Enterprise (AgentSpace)
agentspace-register *args="":
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace register {{ args }}

# Link deployed agent to Gemini Enterprise (AgentSpace) with OAuth
agentspace-link-agent:
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace link-agent

# Update Gemini Enterprise (AgentSpace) agent configuration
agentspace-update:
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace update

# Verify Gemini Enterprise (AgentSpace) agent status
agentspace-verify:
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace verify

# Display Gemini Enterprise (AgentSpace) UI URL
agentspace-url:
  uv run oauth-flow-gemini-enterprise-secops-mcp agentspace url

# Interactive OAuth client setup from client_secret.json
oauth-setup client_secret:
  uv run oauth-flow-gemini-enterprise-secops-mcp oauth setup {{ client_secret }}

# Create OAuth authorization in Discovery Engine
oauth-create-auth:
  uv run oauth-flow-gemini-enterprise-secops-mcp oauth create-auth

# Verify OAuth authorization status
oauth-verify:
  uv run oauth-flow-gemini-enterprise-secops-mcp oauth verify

# Upload Chronicle service account credentials to Secret Manager
secret-upload *args="":
  uv run oauth-flow-gemini-enterprise-secops-mcp secret upload {{ args }}

# Verify Secret Manager credentials
secret-verify *args="":
  uv run oauth-flow-gemini-enterprise-secops-mcp secret verify {{ args }}

# Verify Vertex AI APIs, auth, and permissions
vertex-ai-verify:
  uv run oauth-flow-gemini-enterprise-secops-mcp vertex verify

# Enable required Vertex AI APIs
vertex-ai-enable-apis:
  uv run oauth-flow-gemini-enterprise-secops-mcp vertex enable-apis

# Configure IAM permissions for Reasoning Engine and Discovery Engine service agents
iam-setup:
  uv run oauth-flow-gemini-enterprise-secops-mcp iam setup

# Verify IAM permissions for service agents
iam-verify:
  uv run oauth-flow-gemini-enterprise-secops-mcp iam verify

# Complete end-to-end deployment workflow with OAuth and AgentSpace linking
full-deploy-with-oauth:
  uv run oauth-flow-gemini-enterprise-secops-mcp workflow full-deploy

# Redeploy Agent Engine and update AgentSpace configuration
redeploy-all:
  uv run oauth-flow-gemini-enterprise-secops-mcp workflow redeploy-all

# Check overall system status
status:
  uv run oauth-flow-gemini-enterprise-secops-mcp workflow status

# Clean build artifacts, bytecode, and test caches
clean:
  find . -type f -name "*.pyc" -delete
  find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  rm -rf .pytest_cache .pytype .mypy_cache .ruff_cache .coverage htmlcov dist build *.egg-info
