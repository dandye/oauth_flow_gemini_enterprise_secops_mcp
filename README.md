# Gemini Enterprise SecOps MCP OAuth Deployment

Google SecOps Remote MCP ADK Agent (`google-adk>=2.0.0`) with Gemini Enterprise OAuth Passthrough.

- **Interactive Colab Guide**: [SecOps remote MCP OAuth flow](https://colab.research.google.com/drive/1Q4fCimoRiUBkAwEG2EHmfe1z-FxQ5sWw)
- **Style & Tooling**: Adheres to the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html) (2-space indentation, 80-column line limit, Pyink formatter, Pytype static analyzer).

## Quickstart

```bash
# Setup environment and sync dependencies
just setup

# Run test suite
just test

# Check formatting, lint, and static types
just lint
just typecheck

# Run CLI info command
just run info
# or
uv run oauth-flow-gemini-enterprise-secops-mcp info
```

---

## High-Level Deployment Workflow

1. **Deploy Agent to Vertex AI Agent Engine**: Containerize and deploy the ADK agent to Vertex AI Reasoning Engine.
2. **Configure Local Environment**: Update your `.env` file with the generated Reasoning Engine resource name.
3. **Generate GCP Client Secret**: Configure your GCP project and download the OAuth Web application client secret JSON.
4. **Setup OAuth Credentials**: Generate the local OAuth Authorization configuration properties using your client secret.
5. **Create OAuth Authorization**: Register the OAuth credentials with the Discovery Engine control plane.
6. **Create Gemini Enterprise App**: Initialize the application container within Gemini Enterprise.
7. **Register Agent with Enterprise**: Associate your Reasoning Engine with your Gemini Enterprise App.

---

## 1. Deploy Agent to Vertex AI

Populate `.env` with your tenancy variables:

```env
GCP_PROJECT_ID="your-gcp-project-id"
GCP_PROJECT_NUMBER="123456789012"
GCP_LOCATION="us-central1"
GCP_STAGING_BUCKET="gs://your-staging-bucket"
CHRONICLE_PROJECT_ID="your-chronicle-project-id"
CHRONICLE_CUSTOMER_ID="00000000-0000-0000-0000-000000000000"
CHRONICLE_REGION="us"

OAUTH_AUTH_ID="gement-onemcp-auth-passthrough-v1"
GEMINI_AUTHORIZATION_ID="gement-onemcp-auth-passthrough-v1"
```

Deploy via `just` or `uv run`:

```bash
just agent-engine-deploy
# or
uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine deploy --agent-module agent
```

## 2. Configure Local Environment

Save the printed Reasoning Engine resource name into `.env`:

```env
AGENT_ENGINE_RESOURCE_NAME="projects/[PROJECT_NUMBER]/locations/us-central1/reasoningEngines/[ENGINE_ID]"
```

## 3. Generate GCP Client Secret

1. Navigate to **APIs & Services > Credentials** in the Google Cloud Console for `GCP_PROJECT_ID`.
2. Click **Create Credentials > OAuth client ID**.
3. Select **Web application**.
4. Under **Authorized redirect URIs**, add: `https://vertexaisearch.cloud.google.com/oauth-redirect`
5. Click **Create** and download the JSON file.

![Create OAuth Client ID](docs/client_id_for_web_application.png "Create OAuth Client ID in Google Cloud Console")

## 4. Setup OAuth Credentials

```bash
CLIENT_SECRET_JSON="path/to/client_secret.json"

just run oauth setup "$CLIENT_SECRET_JSON" \
  --scopes "https://www.googleapis.com/auth/chronicle,https://www.googleapis.com/auth/cloud-platform,openid"
```

## 5. Create OAuth Authorization

```bash
YOUR_OAUTH_AUTH_ID="gement-onemcp-auth-passthrough-v1"

just run oauth create-auth --auth-id "$YOUR_OAUTH_AUTH_ID"
```

## 6. Create Gemini Enterprise App

```bash
just run agentspace create-app \
  --name "SecOps Agent" \
  --app-type APP_TYPE_INTRANET \
  --industry-vertical GENERIC \
  --no-datastore
```

## 7. Register Agent with Gemini Enterprise

```bash
AGENT_ENGINE_ID="projects/[PROJECT_NUMBER]/locations/[LOCATION]/reasoningEngines/[ENGINE_ID]"
APP_ID="[APP_ID]"

just run agentspace register \
  --agent-engine-id "$AGENT_ENGINE_ID" \
  --app-id "$APP_ID" \
  --force
```

## 8. Redeploying or Testing the Agent

```bash
# Update deployed agent in-place
just agent-engine-update

# Run test query against deployed agent engine
just agent-engine-test
```
