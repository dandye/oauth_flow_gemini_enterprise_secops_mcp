# Gemini Enterprise SecOps MCP OAuth Deployment

Google Security Operations (SecOps) remote MCP ADK agent (`google-adk>=2.0.0`) deployed on Vertex AI Agent Engine with Gemini Enterprise OAuth passthrough.

- **Interactive Colab Guide**: [SecOps remote MCP OAuth flow](https://colab.research.google.com/drive/1Q4fCimoRiUBkAwEG2EHmfe1z-FxQ5sWw)
- **Style & Tooling**: Follows the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html) with 2-space indentation, 80-column line limit, Pyink formatter, Ruff linter, and Pytype static type checker.
- **Setup & Troubleshooting Guide**: [docs/setup.md](docs/setup.md)

## Quickstart

```bash
# Initialize .env and sync dependencies into .venv
just setup

# Run unit tests
just test

# Check formatting, lint rules, and static types
just lint
just typecheck

# Display CLI status
just run info
# or
uv run oauth-flow-gemini-enterprise-secops-mcp info
```

---

## IAM & SOAR User Prerequisites

Before testing end-user OAuth flows in Gemini Enterprise, configure both the Google Cloud IAM bindings and Google Security Operations user access rules below.

### 1. Google Cloud IAM Roles on `CHRONICLE_PROJECT_ID`

Each authorizing end user who signs in through Gemini Enterprise invokes the remote Google SecOps MCP endpoint (`https://{region}-chronicle.googleapis.com/mcp`) using their own OAuth bearer token, with `CHRONICLE_PROJECT_ID` passed in the `x-goog-user-project` header. Grant each end user these three IAM roles on `CHRONICLE_PROJECT_ID`:

- `roles/mcp.toolUser` (`mcp.googleapis.com/tools.call`) to invoke remote MCP tools.
- `roles/chronicle.viewer` (or `roles/chronicle.editor` / `roles/chronicle.admin`) to read or manage Google SecOps data.
- `roles/serviceusage.serviceUsageConsumer` to consume API quota on the project passed in `x-goog-user-project`.

```bash
CHRONICLE_PROJECT_ID="your-chronicle-project-id"
USER_EMAIL="analyst@example.com"

for ROLE in \
  "roles/mcp.toolUser" \
  "roles/chronicle.viewer" \
  "roles/serviceusage.serviceUsageConsumer"; do
  gcloud projects add-iam-policy-binding "$CHRONICLE_PROJECT_ID" \
    --member="user:$USER_EMAIL" \
    --role="$ROLE"
done

# Verify service agent bindings and end-user SecOps MCP roles
just run iam verify --principal "$USER_EMAIL"
```

In addition, grant the Vertex AI Reasoning Engine and Discovery Engine Google-managed service agents their required roles on `GCP_PROJECT_ID`:

```bash
just iam-setup
just iam-verify
```

### 2. Google SecOps SOAR User Provisioning Prerequisites

Interactive OAuth users calling SOAR-backed MCP tools (`list_cases`, `list_integrations`, `list_playbooks`) must meet two identity requirements inside Google Security Operations:

1. Their user identity or group must match an access control rule in `Settings > Access management > Group Mapping`.
2. They must sign in to the Google SecOps web UI at least once so their user profile exists in `Settings > Access management > User Management`.

If either step is missing, SOAR-backed MCP tools return `401 You are not recognized.` even when SIEM tools such as `udm_search` succeed.

---

## Deployment Workflow

1. **Deploy Agent to Vertex AI Agent Engine**: Package and deploy the ADK agent to Vertex AI Reasoning Engine.
2. **Configure Local Environment**: Save the Reasoning Engine resource name in `.env` and configure service agent IAM bindings.
3. **Create Google Cloud OAuth Client Secret**: Create a Web application OAuth client in Google Cloud Console and download its JSON file.
4. **Configure OAuth Credentials**: Generate the OAuth authorization URI template (with optional RFC 7636 PKCE verification) in `.env`.
5. **Register OAuth Authorization**: Create the authorization resource in Discovery Engine.
6. **Create Gemini Enterprise App**: Provision the application engine in Gemini Enterprise.
7. **Register Agent with Gemini Enterprise**: Link the deployed Reasoning Engine and OAuth authorization resource to the Gemini Enterprise app.

---

## 1. Deploy Agent to Vertex AI Agent Engine

Populate `.env` with your project and Google SecOps tenant settings:

```env
GCP_PROJECT_ID="your-gcp-project-id"
GCP_PROJECT_NUMBER="123456789012"
GCP_LOCATION="us-central1"
GCP_STAGING_BUCKET="gs://your-staging-bucket"
CHRONICLE_PROJECT_ID="your-chronicle-project-id"
CHRONICLE_CUSTOMER_ID="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
CHRONICLE_REGION="us"

OAUTH_AUTH_ID="gement-onemcp-auth-passthrough-v1"
GEMINI_AUTHORIZATION_ID="gement-onemcp-auth-passthrough-v1"
```

Configure service agent IAM roles on `GCP_PROJECT_ID` and deploy the agent:

```bash
just iam-setup
just agent-engine-deploy
# or
uv run oauth-flow-gemini-enterprise-secops-mcp agent-engine deploy --agent-module agent
```

## 2. Configure Local Environment

Verify that `AGENT_ENGINE_RESOURCE_NAME` is recorded in `.env`:

```env
AGENT_ENGINE_RESOURCE_NAME="projects/123456789012/locations/us-central1/reasoningEngines/9876543210"
```

## 3. Create Google Cloud OAuth Client Secret

1. Open **APIs & Services > Credentials** in the Google Cloud Console for `GCP_PROJECT_ID`.
2. Select **Create Credentials > OAuth client ID**.
3. Choose **Web application**.
4. Under **Authorized redirect URIs**, add `https://vertexaisearch.cloud.google.com/oauth-redirect`.
5. Click **Create** and download the client secret JSON file.

![Create OAuth Client ID](docs/client_id_for_web_application.png "Create OAuth Client ID in Google Cloud Console")

## 4. Configure OAuth Credentials

Generate the OAuth authorization configuration in `.env`. Pass `--pkce` to enable RFC 7636 S256 PKCE verification on the Discovery Engine authorization resource. Gemini Enterprise invokes the generated authorization URI automatically when end users sign in.

```bash
CLIENT_SECRET_JSON="path/to/client_secret.json"

just run oauth setup "$CLIENT_SECRET_JSON" \
  --scopes "https://www.googleapis.com/auth/chronicle,https://www.googleapis.com/auth/cloud-platform,openid" \
  --pkce
```

## 5. Register OAuth Authorization

Register the OAuth authorization resource in Discovery Engine:

```bash
YOUR_OAUTH_AUTH_ID="gement-onemcp-auth-passthrough-v1"

just run oauth create-auth --auth-id "$YOUR_OAUTH_AUTH_ID"
just oauth-verify
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
AGENT_ENGINE_ID="projects/123456789012/locations/us-central1/reasoningEngines/9876543210"
APP_ID="secops-agent_1700000000"

just run agentspace register \
  --agent-engine-id "$AGENT_ENGINE_ID" \
  --app-id "$APP_ID" \
  --force
```

## 8. Redeploying or Testing the Agent

```bash
# Update deployed Reasoning Engine in-place
just agent-engine-update

# Send a test query to the deployed Reasoning Engine
just agent-engine-test
```
