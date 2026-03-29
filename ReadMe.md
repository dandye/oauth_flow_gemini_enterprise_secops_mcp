# Gemini Enterprise Agent Deployment

This guide outlines the bare minimum steps to successfully deploy and register a custom ADK agent that uses the [remote MCP server for SecOps](https://docs.cloud.google.com/chronicle/docs/secops/use-google-secops-mcp) in Vertex AI, setup OAuth, and integrate it with Gemini Enterprise. The goal is for OAuth passthrough to work seamlessly in Gemini Enterprise.

## High-Level Deployment Workflow

1. **Deploy Agent to Vertex AI Agent Engine**: Containerize and deploy your agent code to Vertex AI Reasoning Engine.
2. **Configure Local Environment**: Update your `.env` file with the newly generated Reasoning Engine ID.
3. **Generate GCP Client Secret**: Configure your GCP project and download the OAuth Web application client secret JSON (Requires Web Console).
4. **Setup OAuth Credentials**: Generate the local OAuth Authorization configuration properties using your client secret.
5. **Create OAuth Authorization**: Register the OAuth credentials with the Discovery Engine control plane.
6. **Create Gemini Enterprise App**: Initialize the application container within Gemini Enterprise.
7. **Register Agent with Enterprise**: Finalize the process by associating your Reasoning Engine to your Gemini Enterprise App.

---

## 0. Prerequisite: Environment Validation
Ensure your `.env` file is properly configured and does not contain placeholder values.

```bash
# Using Makefile
make env-validate

# Using manage.py
python manage.py env validate
```

## 1. Deploy Agent to Vertex AI
Deploy your agent code to Vertex AI Reason Engine. This command will execute a background deployment operation and inject necessary UI/Telemetry metadata natively.

Before running the command, ensure your `.env` file is populated with your specific tenancy variables:
```env
GCP_PROJECT_ID="your-project-id"
GCP_LOCATION="us-central1"
CHRONICLE_PROJECT_ID="your-chronicle-project-id"
CHRONICLE_CUSTOMER_ID="your-chronicle-customer-id"
CHRONICLE_REGION="us"

# Define a unique Auth ID here for your deployment. 
# (This is NOT generated from the OAuth flow, you simply invent an identifier string here and re-use it later in Step 5):
OAUTH_AUTH_ID="gement-onemcp-auth-passthrough-vX"
GEMINI_AUTHORIZATION_ID="gement-onemcp-auth-passthrough-vX"
```

```bash
# Using Makefile
make agent-engine-deploy

# Using manage.py
python manage.py agent-engine deploy --agent-module agent
```

## 2. Configure Local Environment
**Important**: The deployment command above will print a Resource Name to the terminal (e.g., `projects/XXXXXXXXX/locations/us-central1/reasoningEngines/YYYYYYYYY`).
You **must** manually copy this Resource Name into your `.env` file before proceeding:

```env
AGENT_ENGINE_RESOURCE_NAME="projects/[PROJECT_NUMBER]/locations/us-central1/reasoningEngines/[ENGINE_ID]"
```

## 3. Generate GCP Client Secret (Web Console Required)
**Note:** Due to Google Cloud security requirements and API deprecations, creating the **OAuth Consent Screen** and **OAuth Client ID** must be performed once via the Google Cloud Console web interface. It cannot be fully automated via CLI at this time.

1. Navigate to **APIs & Services > Credentials** in the Google Cloud Console for your `GCP_PROJECT_ID`.
2. Configure an **OAuth Consent Screen** if you haven't already (External/Internal brand).
3. Click **Create Credentials > OAuth client ID**.
4. Select **Web application** (NOT Desktop or Mobile).
5. Under **Authorized redirect URIs**, add exactly: `https://vertexaisearch.cloud.google.com/oauth-redirect`
6. Click **Create** and download the resulting JSON file. 

![Create OAuth Client ID](docs/client_id_for_web_application.png "Create OAuth Client ID in Google Cloud Console")

*(Save this file as `client_secret.json` in your project root).*

## 4. Setup OAuth Credentials
Generate the Authorization URI and store the required credentials. This step links your downloaded `client_secret.json` to the local environment.

```bash
# Using Makefile (assumes file is named client_secret.json)
make oauth-setup CLIENT_SECRET=client_secret.json

# Using manage.py
python manage.py oauth setup client_secret.json \
  --scopes "https://www.googleapis.com/auth/chronicle,https://www.googleapis.com/auth/cloud-platform,openid"
```

## 5. Create OAuth Authorization
Register the newly setup OAuth credentials with the Discovery Engine control plane.

```bash
# Using Makefile (uses OAUTH_AUTH_ID from .env)
make oauth-create-auth

# Using manage.py
python manage.py oauth create-auth --auth-id gement-onemcp-auth-passthrough-vX
```

## 6. Create Gemini Enterprise App
Create the application container within the Gemini Enterprise platform.

```bash
# Using Makefile
make agentspace-create-app APP_NAME="SecOps Agent"

# Using manage.py
python manage.py agentspace create-app \
  --name "SecOps Agent" \
  --app-type APP_TYPE_INTRANET \
  --industry-vertical GENERIC \
  --no-datastore
```

## 7. Register Agent with Enterprise
Associate your deployed Reasoning Engine (`AGENT_ENGINE_RESOURCE_NAME`) with your newly created Gemini Enterprise App.

```bash
# Using Makefile
make agentspace-register

# Using manage.py
python manage.py agentspace register --force
```

---

## OPTIONAL

### 8. Redeploying the Agent
If you make code changes to your agent locally, you **do not** need to rebuild the entire AgentSpace UX or OAuth integration! 
As long as your `.env` contains the existing `AGENT_ENGINE_RESOURCE_NAME` you populated in Step 2, you can just forcefully update the existing pipeline in-place:

```bash
# Using Makefile
make agent-engine-update

# Using manage.py
python manage.py agent-engine update
```

### 9. Create a second (or third) Agent in the exact same application
If you want to deploy a brand new agent pipeline (via `agent-engine deploy` generating a new `$AGENT_ENGINE_ID`) but attach it to the exact same web UI drop-down as your previous assistant, you simply re-run the `register` command!

The Gemini Enterprise App container (Step 6) and OAuth definitions can safely host **multiple** assistants simultaneously. Just feed the registration endpoint the *new* engine ID alongside your *existing* App ID:

```bash
export NEW_AGENT_ENGINE_ID="projects/[PROJECT_NUMBER]/locations/[LOCATION]/reasoningEngines/[NEW_ENGINE_ID]"
export EXISTING_APP_ID="[EXISTING_APP_ID]"

python manage.py agentspace register \
  --agent-engine-id $NEW_AGENT_ENGINE_ID \
  --app-id $EXISTING_APP_ID \
  --force
```

---

## Utility Commands

### IAM Setup
Automate the required IAM permissions for AgentSpace service accounts.

```bash
make iam-setup
```

### Verification
Check if all components are properly configured.

```bash
make status
# OR
make vertex-ai-verify
make agentspace-verify
make oauth-verify
make iam-verify
```

### Enable ADK Console Metrics & Telemetry
The deployment script should automatically tag your engine for UI observability, but if you have an older deployment missing performance metrics or trace logs in the Cloud Console, you can manually fix it:

```bash
# Using Makefile (inherits from deploy)
# Using manage.py
python manage.py agent-engine tag-as-adk
```

### Cleanup / Re-create OAuth
If you need to strictly delete an existing authorization before re-creating:

```bash
# Using Makefile
make oauth-delete

# Using manage.py
python manage.py oauth delete --auth-id gement-onemcp-auth-passthrough-vX --force
```

### Deployment via Makefile (Summary)
After updating your `.env` file and downloading `client_secret.json`:

```bash
make agent-engine-deploy
make oauth-setup CLIENT_SECRET=client_secret.json
make oauth-create-auth
make agentspace-create-app APP_NAME="My App"
make agentspace-register
```
