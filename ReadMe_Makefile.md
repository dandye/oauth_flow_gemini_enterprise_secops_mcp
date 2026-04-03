# ReadMe_Makefile.md: Frictionless Makefile targets

To provide a cold-start single command for deployers, we created standardized frictionless targets that automate the end-to-end setup in a single terminal session without manual copy-pasting into the Cloud Console URI.

---

## Prerequisites

Before running standard frictionless targets, you must have your OAuth 2.0 Web Application client secret JSON from standard Google Cloud Console.

For detailed instructions on how to:
1.  Enable required APIs
2.  Create an OAuth Client ID (Web Application type)
3.  Add the Redirect URI (`https://vertexaisearch.cloud.google.com/oauth-redirect`)
4. Save the file locall, for example to: `~/.ssh/client_secret.json`

[View Detailed Prerequisite Guide here](file:///Users/dandye/Projects/adk_onemcp_auth__worktrees/adk_oauth_auth_credential_v0001/ReadMe.md#3-generate-gcp-client-secret)

---

## Step 0: Fresh Checkout Setup

If this is your first time checking out standard repo, running standard chained sequence immediately will deploy using template placeholders and fail.

**How to start cold:**

1.  **Prep Environment:** Run `make setup` to create your local `.env` and `venv`.
2.  **Edit Configuration:** Open `.env` manually and fill standard IDs:
    ```bash
    GCP_PROJECT_ID=secops-demo-env
    CHRONICLE_PROJECT_ID=a13f6726-efed-452e-9008-8fe0d3cb0f75
    # ... and keep local secrets separate!
    ```
3.  **Discover Secrets:** Proceed to Prerequisite Discovery below and pass standard file path CLI style!

---

## The Frictionless Targets

### 1. Unified Wizard Single Command Target

```bash
make full-deploy-with-oauth OAUTH_SECRETS_FILE=~/.ssh/client_secret.json
```

**What it does sequentially:**
1.  **`make setup`**: Automatically creates `.env` from template and installs `venv` and dependencies.
2.  **`make agent-engine-deploy`**: Deploys your agent to Vertex AI Reasoning Engine.
3.  **`make oauth-setup`**: Translates your JSON natively from local system.
4.  **`make agentspace-unified-register`**: Sequential Python link that creates an OAuth authorization automatically without manual paste, and immediately links custom agents in AgentSpace frictionless!

---

### 2. Manual Pre-Requisites + Sequence

If you have already downloaded your JSON from the browser, but don't want to run deployer from cold-start, you can run the already sequential setup-and-link wizard:

```bash
make unified-wizard-workflow OAUTH_SECRETS_FILE=~/.ssh/client_secret.json
```

***

## How It Works (Python .expanduser())

To allow standard local workspace tips (e.g. `~/.ssh/client_secret.json`), we added natively tilde expansion inside our python validating scripts:

```python
expanded_path = Path(client_secret_file).expanduser()
```

This prevents crashes where `.env` loaders otherwise parse literal tilde as invalid filesystem string. Your `.env` value works flawlessly!

---

## Usage Flow Tip:
Run `make help` inside your terminal to display the live list of targets alongside their descriptions!
