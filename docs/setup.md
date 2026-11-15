# Setup & Troubleshooting - oauth_flow_gemini_enterprise_secops_mcp

This guide covers local environment setup, Google Cloud IAM configuration, Google Security Operations (SecOps) SOAR user provisioning, and Discovery Engine OAuth registration for Gemini Enterprise.

## Prerequisites

- Python >= 3.11 (Python 3.12 recommended)
- `uv` (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- `just` (`cargo install just` or system package manager)
- `gcloud` CLI authenticated against your target Google Cloud project
- `direnv` (optional, for per-directory Google Cloud configuration and ADC isolation)

## Local Development

1. Run `just setup` to create `.env` from `.env.example` and synchronize `.venv` dependencies.
2. Run `just test` to execute the unit test suite.
3. Run `just lint` to check formatting and lint rules with Pyink and Ruff.
4. Run `just typecheck` to run Pytype static type analysis.
5. Run `just run info` to inspect the CLI and repository status.

## Environment Configuration

Populate `.env` with your Vertex AI host project, Google SecOps tenant identifiers, and OAuth authorization ID:

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

Keep the `CHRONICLE_*` variable names and the `https://www.googleapis.com/auth/chronicle` OAuth scope unchanged; the Google SecOps API and remote MCP endpoint (`https://{region}-chronicle.googleapis.com/mcp`) require those exact identifiers.

## Service Agent IAM Setup

Vertex AI Agent Engine and Gemini Enterprise rely on two Google-managed service agents in `GCP_PROJECT_ID`:

- `service-<GCP_PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com`: requires `roles/aiplatform.user` to invoke Gemini models during Reasoning Engine execution.
- `service-<GCP_PROJECT_NUMBER>@gcp-sa-discoveryengine.iam.gserviceaccount.com`: requires `roles/aiplatform.user` and `roles/aiplatform.viewer` to invoke the Reasoning Engine from Gemini Enterprise.

Grant and verify both service agent bindings with:

```bash
just iam-setup
just iam-verify
```

## IAM & SOAR User Prerequisites

### 1. Required Google Cloud IAM Roles on `CHRONICLE_PROJECT_ID`

Gemini Enterprise forwards each signed-in user's OAuth access token to the agent, and the agent sends `CHRONICLE_PROJECT_ID` in the `x-goog-user-project` header on every MCP request. Every authorizing end user needs three IAM roles on `CHRONICLE_PROJECT_ID`:

- `roles/mcp.toolUser`: grants `mcp.googleapis.com/tools.call` to call tools on `mcp.googleapis.com`.
- `roles/chronicle.viewer` (or `roles/chronicle.editor` / `roles/chronicle.admin`): grants access to Google SecOps SIEM and SOAR data.
- `roles/serviceusage.serviceUsageConsumer`: grants permission to bill API quota against the project passed in `x-goog-user-project`.

Grant and verify these roles for an end user:

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

uv run oauth-flow-gemini-enterprise-secops-mcp iam verify --principal "$USER_EMAIL"
```

### 2. Google SecOps SOAR User Provisioning Prerequisites

Interactive OAuth users who invoke SOAR-backed MCP tools (`list_cases`, `list_integrations`, `list_playbooks`) must also be provisioned in Google Security Operations:

1. Map the user's identity or IdP group to a Google SecOps role under `Settings > Access management > Group Mapping`.
2. Have the user sign in to the Google SecOps web UI at least once so Google SecOps creates their profile in `Settings > Access management > User Management`.

If the user has valid Google Cloud IAM bindings on `CHRONICLE_PROJECT_ID` but lacks a `Group Mapping` rule or has never signed in to the Google SecOps web UI, SOAR-backed MCP tools fail with `401 You are not recognized.`.

## OAuth 2.0 & PKCE Setup

1. In the Google Cloud Console for `GCP_PROJECT_ID`, create a **Web application** OAuth 2.0 Client ID with authorized redirect URI `https://vertexaisearch.cloud.google.com/oauth-redirect` and download the client secret JSON file.
2. Generate the OAuth settings in `.env` (pass `--pkce` to enable RFC 7636 PKCE verification on the Discovery Engine authorization resource, or `--no-pkce` to disable it):

```bash
CLIENT_SECRET_JSON="path/to/client_secret.json"
OAUTH_AUTH_ID="gement-onemcp-auth-passthrough-v1"

uv run oauth-flow-gemini-enterprise-secops-mcp oauth setup "$CLIENT_SECRET_JSON" --pkce
uv run oauth-flow-gemini-enterprise-secops-mcp oauth create-auth --auth-id "$OAUTH_AUTH_ID"
uv run oauth-flow-gemini-enterprise-secops-mcp oauth verify --auth-id "$OAUTH_AUTH_ID"
```

Do not open the generated `OAUTH_AUTH_URI` manually during CLI setup. Gemini Enterprise redirects each end user to `OAUTH_AUTH_URI` dynamically when they start a session and attaches per-session `state` and PKCE parameters automatically.

## Troubleshooting

- **`403 PERMISSION_DENIED` on `mcp.googleapis.com/tools.call`**: The signed-in user is missing `roles/mcp.toolUser` on `CHRONICLE_PROJECT_ID`. Run `just run iam verify --principal "$USER_EMAIL"` to check.
- **`403 USER_PROJECT_DENIED` or quota error on `x-goog-user-project`**: The signed-in user is missing `roles/serviceusage.serviceUsageConsumer` on `CHRONICLE_PROJECT_ID`.
- **`401 You are not recognized.` on `list_cases`, `list_integrations`, or `list_playbooks`**: Confirm the user matches a rule in `Settings > Access management > Group Mapping` and has logged in to the Google SecOps web UI at least once so their entry exists in `Settings > Access management > User Management`.
- **OAuth redirect mismatch during sign-in**: Verify that `https://vertexaisearch.cloud.google.com/oauth-redirect` is listed under **Authorized redirect URIs** on the Web application OAuth client in Google Cloud Console.
