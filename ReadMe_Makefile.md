# 📖 `ReadMe_Makefile.md`: Frictionless Makefile targets

To provide a cold-start single command for deployers, we created standardized frictionless targets that automate the end-to-end setup in a single terminal session without manual copy-pasting into the Cloud Console URI.

---

## 🚀 The Frictionless Targets

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

## ⚙️ How It Works (Python `.expanduser()`)

To allow standard local workspace tips (e.g. `~/.ssh/client_secret.json`), we added natively tilde expansion inside our python validating scripts:

```python
expanded_path = Path(client_secret_file).expanduser()
```

This prevents crashes where `.env` loaders otherwise parse literal tilde as invalid filesystem string. Your `.env` value works flawlessly!

---

## 🛠 Usage Flow Tip:
Run `make help` inside your terminal to display the live list of targets alongside their descriptions!
