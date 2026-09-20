"""Unified CLI for oauth_flow_gemini_enterprise_secops_mcp.

Provides a unified management interface for Agent Engine deployments,
Gemini Enterprise (AgentSpace) registration, OAuth authorizations,
and Vertex AI configuration.
"""

import importlib
import shutil
import sys
import uuid
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from rich.console import Console

from oauth_flow_gemini_enterprise_secops_mcp.core import run_pipeline

# Resolve repo root (src/oauth_flow_gemini_enterprise_secops_mcp/cli.py -> parents[2])
REPO_ROOT = Path(__file__).resolve().parents[2]

# Load environment variables
load_dotenv(REPO_ROOT / ".env")

# Ensure repository root and installation_scripts are importable
for path_entry in (str(REPO_ROOT), str(REPO_ROOT / "installation_scripts")):
  if path_entry not in sys.path:
    sys.path.insert(0, path_entry)


def get_app(module_name: str) -> typer.Typer | None:
  """Dynamically load a Typer sub-application from installation_scripts.

  Args:
    module_name: Name of the module inside installation_scripts.

  Returns:
    Loaded Typer application or None if unavailable.
  """
  try:
    module = importlib.import_module(f"installation_scripts.{module_name}")
    return module.app
  except (ImportError, AttributeError):
    return None


console = Console()

app = typer.Typer(
    name="oauth-flow-gemini-enterprise-secops-mcp",
    help=(
        "Unified management CLI for Agentic SOC Gemini Enterprise SecOps MCP"
        " OAuth"
    ),
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

# Mount management subcommands
SUBCOMMAND_SPECS = [
    ("manage_agent_engine", "agent-engine", "Manage Agent Engine instances"),
    ("manage_agentspace", "agentspace", "Manage AgentSpace apps and agents"),
    ("manage_oauth", "oauth", "Manage OAuth authorizations"),
    ("manage_datastore", "datastore", "Manage data stores"),
    ("manage_rag", "rag", "Manage RAG corpora"),
    ("manage_memories", "memories", "Manage Agent Engine memories"),
    ("manage_iam", "iam", "Manage IAM permissions for service accounts"),
    ("manage_vertex_ai", "vertex", "Verify and manage Vertex AI setup"),
    (
        "manage_chat_ops",
        "chatops",
        "Manage and test ChatOps cards and functions",
    ),
]

for mod_name, sub_name, sub_help in SUBCOMMAND_SPECS:
  sub_app = get_app(mod_name)
  if sub_app is not None:
    app.add_typer(sub_app, name=sub_name, help=sub_help)

# Workflow subcommand group
workflow_app = typer.Typer(
    help="Composite workflows and multi-step operations",
    no_args_is_help=True,
)
app.add_typer(workflow_app, name="workflow")


@app.callback()
def main_callback() -> None:
  """oauth_flow_gemini_enterprise_secops_mcp CLI Operations."""


@app.command("info")
def info() -> None:
  """Display project configuration and environment status."""
  console.print(
      "[bold blue]oauth_flow_gemini_enterprise_secops_mcp[/bold blue]"
      " Environment Status"
  )
  console.print(f"Repository Root: [cyan]{REPO_ROOT}[/cyan]")


@app.command("run-demo")
def run_demo(
    name: Annotated[
        str, typer.Option("--name", "-n", help="Target entity name")
    ] = "world",
) -> None:
  """Run basic demo pipeline.

  Args:
    name: Target entity name to process.
  """
  result = run_pipeline(name)
  console.print(f"[green]Pipeline Output:[/green] {result}")


@workflow_app.command("full-deploy")
def full_deploy(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = REPO_ROOT
    / ".env",
) -> None:
  """Complete deployment workflow with OAuth.

  Args:
    env_file: Path to the environment file.
  """
  console.print(
      "\n[bold blue]Starting full deployment workflow...[/bold blue]\n"
  )

  console.print("[yellow]Step 1: Deploy Agent Engine[/yellow]")
  console.print(
      "Please run: [cyan]just agent-engine-deploy[/cyan] and save"
      " AGENT_ENGINE_RESOURCE_NAME to .env\n"
  )

  if not typer.confirm("Have you deployed the agent engine?"):
    console.print(
        "[red]Deployment cancelled. Please deploy the agent engine first.[/red]"
    )
    raise typer.Exit(code=1)

  console.print("\n[yellow]Step 2: Create OAuth Authorization[/yellow]")
  from installation_scripts.manage_oauth import OAuthManager

  oauth_manager = OAuthManager(env_file)

  if not oauth_manager.env_vars.get("OAUTH_CLIENT_ID"):
    console.print(
        "[red]OAuth not configured. Please run:[/red] [cyan]just run oauth"
        " setup <client_secret.json>[/cyan]"
    )
    raise typer.Exit(code=1)

  auth_id = oauth_manager.env_vars.get("OAUTH_AUTH_ID")
  if not auth_id:
    auth_id = f"auth-{uuid.uuid4().hex[:8]}"

  client_id = oauth_manager.env_vars.get("OAUTH_CLIENT_ID")
  client_secret = oauth_manager.env_vars.get("OAUTH_CLIENT_SECRET")
  auth_uri = oauth_manager.env_vars.get("OAUTH_AUTH_URI")
  token_uri = oauth_manager.env_vars.get(
      "OAUTH_TOKEN_URI", "https://oauth2.googleapis.com/token"
  )

  if oauth_manager.create_authorization(
      auth_id, client_id, client_secret, auth_uri, token_uri
  ):
    console.print(f"[green]OAuth authorization created: {auth_id}[/green]")
  else:
    console.print("[red]Failed to create OAuth authorization[/red]")
    raise typer.Exit(code=1)

  console.print("\n[yellow]Step 3: Link Agent to AgentSpace[/yellow]")
  from installation_scripts.manage_agentspace import AgentSpaceManager

  as_manager = AgentSpaceManager(env_file)
  if as_manager.link_agent_to_agentspace():
    console.print("[green]Agent linked to AgentSpace successfully![/green]")
  else:
    console.print("[red]Failed to link agent to AgentSpace[/red]")
    raise typer.Exit(code=1)

  console.print(
      "\n[bold green]Full deployment workflow completed"
      " successfully![/bold green]"
  )


@workflow_app.command("redeploy-all")
def redeploy_all(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = REPO_ROOT
    / ".env",
) -> None:
  """Redeploy agent engine and update AgentSpace configuration.

  Args:
    env_file: Path to the environment file.
  """
  console.print("\n[bold blue]Starting full redeployment...[/bold blue]\n")

  console.print("[yellow]Step 1: Redeploy Agent Engine[/yellow]")
  console.print("Please run: [cyan]just agent-engine-update[/cyan]\n")

  if not typer.confirm("Have you redeployed the agent engine?"):
    console.print("[red]Redeployment cancelled.[/red]")
    raise typer.Exit(code=1)

  console.print("\n[yellow]Step 2: Update AgentSpace Configuration[/yellow]")
  from installation_scripts.manage_agentspace import AgentSpaceManager

  manager = AgentSpaceManager(env_file)
  if manager.update_agent():
    console.print("[green]AgentSpace updated successfully![/green]")
  else:
    console.print("[red]Failed to update AgentSpace[/red]")
    raise typer.Exit(code=1)

  console.print(
      "\n[bold green]Full redeployment completed successfully![/bold green]"
  )


@workflow_app.command("status")
def status(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = REPO_ROOT
    / ".env",
) -> None:
  """Check the status of the entire system.

  Args:
    env_file: Path to the environment file.
  """
  console.print("\n[bold blue]System Status Check[/bold blue]\n")

  from installation_scripts.manage_agentspace import AgentSpaceManager

  manager = AgentSpaceManager(env_file)

  console.print("[yellow]Environment Configuration:[/yellow]")
  env_vars_to_check = [
      "GCP_PROJECT_ID",
      "GCP_PROJECT_NUMBER",
      "GCP_LOCATION",
      "AGENT_ENGINE_RESOURCE_NAME",
      "AGENTSPACE_APP_ID",
      "AGENTSPACE_AGENT_ID",
      "OAUTH_AUTH_ID",
      "GEMINI_AUTHORIZATION_ID",
  ]

  for var in env_vars_to_check:
    value = manager.env_vars.get(var)
    if value:
      display_value = value if len(value) < 60 else f"{value[:60]}..."
      console.print(f"  {var}: [green]{display_value}[/green]")
    else:
      console.print(f"  {var}: [red]Not set[/red]")

  console.print("\n[yellow]AgentSpace Status:[/yellow]")
  if manager.verify_agent():
    console.print("  [green]AgentSpace agent is verified and active[/green]")
  else:
    console.print("  [red]AgentSpace agent verification failed[/red]")

  console.print()


@app.command()
def setup(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = REPO_ROOT
    / ".env",
) -> None:
  """Set up the environment and check dependencies.

  Args:
    env_file: Path to the environment file.
  """
  console.print("\n[bold blue]Setting up environment...[/bold blue]\n")

  if not env_file.exists():
    env_example = REPO_ROOT / ".env.example"
    if env_example.exists():
      shutil.copy(env_example, env_file)
      console.print(f"[green]Created {env_file} from template[/green]")
      console.print(
          f"[yellow]Please edit {env_file} with your configuration[/yellow]"
      )
    else:
      console.print(
          f"[yellow]No .env.example found. Please create {env_file}"
          " manually[/yellow]"
      )
  else:
    console.print(f"[green]{env_file} already exists[/green]")

  console.print("\n[yellow]Checking Python dependencies...[/yellow]")
  try:
    import google.adk  # noqa: F401
    import google.auth  # noqa: F401
    import vertexai  # noqa: F401

    console.print("[green]All required packages are installed[/green]")
  except ImportError as exc:
    console.print(f"[red]Missing package: {exc}[/red]")
    console.print("[yellow]Please run:[/yellow] [cyan]just sync[/cyan]")
    raise typer.Exit(code=1) from exc

  console.print("\n[bold green]Setup complete![/bold green]")


@app.command()
def version() -> None:
  """Display version information."""
  console.print(
      "\n[bold blue]Agentic SOC AgentSpace Management CLI[/bold blue]"
  )
  console.print("Version: [cyan]0.1.0[/cyan]")
  console.print("Python Typer-based unified management interface\n")


def main() -> None:
  """Main entry point."""
  try:
    app()
  except KeyboardInterrupt as exc:
    console.print("\n[yellow]Operation cancelled by user[/yellow]")
    raise typer.Exit(code=130) from exc
  except Exception as exc:
    console.print(f"\n[red]Unexpected error: {exc}[/red]")
    raise typer.Exit(code=1) from exc


if __name__ == "__main__":
  main()
