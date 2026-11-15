#!/usr/bin/env python3
"""IAM Manager for Vertex AI Agent Engine, Gemini Enterprise, and Google SecOps.

This module manages Google Cloud IAM policy bindings for Google-managed service
agents required by Vertex AI Agent Engine and Gemini Enterprise, and verifies
runtime IAM roles required to invoke remote Google Security Operations (SecOps)
MCP tools.
"""

import os
from pathlib import Path
from typing import Annotated
from typing import Any

import typer
from dotenv import load_dotenv
from google.auth import default
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2
from google.iam.v1 import policy_pb2

app = typer.Typer(
    add_completion=False,
    help=(
        "Manage and verify IAM permissions for Vertex AI Agent Engine, "
        "Gemini Enterprise, and Google SecOps MCP."
    ),
)

SERVICE_AGENT_PERMISSIONS: tuple[dict[str, Any], ...] = (
    {
        "service": "aiplatform-re",
        "name": "Vertex AI Reasoning Engine Service Agent",
        "roles": ["roles/aiplatform.user"],
        "purpose": "Invoke Gemini models during Reasoning Engine execution",
    },
    {
        "service": "discoveryengine",
        "name": "Discovery Engine Service Agent",
        "roles": ["roles/aiplatform.user", "roles/aiplatform.viewer"],
        "purpose": "Invoke Reasoning Engine from Gemini Enterprise",
    },
)

SECOPS_DATA_ROLES: tuple[str, ...] = (
    "roles/chronicle.viewer",
    "roles/chronicle.editor",
    "roles/chronicle.admin",
)

SECOPS_MCP_ROLE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "role": "roles/mcp.toolUser",
        "accepted_roles": ("roles/mcp.toolUser",),
        "purpose": "Invoke remote SecOps MCP tools (mcp.googleapis.com/tools.call)",
    },
    {
        "role": "roles/chronicle.viewer",
        "accepted_roles": SECOPS_DATA_ROLES,
        "purpose": (
            "Access Google SecOps data (satisfied by roles/chronicle.viewer, "
            "roles/chronicle.editor, or roles/chronicle.admin)"
        ),
    },
    {
        "role": "roles/serviceusage.serviceUsageConsumer",
        "accepted_roles": ("roles/serviceusage.serviceUsageConsumer",),
        "purpose": (
            "Consume API quota on the project passed in x-goog-user-project"
        ),
    },
)


def normalize_principal(principal: str) -> str:
  """Normalize an email or IAM member string into IAM policy member syntax.

  Args:
      principal: User email, service account email, or prefixed IAM member.

  Returns:
      Normalized IAM member string (for example, 'user:analyst@example.com').

  Raises:
      ValueError: If principal is empty or whitespace.
  """
  cleaned = principal.strip()
  if not cleaned:
    raise ValueError("Principal must not be empty.")
  if ":" in cleaned:
    return cleaned
  if cleaned.endswith(".gserviceaccount.com"):
    return f"serviceAccount:{cleaned}"
  return f"user:{cleaned}"


class IAMManager:
  """Manages and verifies Google Cloud IAM policy bindings."""

  def __init__(self, env_file: Path):
    """Initialize the IAM manager.

    Args:
        env_file: Path to the environment file.
    """
    self.env_file = env_file
    self.env_vars = self._load_env_vars()
    self.project_id: str | None = None
    self.project_number: str | None = None
    self.chronicle_project_id: str | None = None
    self.projects_client: resourcemanager_v3.ProjectsClient | None = None
    self._initialize_clients()

  def _load_env_vars(self) -> dict[str, str]:
    """Load environment variables from the .env file."""
    if self.env_file.exists():
      load_dotenv(self.env_file, override=True)
    return dict(os.environ)

  def _initialize_clients(self) -> None:
    """Initialize Google Cloud Resource Manager client with credentials."""
    self.project_id = self.env_vars.get("GCP_PROJECT_ID")
    self.project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
    self.chronicle_project_id = (
        self.env_vars.get("CHRONICLE_PROJECT_ID") or self.project_id
    )

    if not self.project_id:
      typer.secho(
          "[ERROR] Missing required variable: GCP_PROJECT_ID",
          fg=typer.colors.RED,
      )
      raise typer.Exit(code=1)

    if not self.project_number:
      typer.secho(
          "[ERROR] Missing required variable: GCP_PROJECT_NUMBER",
          fg=typer.colors.RED,
      )
      raise typer.Exit(code=1)

    try:
      credentials, _ = default()
      self.projects_client = resourcemanager_v3.ProjectsClient(
          credentials=credentials
      )
    except Exception as e:
      typer.secho(
          f"[ERROR] Failed to initialize Resource Manager client: {e}",
          fg=typer.colors.RED,
      )
      raise typer.Exit(code=1)

  def _get_service_account_email(self, service: str) -> str:
    """Get the service account email for a Google-managed service agent.

    Args:
        service: Service identifier (e.g., 'aiplatform-re', 'discoveryengine').

    Returns:
        Service account email address.
    """
    return f"service-{self.project_number}@gcp-sa-{service}.iam.gserviceaccount.com"

  def _get_iam_policy(self, project_id: str | None = None) -> policy_pb2.Policy:
    """Get the current IAM policy for a Google Cloud project."""
    if self.projects_client is None:
      raise RuntimeError("Resource Manager client is not initialized.")
    target_project = project_id or self.project_id
    request = iam_policy_pb2.GetIamPolicyRequest(
        resource=f"projects/{target_project}"
    )
    return self.projects_client.get_iam_policy(request=request)

  def _set_iam_policy(
      self, policy: policy_pb2.Policy, project_id: str | None = None
  ) -> policy_pb2.Policy:
    """Set the IAM policy for a Google Cloud project."""
    if self.projects_client is None:
      raise RuntimeError("Resource Manager client is not initialized.")
    target_project = project_id or self.project_id
    request = iam_policy_pb2.SetIamPolicyRequest(
        resource=f"projects/{target_project}", policy=policy
    )
    return self.projects_client.set_iam_policy(request=request)

  def _add_role_binding(
      self, service_account: str, role: str, dry_run: bool = False
  ) -> bool:
    """Add a role binding to a service account.

    Args:
        service_account: Service account email.
        role: IAM role to grant (e.g., 'roles/aiplatform.user').
        dry_run: If True, only simulate the change.

    Returns:
        True if binding was added, False if it already exists.
    """
    member = f"serviceAccount:{service_account}"
    policy = self._get_iam_policy()

    for binding in policy.bindings:
      if binding.role == role and member in binding.members:
        return False

    if dry_run:
      return True

    role_exists = False
    for binding in policy.bindings:
      if binding.role == role:
        binding.members.append(member)
        role_exists = True
        break

    if not role_exists:
      new_binding = policy_pb2.Binding(role=role, members=[member])
      policy.bindings.append(new_binding)

    self._set_iam_policy(policy)
    return True

  def _remove_role_binding(
      self, service_account: str, role: str, dry_run: bool = False
  ) -> bool:
    """Remove a role binding from a service account.

    Args:
        service_account: Service account email.
        role: IAM role to remove.
        dry_run: If True, only simulate the change.

    Returns:
        True if binding was removed, False if it did not exist.
    """
    member = f"serviceAccount:{service_account}"
    policy = self._get_iam_policy()

    binding_found = False
    for binding in policy.bindings:
      if binding.role == role and member in binding.members:
        binding_found = True
        if not dry_run:
          binding.members.remove(member)
          if not binding.members:
            policy.bindings.remove(binding)
        break

    if not binding_found:
      return False

    if dry_run:
      return True

    self._set_iam_policy(policy)
    return True

  def _check_role_binding(self, service_account: str, role: str) -> bool:
    """Check if a service account has a specific role on GCP_PROJECT_ID."""
    member = f"serviceAccount:{service_account}"
    policy = self._get_iam_policy()

    for binding in policy.bindings:
      if binding.role == role and member in binding.members:
        return True

    return False

  def setup_service_agent_permissions(
      self, dry_run: bool = False, verbose: bool = False
  ) -> dict[str, list[str]]:
    """Configure required IAM roles for Google-managed service agents.

    Args:
        dry_run: If True, only simulate the changes.
        verbose: If True, print detailed information.

    Returns:
        Dictionary with 'added', 'existing', and 'failed' role lists.
    """
    results: dict[str, list[str]] = {"added": [], "existing": [], "failed": []}

    for perm in SERVICE_AGENT_PERMISSIONS:
      sa_email = self._get_service_account_email(perm["service"])

      if verbose:
        typer.echo("")
        typer.secho(f"Service: {perm['name']}", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"  Account: {sa_email}")
        typer.echo(f"  Purpose: {perm['purpose']}")
        typer.echo("")

      for role in perm["roles"]:
        role_desc = f"{perm['name']}: {role}"
        try:
          if self._check_role_binding(sa_email, role):
            results["existing"].append(role_desc)
            if verbose:
              typer.secho(
                  f"  [OK] {role} - Already exists",
                  fg=typer.colors.YELLOW,
              )
            continue

          added = self._add_role_binding(sa_email, role, dry_run=dry_run)
          if added:
            results["added"].append(role_desc)
            if dry_run:
              typer.secho(
                  f"  [DRY-RUN] {role} - Would be added",
                  fg=typer.colors.GREEN,
              )
            else:
              typer.secho(
                  f"  [OK] {role} - Added successfully",
                  fg=typer.colors.GREEN,
              )
        except Exception as e:
          results["failed"].append(f"{role_desc}: {e}")
          typer.secho(f"  [ERROR] {role} - Failed: {e}", fg=typer.colors.RED)

    return results

  setup_agentspace_permissions = setup_service_agent_permissions

  def verify_service_agent_permissions(self) -> dict[str, bool]:
    """Verify required Vertex AI and Gemini Enterprise service agent roles.

    Returns:
        Dictionary mapping permission descriptions to boolean status.
    """
    results: dict[str, bool] = {}

    for perm in SERVICE_AGENT_PERMISSIONS:
      sa_email = self._get_service_account_email(perm["service"])
      for role in perm["roles"]:
        role_desc = f"{perm['name']}: {role}"
        results[role_desc] = self._check_role_binding(sa_email, role)

    return results

  verify_agentspace_permissions = verify_service_agent_permissions

  def verify_secops_mcp_roles(
      self, principal: str, project_id: str | None = None
  ) -> dict[str, bool]:
    """Verify runtime Google SecOps MCP IAM roles for a user or service account.

    Checks roles on CHRONICLE_PROJECT_ID (or project_id override):
    - roles/mcp.toolUser (mcp.googleapis.com/tools.call)
    - roles/chronicle.viewer (or roles/chronicle.editor / roles/chronicle.admin)
    - roles/serviceusage.serviceUsageConsumer (x-goog-user-project quota)

    Args:
        principal: Email address or IAM member string to check.
        project_id: Optional Google Cloud project override.

    Returns:
        Dictionary mapping canonical required role names to boolean status.
    """
    member = normalize_principal(principal)
    target_project = project_id or self.chronicle_project_id or self.project_id
    policy = self._get_iam_policy(project_id=target_project)

    granted_roles = {
        binding.role for binding in policy.bindings if member in binding.members
    }

    results: dict[str, bool] = {}
    for spec in SECOPS_MCP_ROLE_SPECS:
      canonical_role = spec["role"]
      accepted_roles = spec["accepted_roles"]
      results[canonical_role] = any(
          accepted in granted_roles for accepted in accepted_roles
      )

    return results

  def list_service_account_roles(self, service: str) -> list[str]:
    """List all roles granted to a Google-managed service agent.

    Args:
        service: Service identifier ('aiplatform-re' or 'discoveryengine').

    Returns:
        Sorted list of role names.
    """
    sa_email = self._get_service_account_email(service)
    member = f"serviceAccount:{sa_email}"
    policy = self._get_iam_policy()

    roles = [
        binding.role for binding in policy.bindings if member in binding.members
    ]
    return sorted(roles)


def _print_secops_mcp_role_guidance(chronicle_project_id: str | None) -> None:
  """Print runtime Google SecOps MCP IAM role guidance."""
  target = chronicle_project_id or "<CHRONICLE_PROJECT_ID>"
  typer.echo("Google SecOps Remote MCP Runtime Roles (per OAuth end user):")
  typer.echo(f"  Target Project (x-goog-user-project): {target}")
  for spec in SECOPS_MCP_ROLE_SPECS:
    typer.echo(f"  - {spec['role']}: {spec['purpose']}")
  typer.echo(
      "  Verify a specific principal with: "
      "just run iam verify --principal user@example.com"
  )


@app.command("setup")
def setup_command(
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Simulate changes without applying them",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed information",
        ),
    ] = False,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            help="Path to .env file",
        ),
    ] = Path(".env"),
) -> None:
  """Configure IAM permissions for Vertex AI and Gemini Enterprise service agents.

  Configures the following Google-managed service agents on GCP_PROJECT_ID:
  - Vertex AI Reasoning Engine Service Agent (invoke Gemini models at runtime)
  - Discovery Engine Service Agent (invoke Reasoning Engine from Gemini Enterprise)
  """
  manager = IAMManager(env_file)

  typer.secho("=" * 60, fg=typer.colors.CYAN)
  typer.secho(
      "Vertex AI & Gemini Enterprise IAM Permissions Setup",
      fg=typer.colors.CYAN,
      bold=True,
  )
  typer.secho("=" * 60, fg=typer.colors.CYAN)
  typer.echo("")

  if dry_run:
    typer.secho(
        "DRY RUN MODE - No changes will be made", fg=typer.colors.YELLOW
    )
    typer.echo("")

  typer.echo(f"Project ID: {manager.project_id}")
  typer.echo(f"Project Number: {manager.project_number}")
  typer.echo("")

  results = manager.setup_service_agent_permissions(
      dry_run=dry_run, verbose=verbose
  )

  typer.echo("")
  typer.secho("=" * 60, fg=typer.colors.CYAN)
  typer.secho("Summary", fg=typer.colors.CYAN, bold=True)
  typer.secho("=" * 60, fg=typer.colors.CYAN)
  typer.echo("")

  if results["added"]:
    status = "Would add" if dry_run else "Added"
    typer.secho(f"{status}: {len(results['added'])}", fg=typer.colors.GREEN)
    for item in results["added"]:
      typer.echo(f"  - {item}")
    typer.echo("")

  if results["existing"]:
    typer.secho(
        f"Already configured: {len(results['existing'])}",
        fg=typer.colors.YELLOW,
    )
    for item in results["existing"]:
      typer.echo(f"  - {item}")
    typer.echo("")

  if results["failed"]:
    typer.secho(f"Failed: {len(results['failed'])}", fg=typer.colors.RED)
    for item in results["failed"]:
      typer.echo(f"  - {item}")
    typer.echo("")

  _print_secops_mcp_role_guidance(manager.chronicle_project_id)
  typer.echo("")

  if results["failed"]:
    raise typer.Exit(code=1)

  if not dry_run and results["added"]:
    typer.secho(
        "IAM permissions configured successfully.",
        fg=typer.colors.GREEN,
        bold=True,
    )
  elif dry_run:
    typer.secho(
        "Dry run complete. Run without --dry-run to apply changes.",
        fg=typer.colors.YELLOW,
    )


@app.command("verify")
def verify_command(
    principal: Annotated[
        str | None,
        typer.Option(
            "--principal",
            "-p",
            help=(
                "Optional user email, service account email, or IAM member "
                "to check for runtime Google SecOps MCP roles on "
                "CHRONICLE_PROJECT_ID."
            ),
        ),
    ] = None,
    secops_project: Annotated[
        str | None,
        typer.Option(
            "--secops-project",
            help=(
                "Override target project ID for Google SecOps MCP role checks "
                "(defaults to CHRONICLE_PROJECT_ID or GCP_PROJECT_ID)."
            ),
        ),
    ] = None,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            help="Path to .env file",
        ),
    ] = Path(".env"),
) -> None:
  """Verify service agent IAM bindings and optional Google SecOps MCP roles."""
  manager = IAMManager(env_file)

  typer.secho("=" * 60, fg=typer.colors.CYAN)
  typer.secho(
      "Vertex AI, Gemini Enterprise & SecOps MCP IAM Verification",
      fg=typer.colors.CYAN,
      bold=True,
  )
  typer.secho("=" * 60, fg=typer.colors.CYAN)
  typer.echo("")

  typer.echo(f"Agent Project ID: {manager.project_id}")
  typer.echo(f"Agent Project Number: {manager.project_number}")
  typer.echo("")
  typer.echo("Service Agent Bindings:")

  sa_results = manager.verify_service_agent_permissions()
  sa_all_configured = True
  for role_desc, has_binding in sa_results.items():
    if has_binding:
      typer.secho(f"  [OK] {role_desc}", fg=typer.colors.GREEN)
    else:
      typer.secho(f"  [MISSING] {role_desc}", fg=typer.colors.RED)
      sa_all_configured = False

  typer.echo("")

  mcp_all_configured = True
  target_secops_project = (
      secops_project or manager.chronicle_project_id or manager.project_id
  )

  if principal:
    try:
      member = normalize_principal(principal)
    except ValueError as exc:
      typer.secho(f"[ERROR] {exc}", fg=typer.colors.RED)
      raise typer.Exit(code=1)

    typer.echo(
        f"SecOps Remote MCP Roles for {member} on {target_secops_project}:"
    )
    mcp_results = manager.verify_secops_mcp_roles(
        principal, project_id=target_secops_project
    )
    missing_mcp_roles: list[str] = []
    for spec in SECOPS_MCP_ROLE_SPECS:
      role_name = spec["role"]
      has_role = mcp_results.get(role_name, False)
      if has_role:
        typer.secho(
            f"  [OK] {role_name} - {spec['purpose']}",
            fg=typer.colors.GREEN,
        )
      else:
        typer.secho(
            f"  [MISSING] {role_name} - {spec['purpose']}",
            fg=typer.colors.RED,
        )
        missing_mcp_roles.append(role_name)
        mcp_all_configured = False

    if missing_mcp_roles:
      typer.echo("")
      typer.echo("Grant missing SecOps MCP roles with:")
      for missing_role in missing_mcp_roles:
        typer.echo(
            f"  gcloud projects add-iam-policy-binding {target_secops_project} "
            f'--member="{member}" --role="{missing_role}"'
        )
    typer.echo("")
  else:
    _print_secops_mcp_role_guidance(target_secops_project)
    typer.echo("")

  if sa_all_configured and mcp_all_configured:
    typer.secho(
        "All checked IAM permissions are configured.",
        fg=typer.colors.GREEN,
        bold=True,
    )
    return

  typer.secho(
      "Some required IAM permissions are missing.",
      fg=typer.colors.RED,
      bold=True,
  )
  if not sa_all_configured:
    typer.echo("")
    typer.echo(
        "Run 'just iam-setup' (or 'uv run "
        "oauth-flow-gemini-enterprise-secops-mcp iam setup') to configure "
        "missing service agent permissions."
    )
  raise typer.Exit(code=1)


@app.command("list-roles")
def list_roles_command(
    service: Annotated[
        str,
        typer.Argument(
            help="Service identifier (aiplatform-re or discoveryengine)",
        ),
    ],
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            help="Path to .env file",
        ),
    ] = Path(".env"),
) -> None:
  """List all IAM roles granted to a Google-managed service agent.

  SERVICE can be:
  - aiplatform-re: Vertex AI Reasoning Engine Service Agent
  - discoveryengine: Discovery Engine Service Agent
  """
  service_names = {
      "aiplatform-re": "Vertex AI Reasoning Engine Service Agent",
      "discoveryengine": "Discovery Engine Service Agent",
  }
  if service not in service_names:
    typer.secho(
        "[ERROR] Invalid service. Must be 'aiplatform-re' or 'discoveryengine'.",
        fg=typer.colors.RED,
    )
    raise typer.Exit(code=1)

  manager = IAMManager(env_file)
  sa_email = manager._get_service_account_email(service)
  roles = manager.list_service_account_roles(service)

  typer.secho("=" * 60, fg=typer.colors.CYAN)
  typer.secho(service_names[service], fg=typer.colors.CYAN, bold=True)
  typer.secho("=" * 60, fg=typer.colors.CYAN)
  typer.echo("")
  typer.echo(f"Service Account: {sa_email}")
  typer.echo("")

  if roles:
    typer.secho(
        f"Granted Roles ({len(roles)}):", fg=typer.colors.GREEN, bold=True
    )
    for role in roles:
      typer.echo(f"  - {role}")
  else:
    typer.secho("No roles granted", fg=typer.colors.YELLOW)


if __name__ == "__main__":
  app()
