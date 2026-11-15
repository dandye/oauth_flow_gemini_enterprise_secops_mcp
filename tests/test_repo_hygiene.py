"""Hermetic repository hygiene, CI security, and developer tooling tests."""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
SCRIPTS_DIR = REPO_ROOT / "scripts"
JUSTFILE_PATH = REPO_ROOT / "justfile"
AGENTS_MD_PATH = REPO_ROOT / "AGENTS.md"

SHA_PINNED_USES_RE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$"
)
RAW_USES_COMMENT_RE = re.compile(
    r"^\s*(?:-\s*)?uses:\s+"
    r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40})"
    r"\s+#\s+v\d+\.\d+"
)

# Split token literals so raw diff or repository text scans do not self-match.
UNPINNED_PIP_RE = re.compile(r"\bpip" + r"3?\s+install\b", re.IGNORECASE)
STRICT_LEAK_TOKENS = (
    "argo" + "lis",
    "alto" + "strat",
    "joo" + "nix",
    "air" + "lock-proxy",
    "google" + "plex",
    "corp." + "goog",
)
WORKSTATION_LEAK_TOKENS = (
    "cloud" + "top",
    "siemplify" + "-soar",
)
PENDING_COMPANION_CLEANUP_PATHS = frozenset(
    {
        ".env.example",
        "src/oauth_flow_gemini_enterprise_secops_mcp/agent_engine.py",
        "src/oauth_flow_gemini_enterprise_secops_mcp/env_validation.py",
    }
)
IGNORED_WALK_DIRS = frozenset(
    {
        ".git",
        ".gcloud",
        ".mypy_cache",
        ".pytest_cache",
        ".pytype",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "external",
        "htmlcov",
        "venv",
    }
)
EXPECTED_JUST_GROUPS = frozenset(
    {
        "setup",
        "quality",
        "agent-engine",
        "gemini-enterprise",
        "oauth",
        "secret",
        "vertex-ai",
        "iam",
        "workflow",
    }
)


def _iter_repo_text_files() -> list[Path]:
  """Return tracked or non-ignored text files under REPO_ROOT."""
  git_bin = shutil.which("git")
  if git_bin is not None:
    proc = subprocess.run(  # noqa: S603
        [git_bin, "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
      paths: list[Path] = []
      for rel in proc.stdout.splitlines():
        candidate = REPO_ROOT / rel
        if candidate.is_file():
          paths.append(candidate)
      return sorted(paths)

  discovered: list[Path] = []
  for root, dirnames, filenames in os.walk(REPO_ROOT):
    dirnames[:] = [d for d in dirnames if d not in IGNORED_WALK_DIRS]
    root_path = Path(root)
    for filename in filenames:
      if filename == ".env" or filename.endswith(".pyc"):
        continue
      candidate = root_path / filename
      if candidate.is_file():
        discovered.append(candidate)
  return sorted(discovered)


def test_github_workflows_pin_commit_shas_and_permissions() -> None:
  workflow_files = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(
      WORKFLOWS_DIR.glob("*.yaml")
  )
  assert workflow_files, "Expected at least one GitHub Actions workflow file."

  for wf_path in workflow_files:
    raw_text = wf_path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw_text)
    assert isinstance(parsed, dict), f"{wf_path.name} must parse as a mapping."

    permissions = parsed.get("permissions")
    assert permissions == {"contents": "read"}, (
        f"{wf_path.name} must declare least-privilege permissions:"
        " contents: read."
    )

    uses_lines = [
        line
        for line in raw_text.splitlines()
        if re.match(r"^\s*(?:-\s*)?uses:\s+", line)
    ]
    assert uses_lines, f"{wf_path.name} must contain action steps."
    for line in uses_lines:
      assert RAW_USES_COMMENT_RE.match(line), (
          f"Action reference in {wf_path.name} must be 40-char SHA pinned with"
          f" a version tag comment: {line!r}"
      )

    jobs = parsed.get("jobs", {})
    assert jobs, f"{wf_path.name} must define at least one job."
    for job_name, job_cfg in jobs.items():
      steps = job_cfg.get("steps", [])
      for step in steps:
        if "uses" not in step:
          continue
        uses_ref = step["uses"]
        assert SHA_PINNED_USES_RE.match(
            uses_ref
        ), f"Step in {wf_path.name}:{job_name} uses unpinned ref {uses_ref!r}"
        with_cfg = step.get("with", {})
        if uses_ref.startswith("actions/checkout@"):
          assert with_cfg.get("persist-credentials") is False
        if uses_ref.startswith("astral-sh/setup-uv@"):
          uv_version = str(with_cfg.get("version", ""))
          assert re.match(r"^\d+\.\d+\.\d+$", uv_version), (
              "astral-sh/setup-uv must pin an explicit semantic version, got"
              f" {uv_version!r}"
          )


def test_ci_workflow_targets_python_312_and_venv_pytype_path() -> None:
  ci_path = WORKFLOWS_DIR / "ci.yml"
  parsed = yaml.safe_load(ci_path.read_text(encoding="utf-8"))
  steps = parsed["jobs"]["test"]["steps"]
  run_commands = [step.get("run", "") for step in steps if "run" in step]

  assert "uv python install 3.12" in run_commands
  assert "uv sync --python 3.12 --all-groups --frozen" in run_commands

  pytype_steps = [
      step for step in steps if step.get("run") == "uv run pytype src"
  ]
  assert len(pytype_steps) == 1
  pytype_env = pytype_steps[0].get("env", {})
  assert ".venv/bin" in pytype_env.get("PATH", "")


def test_no_unpinned_pip_install_in_scripts_or_workflows() -> None:
  targets = list(WORKFLOWS_DIR.glob("*.y*ml")) + [
      p for p in SCRIPTS_DIR.iterdir() if p.is_file()
  ]
  for path in sorted(targets):
    text = path.read_text(encoding="utf-8")
    assert not UNPINNED_PIP_RE.search(
        text
    ), f"Disallowed unpinned pip command found in {path.relative_to(REPO_ROOT)}"


def test_setup_env_script_requires_uv_and_runs_frozen_sync(
    tmp_path: Path,
) -> None:
  bash_bin = shutil.which("bash")
  assert bash_bin is not None

  fake_root = tmp_path / "project"
  fake_scripts = fake_root / "scripts"
  fake_scripts.mkdir(parents=True)
  target_script = fake_scripts / "setup_env.sh"
  shutil.copy2(SCRIPTS_DIR / "setup_env.sh", target_script)
  (fake_root / ".env.example").write_text('EXAMPLE="1"\n', encoding="utf-8")

  # Build a minimal tool directory without uv to verify failure behavior.
  no_uv_bin = tmp_path / "no_uv_bin"
  no_uv_bin.mkdir()
  for util_name in ("dirname", "cp"):
    util_path = shutil.which(util_name)
    assert util_path is not None
    (no_uv_bin / util_name).symlink_to(util_path)

  missing_uv_proc = subprocess.run(  # noqa: S603
      [bash_bin, str(target_script)],
      env={"PATH": str(no_uv_bin), "HOME": str(tmp_path)},
      capture_output=True,
      text=True,
      check=False,
  )
  assert missing_uv_proc.returncode == 1
  assert "https://docs.astral.sh/uv/" in missing_uv_proc.stderr
  assert (fake_root / ".env").read_text(encoding="utf-8") == 'EXAMPLE="1"\n'

  # Provide a stub uv binary and verify frozen sync invocation.
  recorded_args = tmp_path / "uv_args.txt"
  stub_uv = no_uv_bin / "uv"
  stub_uv.write_text(
      f'#!/bin/sh\nprintf "%s\\n" "$@" > "{recorded_args}"\n',
      encoding="utf-8",
  )
  stub_uv.chmod(stub_uv.stat().st_mode | stat.S_IXUSR)

  ok_proc = subprocess.run(  # noqa: S603
      [bash_bin, str(target_script)],
      env={"PATH": str(no_uv_bin), "HOME": str(tmp_path)},
      capture_output=True,
      text=True,
      check=False,
  )
  assert ok_proc.returncode == 0
  assert recorded_args.read_text(encoding="utf-8").splitlines() == [
      "sync",
      "--all-groups",
      "--frozen",
  ]


def test_justfile_uses_positional_args_and_grouped_recipes() -> None:
  just_text = JUSTFILE_PATH.read_text(encoding="utf-8")
  assert re.search(
      r"^set\s+positional-arguments(?:\s*:=\s*true)?\s*$",
      just_text,
      re.MULTILINE,
  )
  assert "{{ args }}" not in just_text
  assert 'PATH="$PWD/.venv/bin:$PATH" uv run pytype src' in just_text

  for ge_recipe in (
      "gemini-enterprise-register",
      "gemini-enterprise-link-agent",
      "gemini-enterprise-update",
      "gemini-enterprise-verify",
      "gemini-enterprise-url",
  ):
    assert re.search(rf"^{re.escape(ge_recipe)}\b", just_text, re.MULTILINE)

  for legacy_alias in (
      "agentspace-register",
      "agentspace-link-agent",
      "agentspace-update",
      "agentspace-verify",
      "agentspace-url",
  ):
    assert f"alias {legacy_alias} :=" in just_text

  seen_groups: set[str] = set()
  lines = just_text.splitlines()
  recipe_header_re = re.compile(r"^([a-z][a-z0-9_-]*)(?:\s+[^:=]+)?:\s*$")
  group_attr_re = re.compile(r"^\[group\('([a-z0-9-]+)'\)\]\s*$")

  for idx, line in enumerate(lines):
    header_match = recipe_header_re.match(line)
    if not header_match:
      continue
    recipe_name = header_match.group(1)
    attr_window = lines[max(0, idx - 3) : idx]
    matched_groups = [
        m.group(1)
        for attr_line in attr_window
        if (m := group_attr_re.match(attr_line)) is not None
    ]
    assert matched_groups, f"Recipe {recipe_name!r} is missing [group('...')]"
    for grp in matched_groups:
      assert grp in EXPECTED_JUST_GROUPS
      seen_groups.add(grp)

  assert seen_groups == EXPECTED_JUST_GROUPS

  just_bin = shutil.which("just")
  if just_bin is not None:
    list_proc = subprocess.run(  # noqa: S603
        [just_bin, "--justfile", str(JUSTFILE_PATH), "--list"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert list_proc.returncode == 0, list_proc.stderr
    for grp in EXPECTED_JUST_GROUPS:
      assert f"[{grp}]" in list_proc.stdout


def test_repo_files_contain_no_internal_domain_or_hostname_leaks() -> None:
  owned_paths = (
      list(WORKFLOWS_DIR.glob("*.y*ml"))
      + [p for p in SCRIPTS_DIR.iterdir() if p.is_file()]
      + [JUSTFILE_PATH, AGENTS_MD_PATH]
  )
  for path in owned_paths:
    content = path.read_text(encoding="utf-8")
    lowered = content.lower()
    for token in STRICT_LEAK_TOKENS + WORKSTATION_LEAK_TOKENS:
      assert token not in lowered, (
          f"Disallowed internal token {token!r} in"
          f" {path.relative_to(REPO_ROOT)}"
      )
    assert (
        "\u2014" not in content
    ), f"Disallowed em-dash in {path.relative_to(REPO_ROOT)}"
    assert all(
        ord(ch) < 128 for ch in content
    ), f"Non-ASCII character found in {path.relative_to(REPO_ROOT)}"

  for repo_file in _iter_repo_text_files():
    rel_str = repo_file.relative_to(REPO_ROOT).as_posix()
    lowered = repo_file.read_text(encoding="utf-8", errors="replace").lower()
    for token in STRICT_LEAK_TOKENS:
      assert (
          token not in lowered
      ), f"Disallowed internal token {token!r} in {rel_str}"
    if rel_str not in PENDING_COMPANION_CLEANUP_PATHS:
      for token in WORKSTATION_LEAK_TOKENS:
        assert (
            token not in lowered
        ), f"Disallowed internal token {token!r} in {rel_str}"


def test_agents_md_documents_python_312_and_gemini_enterprise() -> None:
  agents_text = AGENTS_MD_PATH.read_text(encoding="utf-8")
  assert "3.12" in agents_text
  assert "gemini-enterprise-register" in agents_text
  assert "gemini-enterprise-link-agent" in agents_text
