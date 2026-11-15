#!/usr/bin/env python3
"""Environment Variable Validation Utility.

This module provides validation for environment variables to detect when users
have copied .env.example without updating placeholder values.
"""

import os
import re
from typing import NamedTuple


class ValidationError(NamedTuple):
  """Represents an environment variable validation error."""

  variable: str
  current_value: str
  error_type: str  # "missing" or "placeholder"
  suggestion: str


APP_ID_ALIASES = ("GEMINI_ENTERPRISE_APP_ID", "AGENTSPACE_APP_ID")

# Placeholder patterns from .env.example
# Maps environment variable names to their placeholder values/patterns
PLACEHOLDER_PATTERNS: dict[str, list[str]] = {
    "GCP_PROJECT_ID": ["your-gcp-project-id", "your-project-id"],
    "GCP_PROJECT_NUMBER": ["123456789012"],
    "GCP_STAGING_BUCKET": ["gs://your-staging-bucket"],
    "CHRONICLE_PROJECT_ID": [
        "your-chronicle-project-id",
        "your-gcp-project-id",
        "your-project-id",
    ],
    "CHRONICLE_CUSTOMER_ID": [
        "a1b2c3d4-e5f6-4321-abcd-ef1234567890",
        "00000000-0000-0000-0000-000000000000",
        "your-customer-uuid",
    ],
    "GEMINI_ENTERPRISE_APP_ID": [
        "your-gemini-enterprise-app-id",
        "your-agentspace-app-id",
        "your-app-id",
    ],
    "AGENTSPACE_APP_ID": [
        "your-agentspace-app-id",
        "your-gemini-enterprise-app-id",
        "your-app-id",
    ],
    "GEMINI_ENTERPRISE_AGENT_ID": ["your-agent-id"],
    "AGENTSPACE_AGENT_ID": ["your-agent-id"],
}

# Additional pattern-based checks for values that contain placeholders
PLACEHOLDER_REGEX_PATTERNS = [
    (r"your-[a-z-]+", "placeholder pattern 'your-...'"),
    (r"/path/to/", "placeholder path '/path/to/...'"),
    (r"^123456789012$", "example project number"),
    (
        r"^(?:a1b2c3d4-e5f6-4321-abcd-ef1234567890|00000000-0000-0000-0000-000000000000)$",
        "example placeholder UUID",
    ),
]


def is_placeholder_value(var_name: str, value: str) -> tuple[bool, str | None]:
  """Check if a value is a placeholder from .env.example.

  Args:
      var_name: Name of the environment variable.
      value: Current value of the variable.

  Returns:
      Tuple of (is_placeholder, reason):
      - is_placeholder: True if value appears to be a placeholder.
      - reason: Description of why it is considered a placeholder, or None.
  """
  if not value:
    return False, None

  # Check exact matches for known placeholders
  if var_name in PLACEHOLDER_PATTERNS:
    for placeholder in PLACEHOLDER_PATTERNS[var_name]:
      if value == placeholder:
        return True, f"matches .env.example placeholder: '{placeholder}'"

  # Check if value contains common placeholder patterns
  for pattern, description in PLACEHOLDER_REGEX_PATTERNS:
    if re.search(pattern, value):
      return True, f"contains {description}"

  return False, None


def resolve_gemini_enterprise_app_id(
    env_vars: dict[str, str] | None = None,
) -> str | None:
  """Resolve the Gemini Enterprise app ID from preferred or legacy env vars.

  Checks GEMINI_ENTERPRISE_APP_ID first and falls back to AGENTSPACE_APP_ID,
  ignoring unset or placeholder values.

  Args:
      env_vars: Optional dict of env vars to inspect (defaults to os.environ).

  Returns:
      Resolved non-placeholder app ID, or None if not configured.
  """
  if env_vars is None:
    env_vars = dict(os.environ)

  for key in APP_ID_ALIASES:
    candidate = env_vars.get(key, "")
    if candidate and not is_placeholder_value(key, candidate)[0]:
      return candidate
  return None


def validate_env_vars(
    required_vars: list[str], env_vars: dict[str, str] | None = None
) -> tuple[bool, list[ValidationError]]:
  """Validate required environment variables.

  Checks for both missing variables and placeholder values from .env.example.
  Supports GEMINI_ENTERPRISE_APP_ID and AGENTSPACE_APP_ID interchangeably.

  Args:
      required_vars: List of required environment variable names.
      env_vars: Optional dict of env vars to check (defaults to os.environ).

  Returns:
      Tuple of (is_valid, errors):
      - is_valid: True if all validations pass.
      - errors: List of ValidationError objects for any issues found.
  """
  if env_vars is None:
    env_vars = dict(os.environ)

  errors: list[ValidationError] = []

  for var in required_vars:
    if var in APP_ID_ALIASES:
      if resolve_gemini_enterprise_app_id(env_vars):
        continue
      raw_val = (
          env_vars.get(var)
          or env_vars.get("GEMINI_ENTERPRISE_APP_ID")
          or env_vars.get("AGENTSPACE_APP_ID")
          or ""
      )
      if not raw_val:
        errors.append(
            ValidationError(
                variable=var,
                current_value="",
                error_type="missing",
                suggestion=(
                    "Set GEMINI_ENTERPRISE_APP_ID (or AGENTSPACE_APP_ID) in"
                    " your .env file"
                ),
            )
        )
      else:
        errors.append(
            ValidationError(
                variable=var,
                current_value=raw_val,
                error_type="placeholder",
                suggestion=(
                    "Replace placeholder value with your Gemini Enterprise"
                    f" app ID in {var}"
                ),
            )
        )
      continue

    value = env_vars.get(var)

    # Check if missing
    if not value:
      errors.append(
          ValidationError(
              variable=var,
              current_value="",
              error_type="missing",
              suggestion=f"Set {var} in your .env file",
          )
      )
      continue

    # Check if it's a placeholder value
    is_placeholder, _ = is_placeholder_value(var, value)
    if is_placeholder:
      errors.append(
          ValidationError(
              variable=var,
              current_value=value,
              error_type="placeholder",
              suggestion=f"Replace placeholder value with actual {var}",
          )
      )

  is_valid = len(errors) == 0
  return is_valid, errors


def format_validation_errors(errors: list[ValidationError]) -> str:
  """Format validation errors into a user-friendly error message.

  Args:
      errors: List of ValidationError objects.

  Returns:
      Formatted error message string.
  """
  if not errors:
    return ""

  lines = [
      "[ERROR] Environment variable validation failed:\n",
  ]

  # Group by error type
  missing = [e for e in errors if e.error_type == "missing"]
  placeholders = [e for e in errors if e.error_type == "placeholder"]

  if missing:
    lines.append("Missing required variables:")
    for error in missing:
      lines.append(f"  - {error.variable}")
    lines.append("")

  if placeholders:
    lines.append(
        "Variables contain placeholder values from .env.example"
        " (must be updated):"
    )
    for error in placeholders:
      value_display = error.current_value
      if len(value_display) > 50:
        value_display = value_display[:47] + "..."
      lines.append(f"  - {error.variable}: '{value_display}'")
    lines.append("")

  lines.extend(
      [
          "Action required:",
          "1. Copy .env.example to .env (if you haven't already)",
          (
              "2. Edit .env and replace ALL placeholder values with your actual"
              " configuration"
          ),
          "3. Refer to .env.example comments for guidance on each variable",
      ]
  )

  return "\n".join(lines)


def validate_file_path_exists(
    var_name: str, file_path: str
) -> ValidationError | None:
  """Validate that a file path exists and is not a placeholder.

  Args:
      var_name: Name of the environment variable.
      file_path: Path to validate.

  Returns:
      ValidationError if path is invalid, None otherwise.
  """
  is_placeholder, _ = is_placeholder_value(var_name, file_path)
  if is_placeholder:
    readable_name = var_name.lower().replace("_", " ")
    return ValidationError(
        variable=var_name,
        current_value=file_path,
        error_type="placeholder",
        suggestion=f"Replace with actual path to your {readable_name}",
    )

  if not os.path.exists(file_path):
    return ValidationError(
        variable=var_name,
        current_value=file_path,
        error_type="missing",
        suggestion=f"File does not exist: {file_path}",
    )

  return None
