"""Core functionality for oauth_flow_gemini_enterprise_secops_mcp."""

import logging
import os

logger = logging.getLogger(__name__)


def run_pipeline(name: str = "world") -> str:
  """Execute core pipeline logic.

  Args:
    name: Name parameter to process.

  Returns:
    Formatted greeting string.
  """
  logger.info("Executing pipeline with name: %s", name)
  return (
      f"Hello, {name}! oauth_flow_gemini_enterprise_secops_mcp initialized"
      " successfully."
  )


def get_secops_mcp_endpoint(region: str | None = None) -> str:
  """Build the locational Google Security Operations Remote MCP Server URL.

  Args:
    region: Google Security Operations region identifier, defaulting to
      CHRONICLE_REGION or 'us'. Ignored when SECOPS_MCP_URL is set.

  Returns:
    Full HTTPS MCP endpoint URL.
  """
  override_url = os.environ.get("SECOPS_MCP_URL", "").strip()
  if override_url:
    return override_url
  resolved_region = (region or os.environ.get("CHRONICLE_REGION", "us")).strip()
  return f"https://{resolved_region}-chronicle.googleapis.com/mcp"
