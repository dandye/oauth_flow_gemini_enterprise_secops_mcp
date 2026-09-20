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
  """Build the regional Google Cloud Remote MCP Server URL for SecOps.

  Args:
    region: Chronicle region identifier (defaults to CHRONICLE_REGION or 'us').

  Returns:
    Full HTTPS MCP endpoint URL.
  """
  resolved_region = region or os.environ.get("CHRONICLE_REGION", "us")
  return f"https://chronicle.{resolved_region}.rep.googleapis.com/mcp"
