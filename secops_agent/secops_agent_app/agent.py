import os
import google.auth
from google.adk.auth import AuthScheme, AuthCredential
from google.adk.agents import Agent
from google.adk.models import Gemini
from google.adk.tools import FunctionTool
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
from google.genai import types



from opentelemetry.instrumentation.google_genai import GoogleGenAiSdkInstrumentor
from dotenv import load_dotenv
import logging
import sys

# Configure logging for Reasoning Engine environment
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.debug("Agent module loaded, logger initialized.")

def get_secops_headers(context) -> dict[str, str]:
    
    chronicle_project_id = os.environ.get("CHRONICLE_PROJECT_ID")
    if not chronicle_project_id:
        raise ValueError("CHRONICLE_PROJECT_ID is missing from environment! OneMCP tool calls will fail without it.")
    
    headers = {
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        "x-goog-user-project": chronicle_project_id
    }

    try:
        # Safely resolve items from state (falling back to empty list if no items method is present)
        for _, val in getattr(getattr(context, "state", {}), "items", lambda: [])():
            if isinstance(val, str) and val.startswith("ya29."):
                headers["Authorization"] = f"Bearer {val}"
                break
    except Exception as e:
        logger.error(f"Error in get_secops_headers: {e}", exc_info=True)
    
    return headers

def create_mcp_toolset(region, auth_scheme=None, auth_credential=None) -> McpToolset:
    # Matching working example pattern: https://chronicle.{region}.rep.googleapis.com/mcp
    secops_mcp_url = f"https://chronicle.{region}.rep.googleapis.com/mcp"
    
    logging.info(f"Initializing MCP Toolset with URL: {secops_mcp_url}")
    
    return McpToolset(
        connection_params=StreamableHTTPConnectionParams(url=secops_mcp_url),
        header_provider=get_secops_headers,
        errlog=None, # explicitly None to prevent sys.stderr capturing (which cannot be pickled)
        auth_scheme=auth_scheme,
        auth_credential=auth_credential
    )

def get_current_datetime() -> str:
    """Get the current date and time in ISO 8601 format and epoch seconds.
    
    Use this tool when you need to provide a timestamp for tool calls or when
    answering questions about time (e.g., 'past 24 hours').
    
    Returns:
        A JSON string containing:
        - iso: The current date and time in ISO 8601 format (e.g., YYYY-MM-DDTHH:MM:SSZ)
        - epoch: The current date and time as Unix epoch seconds (integer)
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    return f'{{"iso": "{now.strftime("%Y-%m-%dT%H:%M:%SZ")}", "epoch": {int(now.timestamp())}}}'


def create_agent():
    logger.debug("create_agent() entry")
    if not os.environ.get("RUNNING_IN_CLOUD"):
        load_dotenv()
    
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT_ID")
    if not project_id and os.environ.get("REASONING_ENGINE_DEPLOYMENT") != "True":
        try:
            _, project_id = google.auth.default()
        except Exception:
            pass

    if not project_id:
        raise ValueError("GOOGLE_CLOUD_PROJECT environment variable is missing and could not be auto-discovered.")

    os.environ["GOOGLE_CLOUD_PROJECT"] = project_id
    os.environ["GOOGLE_CLOUD_LOCATION"] = "global"
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"

    if os.environ.get("REASONING_ENGINE_DEPLOYMENT") != "True":
         GoogleGenAiSdkInstrumentor().instrument()

    Agent.version = "1.0"
    os.environ["GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY"] = "True"

    region = os.environ.get("CHRONICLE_REGION", "us")
    customer_id = os.environ.get("CHRONICLE_CUSTOMER_ID")
    if not customer_id:
        raise ValueError("CHRONICLE_CUSTOMER_ID is missing from environment! The agent will not know which customer to query.")
        
    chronicle_project_id = os.environ.get("CHRONICLE_PROJECT_ID")
    gemini_auth_id = os.environ.get("GEMINI_AUTHORIZATION_ID")
    if not gemini_auth_id:
        raise ValueError("GEMINI_AUTHORIZATION_ID is missing from environment! OneMCP tool calls will fail without an authorization ID.")

    logger.debug("Defining MCP connection params and toolset...")
    secops_toolset = create_mcp_toolset(region) # No internal OAuth
    logger.debug("MCP toolset defined.")

    agent_obj = Agent(
        name="secops_agent",
        model=Gemini(
            model="gemini-2.5-pro",
            retry_options=types.HttpRetryOptions(attempts=3),
        ),
        instruction=f"""You are a Google SecOps assistant. 
You have access to the remote SecOps MCP server which provides tools for SIEM and SOAR operations.
Always use the provided tools to fetch information from Chronicle.

Current Tenant Information:
- Project ID: {chronicle_project_id}
- Customer ID: {customer_id}
- Region: {region}

When calling tools, ensure you use these identifiers if the tool requires them.
""",
        tools=[secops_toolset, FunctionTool(func=get_current_datetime)],
    )
    logger.debug("Agent object created.")
    return agent_obj
