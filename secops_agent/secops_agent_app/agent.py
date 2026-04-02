import os
import google.auth
from google.adk.auth import AuthScheme, AuthCredential, AuthCredentialTypes, OAuth2Auth
from google.adk.agents import Agent
from google.adk.models import Gemini
from google.adk.tools import FunctionTool
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
from google.genai import types

from fastapi.openapi.models import OAuth2, OAuthFlows, OAuthFlowAuthorizationCode

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
logger.info("Agent module loaded, logger initialized.")

def get_secops_headers(context) -> dict[str, str]:
    logger.debug("get_secops_headers called")
    
    chronicle_project_id = os.environ.get("CHRONICLE_PROJECT_ID")
    if not chronicle_project_id:
        raise ValueError("CHRONICLE_PROJECT_ID is missing from environment! OneMCP tool calls will fail without it.")
    
    headers = {
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        "x-goog-user-project": chronicle_project_id
    }

    try:
        logger.debug(f"Context Type: {type(context)}")
        
        if hasattr(context, "state"):
            logger.debug(f"context.state Type: {type(context.state)}")
            logger.debug(f"context.state Value: {context.state}")
            
            # Case 1: Mapping (Dict, mappingproxy, etc.)
            if hasattr(context.state, "items"):
                for key, val in context.state.items():
                    if isinstance(val, str) and val.startswith("ya29."):
                        logger.debug(f"Found token in context.state (items) with key '{key}'")
                        headers["Authorization"] = f"Bearer {val}"
                        break
            
            # Case 2: String
            elif isinstance(context.state, str):
                logger.debug("context.state is a string. Checking for 'ya29.'")
                if "ya29." in context.state:
                    logger.debug("Found 'ya29.' in state string!")
                    try:
                        import json
                        # Try to parse as JSON if it looks like it
                        if context.state.strip().startswith("{"):
                            state_dict = json.loads(context.state)
                            for key, val in state_dict.items():
                                if isinstance(val, str) and val.startswith("ya29."):
                                    logger.debug(f"Found token in context.state (parsed JSON) with key '{key}'")
                                    headers["Authorization"] = f"Bearer {val}"
                                    break
                    except Exception as parse_e:
                        logger.warning(f"Failed to parse state string as JSON: {parse_e}")
                    
                    # Fallback Regex if not parsed or not found in keys
                    if "Authorization" not in headers:
                        import re
                        match = re.search(r'(ya29\.[a-zA-Z0-9_\-]+)', context.state)
                        if match:
                            token = match.group(1)
                            logger.debug("Extracted token from state string using regex")
                            headers["Authorization"] = f"Bearer {token}"

        # If still not found, dump dir(context) and check _invocation_context
        if "Authorization" not in headers:
            logger.debug(f"Context Dir: {dir(context)}")
            if hasattr(context, "_invocation_context"):
                inv_ctx = context._invocation_context
                logger.debug(f"InvocationContext Type: {type(inv_ctx)}")
                logger.debug(f"InvocationContext Dir: {dir(inv_ctx)}")
                if hasattr(inv_ctx, "state"):
                    logger.debug(f"inv_ctx.state Value: {getattr(inv_ctx, 'state')}")

    except Exception as e:
        logger.error(f"Error in get_secops_headers Shotgun Logging: {e}", exc_info=True)

    safe_headers = {k: "REDACTED" if k == "Authorization" else v for k, v in headers.items()}
    logger.debug(f"Returning headers: {safe_headers}")
    
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

async def get_current_datetime() -> str:
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
    logger.info("create_agent() entry")
    load_dotenv()
    
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id and os.environ.get("REASONING_ENGINE_DEPLOYMENT") != "True":
        try:
            _, project_id = google.auth.default()
        except Exception:
            pass

    os.environ["GOOGLE_CLOUD_PROJECT"] = project_id or ""
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

    oauth_client_id = os.environ.get("OAUTH_CLIENT_ID")
    oauth_client_secret = os.environ.get("OAUTH_CLIENT_SECRET")

    # auth_scheme = OAuth2(
    #     flows=OAuthFlows(
    #         authorizationCode=OAuthFlowAuthorizationCode(
    #             authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    #             tokenUrl="https://oauth2.googleapis.com/token",
    #             scopes={
    #                 "https://www.googleapis.com/auth/chronicle": "Chronicle API",
    #                 "openid": "OpenID",
    #                 #"email": "Email",
    #             },
    #         )
    #     )
    # )

    # auth_credential = AuthCredential(
    #     auth_type=AuthCredentialTypes.OAUTH2,
    #     oauth2=OAuth2Auth(
    #         client_id=oauth_client_id,
    #         client_secret=oauth_client_secret,
    #     ),
    # )

    logger.info("Defining MCP connection params and toolset...")
    secops_toolset = create_mcp_toolset(region) # No internal OAuth
    logger.info("MCP toolset defined.")

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
    logger.info("Agent object created.")
    return agent_obj
