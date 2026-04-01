import os
import google.auth
from google.adk.auth import AuthScheme, AuthCredential, AuthCredentialTypes, OAuth2Auth
from google.adk.agents import Agent
from google.adk.models import Gemini
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
from google.genai import types

from fastapi.openapi.models import OAuth2, OAuthFlows, OAuthFlowAuthorizationCode

from opentelemetry.instrumentation.google_genai import GoogleGenAiSdkInstrumentor
from dotenv import load_dotenv
import logging
import sys

def get_secops_headers(context) -> dict[str, str]:
    # Read from environment AT RUNTIME
    chronicle_project_id = os.environ.get("CHRONICLE_PROJECT_ID")
    customer_id = os.environ.get("CHRONICLE_CUSTOMER_ID")
    gemini_auth_id = os.environ.get("GEMINI_AUTHORIZATION_ID")
    region = os.environ.get("CHRONICLE_REGION", "us")

    headers = {
        "Accept": "text/event-stream",
        "Content-Type": "application/json"
    }
    
    # Only add the project header if we actually have a value
    if chronicle_project_id:
        headers["x-goog-user-project"] = chronicle_project_id
    else:
        # Critical for tool execution, though list_tools might still work
        logging.critical("CHRONICLE_PROJECT_ID is missing from environment! OneMCP tool calls *will* fail without a routing context.")

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

def create_agent():
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
    chronicle_project_id = os.environ.get("CHRONICLE_PROJECT_ID")
    gemini_auth_id = os.environ.get("GEMINI_AUTHORIZATION_ID")

    oauth_client_id = os.environ.get("OAUTH_CLIENT_ID")
    oauth_client_secret = os.environ.get("OAUTH_CLIENT_SECRET")

    auth_scheme = OAuth2(
        flows=OAuthFlows(
            authorizationCode=OAuthFlowAuthorizationCode(
                authorizationUrl="https://accounts.google.com/o/oauth2/auth",
                tokenUrl="https://oauth2.googleapis.com/token",
                scopes={
                    "https://www.googleapis.com/auth/chronicle": "Chronicle API",
                    "openid": "OpenID",
                    #"email": "Email",
                },
            )
        )
    )

    auth_credential = AuthCredential(
        auth_type=AuthCredentialTypes.OAUTH2,
        oauth2=OAuth2Auth(
            client_id=oauth_client_id,
            client_secret=oauth_client_secret,
        ),
    )

    secops_toolset = create_mcp_toolset(region, auth_scheme, auth_credential)

    return Agent(
        name="secops_agent",
        model=Gemini(
            model="gemini-3.1-flash-lite-preview",
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
        tools=[secops_toolset],
    )
