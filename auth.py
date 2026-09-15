import json
import os
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.labels",
]

def run_oauth_flow():
    client_config = {
        "installed": {
            "client_id": os.environ.get("OAUTH_CLIENT_ID", ""),
            "client_secret": os.environ.get("OAUTH_CLIENT_SECRET", ""),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }

    # Require these for InstalledAppFlow to work properly
    if not client_config["installed"]["client_id"] or not client_config["installed"]["client_secret"]:
        print("Error: OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET environment variables must be set.")
        return None

    flow = InstalledAppFlow.from_client_config(client_config, scopes=SCOPES)
    creds = flow.run_local_server(port=0)

    cred_dict = json.loads(creds.to_json())
    cred_dict["type"] = "authorized_user"
    cred_dict["quota_project_id"] = os.environ.get("GOOGLE_CLOUD_PROJECT")

    with open("token.json", "w") as f:
        json.dump(cred_dict, f, indent=2)
    return creds

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    run_oauth_flow()
