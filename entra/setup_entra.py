"""
Create the Entra ID side of the lab with Microsoft Graph (uses your `az login`).

Creates:
  * API app registration "agentlab-gateway-api"
      - Application ID URI api://<appId>, delegated scope access_as_user
      - accepts v2.0 access tokens only (requestedAccessTokenVersion = 2)
      - app roles: Finance.Analyst, Finance.Contractor, HR.Manager
      - enterprise app with "assignment required"
  * Client app registration "agentlab-agent-client" (public client, device code)
      - pre-authorised on the API scope, so users get no consent prompt
  * Test users alice / bob / carol (+ dave, who has NO role, for a negative test)
  * App role assignments and the HR clearance values used by the lab

Writes .lab/entra.json (contains test passwords: keep it out of git).

Usage:
  az login --tenant <your-tenant-id> --allow-no-subscriptions
  python entra/setup_entra.py
"""

import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import time
import uuid

import requests

GRAPH = "https://graph.microsoft.com/v1.0"
PREFIX = "agentlab"
STATE_DIR = os.path.join(os.path.dirname(__file__), "..", ".lab")
STATE_FILE = os.path.join(STATE_DIR, "entra.json")
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

APP_ROLES = {
    "Finance.Analyst": "Finance analyst: department fin, role analyst",
    "Finance.Contractor": "Finance contractor: department fin, role contractor",
    "HR.Manager": "HR manager: department hr, role manager",
}

# persona -> (display name, app role or None, clearance held in the HR store)
PERSONAS = {
    "alice": ("Alice Analyst (Agent Lab)", "Finance.Analyst", "internal"),
    "bob": ("Bob HRManager (Agent Lab)", "HR.Manager", "restr"),
    "carol": ("Carol Contractor (Agent Lab)", "Finance.Contractor", "public"),
    "dave": ("Dave NoRole (Agent Lab)", None, "internal"),
}


def az_graph_token():
    az = shutil.which("az") or shutil.which("az.cmd")
    if not az:
        sys.exit("Azure CLI not found. Install it and run `az login` first.")
    out = subprocess.run(
        [az, "account", "get-access-token", "--resource-type", "ms-graph", "-o", "json"],
        capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"`az account get-access-token` failed. Run `az login --allow-no-subscriptions` first.\n{out.stderr}")
    return json.loads(out.stdout)["accessToken"]


class Graph:
    def __init__(self, token):
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

    def call(self, method, path, body=None, ok=(200, 201, 204), retries=6):
        for attempt in range(retries):
            r = self.s.request(method, GRAPH + path, data=json.dumps(body) if body is not None else None)
            if r.status_code in ok:
                return r.json() if r.content else {}
            # New objects take a few seconds to replicate across Entra.
            if r.status_code in (400, 404) and attempt < retries - 1 and (
                    "does not exist" in r.text or "Request_ResourceNotFound" in r.text):
                time.sleep(5)
                continue
            if r.status_code == 429 and attempt < retries - 1:
                time.sleep(int(r.headers.get("Retry-After", "5")))
                continue
            sys.exit(f"Graph {method} {path} failed: {r.status_code}\n{r.text}")

    def find_app(self, name):
        res = self.call("GET", f"/applications?$filter=displayName eq '{name}'")
        return res.get("value", [])


def password():
    alphabet = string.ascii_letters + string.digits
    return "Lab!" + "".join(secrets.choice(alphabet) for _ in range(16)) + "9a"


def main():
    if os.path.exists(STATE_FILE):
        sys.exit(f"{STATE_FILE} already exists. Run entra/teardown_entra.py first, or delete the file.")
    g = Graph(az_graph_token())

    tenant_id = g.call("GET", "/organization")["value"][0]["id"]
    domain = next(d["id"] for d in g.call("GET", "/domains")["value"] if d.get("isDefault"))
    print(f"Tenant: {tenant_id}  default domain: {domain}")

    for name in (f"{PREFIX}-gateway-api", f"{PREFIX}-agent-client"):
        if g.find_app(name):
            sys.exit(f"An app named {name} already exists. Delete it (or run teardown) and retry.")

    # 1. API app ------------------------------------------------------------
    scope_id = str(uuid.uuid4())
    role_ids = {value: str(uuid.uuid4()) for value in APP_ROLES}
    scope = {
        "id": scope_id, "value": "access_as_user", "type": "User", "isEnabled": True,
        "adminConsentDisplayName": "Call the agent gateway as the signed-in user",
        "adminConsentDescription": "Lets the agent call AgentCore Gateway on behalf of the signed-in user.",
        "userConsentDisplayName": "Call the agent gateway as you",
        "userConsentDescription": "Lets the agent call AgentCore Gateway on your behalf.",
    }
    api_app = g.call("POST", "/applications", {
        "displayName": f"{PREFIX}-gateway-api",
        "signInAudience": "AzureADMyOrg",
        "api": {"requestedAccessTokenVersion": 2, "oauth2PermissionScopes": [scope]},
        "appRoles": [{
            "id": role_ids[v], "value": v, "displayName": v, "description": d,
            "allowedMemberTypes": ["User"], "isEnabled": True} for v, d in APP_ROLES.items()],
    })
    api_app_id, api_obj_id = api_app["appId"], api_app["id"]
    g.call("PATCH", f"/applications/{api_obj_id}", {"identifierUris": [f"api://{api_app_id}"]})
    api_sp = g.call("POST", "/servicePrincipals", {
        "appId": api_app_id, "appRoleAssignmentRequired": True,
        "tags": ["WindowsAzureActiveDirectoryIntegratedApp"]})
    print(f"API app:    {api_app_id}")

    # 2. Client app (public client for device-code sign-in) ----------------
    client_app = g.call("POST", "/applications", {
        "displayName": f"{PREFIX}-agent-client",
        "signInAudience": "AzureADMyOrg",
        "isFallbackPublicClient": True,
        "publicClient": {"redirectUris": ["http://localhost"]},
        "requiredResourceAccess": [
            {"resourceAppId": api_app_id, "resourceAccess": [{"id": scope_id, "type": "Scope"}]},
        ],
    })
    client_app_id = client_app["appId"]
    client_sp = g.call("POST", "/servicePrincipals", {"appId": client_app_id})
    print(f"Client app: {client_app_id}")

    # Pre-authorise the client on the API scope (no consent prompt for users).
    # PATCH replaces the whole `api` object, so resend every field.
    g.call("PATCH", f"/applications/{api_obj_id}", {"api": {
        "requestedAccessTokenVersion": 2,
        "oauth2PermissionScopes": [scope],
        "preAuthorizedApplications": [{"appId": client_app_id, "delegatedPermissionIds": [scope_id]}],
    }})

    # Tenant-wide consent for sign-in basics + User.Read (used by the wrong-audience test).
    graph_sp = g.call("GET", f"/servicePrincipals?$filter=appId eq '{GRAPH_APP_ID}'")["value"][0]
    g.call("POST", "/oauth2PermissionGrants", {
        "clientId": client_sp["id"], "consentType": "AllPrincipals",
        "resourceId": graph_sp["id"], "scope": "openid profile offline_access User.Read"})

    # 3. Users + role assignments -------------------------------------------
    users = {}
    for key, (display, role, clearance) in PERSONAS.items():
        upn = f"{key}.{PREFIX}@{domain}"
        pw = password()
        u = g.call("POST", "/users", {
            "accountEnabled": True, "displayName": display, "mailNickname": f"{key}{PREFIX}",
            "userPrincipalName": upn,
            "passwordProfile": {"password": pw, "forceChangePasswordNextSignIn": False}})
        if role:
            g.call("POST", f"/servicePrincipals/{api_sp['id']}/appRoleAssignedTo", {
                "principalId": u["id"], "resourceId": api_sp["id"], "appRoleId": role_ids[role]})
        users[key] = {"upn": upn, "password": pw, "oid": u["id"], "app_role": role, "clearance": clearance}
        print(f"User {key:6} {upn}  role={role}  clearance={clearance}")

    os.makedirs(STATE_DIR, exist_ok=True)
    state = {
        "tenant_id": tenant_id, "domain": domain,
        "api_app_id": api_app_id, "api_object_id": api_obj_id, "api_sp_id": api_sp["id"],
        "client_app_id": client_app_id, "client_object_id": client_app["id"], "client_sp_id": client_sp["id"],
        "scope": f"api://{api_app_id}/access_as_user",
        "discovery_url": f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration",
        "users": users,
    }
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    print(f"\nSaved {os.path.abspath(STATE_FILE)} (contains test passwords; never commit it).")
    print("Next: python client/get_token.py alice")


if __name__ == "__main__":
    main()
