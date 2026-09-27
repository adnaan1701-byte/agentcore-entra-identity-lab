"""Shared helpers: lab state files, token cache, MCP JSON-RPC calls to the gateway."""

import base64
import json
import os
import sys

import msal
import requests

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LAB = os.path.join(ROOT, ".lab")
TOKENS = os.path.join(LAB, "tokens")


def load(name):
    path = os.path.join(LAB, f"{name}.json")
    if not os.path.exists(path):
        sys.exit(f"Missing {path}. Run the earlier lab step first.")
    with open(path) as f:
        return json.load(f)


def decode_claims(token):
    """Decode JWT payload WITHOUT verifying it. For display only."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _app(entra, persona):
    os.makedirs(TOKENS, exist_ok=True)
    cache = msal.SerializableTokenCache()
    cache_path = os.path.join(TOKENS, f"{persona}.cache.bin")
    if os.path.exists(cache_path):
        cache.deserialize(open(cache_path).read())
    app = msal.PublicClientApplication(
        entra["client_app_id"],
        authority=f"https://login.microsoftonline.com/{entra['tenant_id']}",
        token_cache=cache)
    return app, cache, cache_path


def get_token(persona, scopes=None, interactive=True):
    """Return an access token for `persona`, using the cache or device-code sign-in."""
    entra = load("entra")
    scopes = scopes or [entra["scope"]]
    app, cache, cache_path = _app(entra, persona)
    upn = entra["users"][persona]["upn"]
    accounts = [a for a in app.get_accounts() if a["username"].lower() == upn.lower()]
    result = app.acquire_token_silent(scopes, account=accounts[0]) if accounts else None
    if not result:
        if not interactive:
            return None
        flow = app.initiate_device_flow(scopes=scopes)
        if "user_code" not in flow:
            sys.exit(f"Device flow failed: {flow}")
        print("\n" + "=" * 70)
        print(f"Sign in as {upn}")
        print(f"Password: {entra['users'][persona]['password']}")
        print("Use a private/incognito browser window so you don't reuse another session.")
        print(flow["message"])
        print("=" * 70)
        result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        sys.exit(f"Token request failed: {result.get('error')}: {result.get('error_description')}")
    if cache.has_state_changed:
        with open(cache_path, "w") as f:
            f.write(cache.serialize())
    return result["access_token"]


class Gateway:
    def __init__(self):
        self.url = load("aws")["gateway_url"]
        self._id = 0

    def rpc(self, method, params=None, token=None):
        """Send one MCP JSON-RPC request. Returns (http_status, parsed_json_or_text)."""
        self._id += 1
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        r = requests.post(self.url, headers=headers, json=body, timeout=60)
        text = r.text
        if r.headers.get("Content-Type", "").startswith("text/event-stream"):
            for line in text.splitlines():
                if line.startswith("data: "):
                    try:
                        return r.status_code, json.loads(line[6:])
                    except json.JSONDecodeError:
                        pass
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, text[:500]

    def call_tool(self, name, arguments, token):
        return self.rpc("tools/call", {"name": f"docs___{name}", "arguments": arguments}, token)

    def list_tools(self, token):
        return self.rpc("tools/list", {}, token)


def tool_payload(resp_json):
    """Extract the tool's JSON result from an MCP tools/call response, if any."""
    if not isinstance(resp_json, dict):
        return None
    content = (resp_json.get("result") or {}).get("content") or []
    for c in content:
        if c.get("type") == "text":
            try:
                return json.loads(c["text"])
            except (ValueError, TypeError):
                return {"raw": c["text"]}
    return None
