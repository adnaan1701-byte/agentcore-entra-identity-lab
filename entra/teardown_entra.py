"""Delete everything setup_entra.py created (apps, service principals, test users)."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from setup_entra import STATE_FILE, Graph, az_graph_token  # noqa: E402


def main():
    if not os.path.exists(STATE_FILE):
        sys.exit(f"No {STATE_FILE}; nothing to delete.")
    state = json.load(open(STATE_FILE))
    g = Graph(az_graph_token())
    for key, u in state["users"].items():
        g.call("DELETE", f"/users/{u['oid']}", ok=(204, 404))
        print(f"deleted user {u['upn']}")
    for obj in ("client_object_id", "api_object_id"):
        g.call("DELETE", f"/applications/{state[obj]}", ok=(204, 404))
        print(f"deleted app registration {state[obj]}")
    os.remove(STATE_FILE)
    print("Entra teardown complete. (Deleted objects sit in the Entra recycle bin for 30 days.)")


if __name__ == "__main__":
    main()
