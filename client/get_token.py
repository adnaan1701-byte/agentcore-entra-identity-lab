"""
Sign in as a persona (device-code flow) and show the claims in the Entra token.

  python client/get_token.py alice
  python client/get_token.py all      # alice, bob, carol, dave in turn

dave has no app role, so Entra refuses to issue him a token for the API
(the enterprise app has "assignment required"). That refusal is a test result.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import LAB, decode_claims, get_token, load  # noqa: E402

SHOW = ["iss", "aud", "azp", "tid", "oid", "preferred_username", "roles", "scp", "ver", "exp"]


def show(persona):
    token = get_token(persona)
    claims = decode_claims(token)
    print(f"\n{persona}: key claims in the access token")
    for k in SHOW:
        print(f"  {k:20} {claims.get(k)}")
    out = os.path.join(LAB, "tokens", f"{persona}.claims.json")
    with open(out, "w") as f:
        json.dump({k: claims.get(k) for k in SHOW}, f, indent=2)
    print(f"  (saved {out}; paste the raw token into https://jwt.ms to explore it)")


if __name__ == "__main__":
    who = sys.argv[1] if len(sys.argv) > 1 else "alice"
    personas = list(load("entra")["users"]) if who == "all" else [who]
    for p in personas:
        try:
            show(p)
        except SystemExit as e:
            print(f"\n{p}: {e}")
