"""Create a GitHub-safe copy of the lab next to this folder (../agentlab-public).

Leaves out: .lab (passwords, tokens), .venv, caches, raw results.json.
Redacts in every text file: AWS account ID, Entra tenant ID, user object IDs,
app IDs, the gateway ID, the bucket, the domain and test passwords.
"""
import json
import os
import re
import shutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEST = os.path.join(os.path.dirname(ROOT), "agentlab-public")
SKIP_DIRS = {".lab", ".venv", "__pycache__", ".pytest_cache", ".git"}
SKIP_FILES = {"results.json"}
SKIP_EXT = {".bin", ".zip"}
TEXT_EXT = {".py", ".md", ".json", ".cedar", ".txt", ".csv", ".gitignore", ""}


def load(name):
    p = os.path.join(ROOT, ".lab", f"{name}.json")
    return json.load(open(p)) if os.path.exists(p) else {}


entra, aws = load("entra"), load("aws")
subs = {}
if aws.get("account"):
    subs[aws["account"]] = "<AWS_ACCOUNT_ID>"
if aws.get("gateway_id"):
    subs[aws["gateway_id"]] = "<GATEWAY_ID>"
if aws.get("bucket"):
    subs[aws["bucket"]] = "<BUCKET>"
for key, label in (("tenant_id", "<TENANT_ID>"), ("api_app_id", "<API_APP_ID>"),
                   ("client_app_id", "<CLIENT_APP_ID>"), ("domain", "<TENANT_DOMAIN>")):
    if entra.get(key):
        subs[entra[key]] = label
for name, u in entra.get("users", {}).items():
    subs[u["oid"]] = f"<{name.upper()}_OID>"
    subs[u["oid"][:8]] = f"<{name.upper()}_OID8>"
    if u.get("password"):
        subs[u["password"]] = "<REDACTED_PASSWORD>"

if os.path.exists(DEST):
    shutil.rmtree(DEST)
count = 0
for base, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    rel = os.path.relpath(base, ROOT)
    os.makedirs(os.path.join(DEST, rel), exist_ok=True)
    for fn in files:
        if fn in SKIP_FILES or os.path.splitext(fn)[1].lower() in SKIP_EXT:
            continue
        src, dst = os.path.join(base, fn), os.path.join(DEST, rel, fn)
        ext = os.path.splitext(fn)[1].lower()
        if ext in TEXT_EXT or fn == ".gitignore":
            text = open(src, encoding="utf-8", errors="replace").read()
            for old in sorted(subs, key=len, reverse=True):
                text = text.replace(old, subs[old])
            text = re.sub(r"ASIA[A-Z0-9]{16}|AKIA[A-Z0-9]{16}", "<REDACTED_KEY>", text)
            open(dst, "w", encoding="utf-8").write(text)
        else:
            shutil.copy2(src, dst)
        count += 1

leftover = []
for base, _, files in os.walk(DEST):
    for fn in files:
        try:
            t = open(os.path.join(base, fn), encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        leftover += [os.path.join(base, fn) for k in subs if k in t]
print(f"Copied {count} files to {DEST}")
print("Redacted:", ", ".join(sorted(set(subs.values()))) or "(nothing found in .lab)")
print("Leftover identifiers:", "none" if not leftover else leftover[:5])
