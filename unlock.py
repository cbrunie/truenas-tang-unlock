#!/usr/bin/env python3
"""Unlock passphrase-encrypted TrueNAS datasets at boot, with the passphrase
sealed by clevis against a tang server. The NAS only holds the sealed blob:
stolen and booted away from the tang server, it cannot open its datasets.

Talks to the WebSocket JSON-RPC API: on TrueNAS 25.10 the REST API answers 403
to any key that is not full admin, whatever its privileges.

The passphrase never goes through argv or the environment: clevis gets the
blob on stdin and returns the passphrase on stdout.
"""
import json
import os
import ssl
import subprocess
import time

import websocket  # python3-websocket

DATASETS = os.environ["DATASETS"].split()
URL = os.environ.get("TRUENAS_URL", "wss://127.0.0.1/api/current")
INTERVAL = int(os.environ.get("INTERVAL", "60"))
DONE = ("SUCCESS", "FAILED", "ABORTED")


def secret(name, default_file=None):
    """Value of NAME, or content of the file named by NAME_FILE."""
    if os.environ.get(name):
        return os.environ[name]
    with open(os.environ.get(name + "_FILE", default_file)) as f:
        return f.read().strip()


# The sealed blob is not a secret on its own (useless without tang), so it may
# come inline, which spares writing files on the NAS.
JWE = secret("JWE", "/config/passphrase.jwe").encode()
KEY = secret("TRUENAS_API_KEY")

# ponytail: no certificate check by default, TrueNAS ships a self-signed one.
# Meant for loopback (network_mode: host); set TRUENAS_CA before pointing
# TRUENAS_URL anywhere else.
SSLOPT = ({"ca_certs": os.environ["TRUENAS_CA"]} if os.environ.get("TRUENAS_CA")
          else {"cert_reqs": ssl.CERT_NONE, "check_hostname": False})


def log(*args):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), *args, flush=True)


class Api:
    def __init__(self):
        self.ws = websocket.create_connection(URL, sslopt=SSLOPT, timeout=30)
        self.n = 0
        if not self.call("auth.login_with_api_key", KEY):
            raise RuntimeError("API key refused")

    def call(self, method, *params):
        self.n += 1
        self.ws.send(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}))
        while True:  # skip notifications
            reply = json.loads(self.ws.recv())
            if reply.get("id") == self.n:
                break
        if "error" in reply:
            err = reply["error"]
            raise RuntimeError(f"{method}: {(err.get('data') or {}).get('reason') or err.get('message')}")
        return reply["result"]

    def wait(self, job_id):
        for _ in range(120):
            job = self.call("core.get_jobs", [["id", "=", job_id]])[0]
            if job["state"] in DONE:
                return job
            time.sleep(2)
        return {"state": "TIMEOUT"}


def run_once():
    api = Api()
    try:
        found = api.call("pool.dataset.query", [["id", "in", DATASETS]], {"select": ["id", "locked"]})
        for missing in set(DATASETS) - {d["id"] for d in found}:
            log(f"{missing}: no such dataset")
        locked = [d["id"] for d in found if d["locked"]]
        if not locked:
            return
        try:
            phrase = subprocess.run(["clevis", "decrypt"], input=JWE, capture_output=True,
                                    check=True).stdout.decode()
        except subprocess.CalledProcessError as e:
            log("clevis decrypt failed (tang unreachable?):", e.stderr.decode().strip())
            return
        for ds in locked:
            job_id = api.call("pool.dataset.unlock", ds, {"datasets": [{"name": ds, "passphrase": phrase}]})
            job = api.wait(job_id)
            # Only the outcome: the job arguments carry the passphrase.
            log(f"{ds}: {job['state']}", job.get("result") or job.get("error") or "")
        del phrase
    finally:
        api.ws.close()


log("watching:", " ".join(DATASETS))
# Loops forever: a dataset locked by hand is unlocked again on the next round.
# Stop the app to keep one locked.
while True:
    try:
        run_once()
    except Exception as e:  # middleware not up yet at boot, network, ...
        log("error:", e)
    time.sleep(INTERVAL)
