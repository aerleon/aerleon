#!/usr/bin/env python3
"""
Reproduce: BlockingIOError: [Errno 11] Resource temporarily unavailable
Scenario: Flask API in dev mode (Werkzeug reloader)

USAGE (from the repository root):

  docker build -f repro_tests/BlockingIOErrorFlask/Dockerfile -t aerleon-repro-flask .
  docker run --rm --ulimit nproc=200:200 aerleon-repro-flask

USER'S REPORT:
  "I am / was running flaskapi in dev mode, so I think it creates an extra
   thread that looks for changes in the filesystem to reload on code updates"

WHAT THIS REPRODUCES:
  Flask's dev server (debug=True) uses Werkzeug's reloader, which spawns a
  child process that monitors the filesystem for changes.  This child process
  and its associated threads consume task slots from RLIMIT_NPROC.

  When aerleon.api.Generate() is called from a Flask route handler, it
  creates a multiprocessing.SyncManager which calls fork().  Under process
  slot pressure (common in containerized/production environments), fork()
  returns EAGAIN (errno 11), surfaced as BlockingIOError.

ROOT CAUSE:
  api.Generate() -> _Generate() -> context.Manager() -> fork()
  The SyncManager fork is unnecessary when max_renderers=1 (the default).
"""

import os
import resource
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

# Self-terminate if anything hangs (Flask reloader, stuck requests, etc.)
signal.alarm(30)

print(f"Python:    {sys.version.split()[0]}")
print(f"Platform:  {sys.platform}")
print(f"UID:       {os.getuid()}")
orig_soft, orig_hard = resource.getrlimit(resource.RLIMIT_NPROC)
print(f"NPROC:     soft={orig_soft} hard={orig_hard}")

if orig_hard < 0 or orig_hard > 10000:
    print("\nERROR: Need a finite nproc hard limit.")
    print("Run: docker run --rm --ulimit nproc=200:200 aerleon-repro-flask")
    sys.exit(2)

print()

# ---------------------------------------------------------------------------
# Step 1: Write a minimal Flask app to a temp file
# ---------------------------------------------------------------------------
FLASK_APP_CODE = '''\
import os
import resource

from flask import Flask, jsonify

from aerleon import api
from aerleon.lib import naming

app = Flask(__name__)

POLICY = {
    "filename": "test",
    "filters": [{
        "header": {"targets": {"cisco": "f"}, "comment": "T"},
        "terms": [{"name": "t1", "destination-address": "B", "action": "deny"}],
    }],
}
NETWORKS = {"networks": {"B": {"values": [{"address": "192.0.0.0/24"}]}}}


@app.route("/generate")
def generate():
    """Call aerleon api.Generate() — this is what the user does."""
    try:
        defs = naming.Naming()
        defs.ParseDefinitionsObject(NETWORKS, "")
        result = api.Generate([POLICY], defs)
        return jsonify({"status": "ok", "files": list(result.keys())})
    except BlockingIOError as e:
        return jsonify({"status": "error", "error": str(e), "errno": e.errno}), 500
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    # Lower RLIMIT_NPROC to simulate resource pressure.
    # We do this AFTER Python+Flask have started but BEFORE requests arrive.
    # This mirrors a real deployment where most task slots are consumed by the
    # server framework (gunicorn workers, celery, K8s sidecar containers, etc.)
    nproc_test = int(os.environ.get("NPROC_TEST", "5"))
    _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    resource.setrlimit(resource.RLIMIT_NPROC, (nproc_test, hard))

    # debug=True enables the Werkzeug reloader (extra process + filesystem watcher thread)
    # use_reloader=True is the key: it spawns a child process via subprocess
    # threaded=False avoids spawning new threads for requests, keeping task count low and stable.
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=True, threaded=False)
'''

flask_app_path = "/tmp/_repro_flask_app.py"
with open(flask_app_path, "w") as f:
    f.write(FLASK_APP_CODE)

print(f"Wrote Flask app to {flask_app_path}")

# ---------------------------------------------------------------------------
# Step 2: Start Flask in dev mode (with reloader) as a subprocess
# ---------------------------------------------------------------------------
import subprocess

print("Starting Flask dev server (debug=True, use_reloader=True)... ", flush=True)

# NPROC_TEST: we set it to 5 because threaded=False keeps the thread overhead minimal.
env = os.environ.copy()
env["NPROC_TEST"] = "5"
env["FLASK_APP"] = flask_app_path
env["PYTHONDONTWRITEBYTECODE"] = "1"
# Disable Werkzeug's pin for the debugger (not needed for repro)
env["WERKZEUG_DEBUG_PIN"] = "off"

flask_proc = subprocess.Popen(
    [sys.executable, flask_app_path],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)


# ---------------------------------------------------------------------------
# Step 3: Wait for Flask to be ready
# ---------------------------------------------------------------------------
def wait_for_flask(host="127.0.0.1", port=5000, timeout=15):
    """Poll until Flask is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = urllib.request.urlopen(f"http://{host}:{port}/health", timeout=2)
            if resp.status == 200:
                return True
        except (urllib.error.URLError, ConnectionRefusedError, TimeoutError, OSError):
            time.sleep(0.3)
    return False


print("Waiting for Flask to accept connections... ", end="", flush=True)
if not wait_for_flask():
    print("FAILED")
    print("\nFlask did not start. stderr:")
    flask_proc.terminate()
    flask_proc.wait(timeout=5)
    stderr = flask_proc.stderr.read().decode(errors="replace")
    print(stderr[-2000:] if len(stderr) > 2000 else stderr)
    sys.exit(2)
print("OK")
print()

# ---------------------------------------------------------------------------
# Step 4: Send concurrent /generate requests (simulates API load)
# ---------------------------------------------------------------------------
N_REQUESTS = 4
counts = {"ok": 0, "e11": 0, "other_error": 0, "conn_error": 0}
error_messages = []
lock = threading.Lock()
barrier = threading.Barrier(N_REQUESTS + 1)


def send_request(req_id):
    """Send a single /generate request."""
    barrier.wait(timeout=10)
    try:
        resp = urllib.request.urlopen("http://127.0.0.1:5000/generate", timeout=10)
        body = resp.read().decode()
        with lock:
            if '"status": "ok"' in body or '"status":"ok"' in body:
                counts["ok"] += 1
            else:
                counts["other_error"] += 1
                error_messages.append(f"req {req_id}: {body[:200]}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        with lock:
            if "errno" in body and ("11" in body or "Resource temporarily unavailable" in body):
                counts["e11"] += 1
                error_messages.append(f"req {req_id}: {body[:200]}")
            else:
                counts["other_error"] += 1
                error_messages.append(f"req {req_id}: HTTP {e.code} {body[:200]}")
    except Exception as e:
        with lock:
            counts["conn_error"] += 1
            error_messages.append(f"req {req_id}: {type(e).__name__}: {e}")


print(f"Sending {N_REQUESTS} concurrent /generate requests... ", flush=True)
threads = [
    threading.Thread(target=send_request, args=(i,), daemon=True) for i in range(N_REQUESTS)
]
for t in threads:
    t.start()

# Release all threads simultaneously
barrier.wait(timeout=10)

for t in threads:
    t.join(timeout=10)

print()

# ---------------------------------------------------------------------------
# Step 5: Report results
# ---------------------------------------------------------------------------
print(f"Results ({N_REQUESTS} concurrent requests to Flask dev server):")
print(f"  OK:                {counts['ok']}/{N_REQUESTS}")
print(f"  BlockingIOError:   {counts['e11']}  (errno 11 = EAGAIN)")
print(f"  Other errors:      {counts['other_error']}")
print(f"  Connection errors: {counts['conn_error']}")

if error_messages:
    print()
    print("Error details:")
    for msg in error_messages[:5]:
        print(f"  {msg}")

print()

# ---------------------------------------------------------------------------
# Step 6: Also check Flask's stderr for BlockingIOError traces
# ---------------------------------------------------------------------------
flask_proc.terminate()
try:
    flask_proc.wait(timeout=5)
except subprocess.TimeoutExpired:
    flask_proc.kill()
    flask_proc.wait(timeout=3)

stderr_output = flask_proc.stderr.read().decode(errors="replace")
stdout_output = flask_proc.stdout.read().decode(errors="replace")

blocking_in_stderr = "BlockingIOError" in stderr_output or "Errno 11" in stderr_output
blocking_in_stdout = "BlockingIOError" in stdout_output or "Errno 11" in stdout_output

if blocking_in_stderr or blocking_in_stdout:
    print("Flask server stderr/stdout contains BlockingIOError traces:")
    for line in (stderr_output + stdout_output).splitlines():
        if "BlockingIOError" in line or "Errno 11" in line or "Resource temporarily" in line:
            print(f"  {line.strip()}")
    print()

if counts["e11"] > 0 or blocking_in_stderr or blocking_in_stdout:
    print("REPRODUCED: BlockingIOError [Errno 11] ✓")
    print("  'Resource temporarily unavailable'")
    print("  Scenario: Flask API dev mode with Werkzeug reloader")
    os._exit(0)
elif counts["ok"] == N_REQUESTS:
    print("All requests succeeded — BlockingIOError not triggered.")
    print("  Try lowering NPROC_TEST or increasing N_REQUESTS.")
    os._exit(1)
else:
    print("Errors occurred but no errno 11 detected.")
    if stderr_output.strip():
        print("\nFlask stderr (last 1000 chars):")
        print(stderr_output[-1000:])
    os._exit(1)
