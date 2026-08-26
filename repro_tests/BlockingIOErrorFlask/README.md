# Reproducing BlockingIOError [Errno 11] — Flask Dev Mode Scenario

This directory contains a reproduction of the BlockingIOError bug triggered
when calling `aerleon.api.Generate()` from a Flask API running in dev mode.

This matches the end user's exact scenario:

> "I am / was running flaskapi in dev mode, so I think it creates an extra
> thread that looks for changes in the filesystem to reload on code updates"

## Quick Start

From the **repository root**:

```bash
# 1. Build the Docker image
docker build -f repro_tests/BlockingIOErrorFlask/Dockerfile -t aerleon-repro-flask .

# 2. Run the reproduction
docker run --rm --ulimit nproc=200:200 aerleon-repro-flask
```

Expected output:

```
Python:    3.13.x
Platform:  linux
UID:       1001
NPROC:     soft=200 hard=200

Wrote Flask app to /tmp/_repro_flask_app.py
Starting Flask dev server (debug=True, use_reloader=True)...
Waiting for Flask to accept connections... OK

Sending 4 concurrent /generate requests...

Results (4 concurrent requests to Flask dev server):
  OK:                0/4
  BlockingIOError:   4  (errno 11 = EAGAIN)
  Other errors:      0
  Connection errors: 0

REPRODUCED: BlockingIOError [Errno 11] ✓
  'Resource temporarily unavailable'
  Scenario: Flask API dev mode with Werkzeug reloader
```

## Prerequisites

- **Docker** (Docker Desktop or Docker Engine)
- **Important (Docker Desktop):** Before running, stop any other containers you
  have running. Docker Desktop runs all containers in a shared Linux VM, and
  `RLIMIT_NPROC` counts tasks per UID **across the entire VM**. Leftover
  containers running as UID 1001 will consume task slots and may cause the
  reproduction to behave inconsistently (or hang). You can check with
  `docker ps` and stop unneeded containers with `docker stop $(docker ps -q)`.

## What the reproduction does

The script [`repro_flask_dev.py`](repro_flask_dev.py) simulates the user's
exact environment:

1. **Writes a minimal Flask app** that has a `/generate` endpoint calling
   `aerleon.api.Generate()` — this is what the user's Flask API does.

2. **Starts Flask in dev mode** (`debug=True, use_reloader=True`) — the
   Werkzeug reloader spawns a child process that watches the filesystem for
   code changes and restarts the server on modifications. This is the "extra
   thread that looks for changes in the filesystem" the user described.

3. **Lowers `RLIMIT_NPROC`** inside the Flask app after startup — this
   simulates a production/container environment where most per-user task slots
   are already consumed by the server framework.

4. **Sends 4 concurrent HTTP requests** to `/generate` — each request triggers
   `api.Generate()`, which tries to create a `multiprocessing.SyncManager`.

5. **The `SyncManager.start()` calls `fork()`** — but with the Werkzeug
   reloader's child process + watcher thread already consuming task slots, and
   `RLIMIT_NPROC` set low, `fork()` returns EAGAIN (errno 11).

6. **Reports results** from both the HTTP responses and Flask's stderr output.

## How this differs from the base `BlockingIOError` test

| Aspect | `BlockingIOError` (base) | `BlockingIOErrorFlask` (this) |
|--------|--------------------------|-------------------------------|
| How Generate() is called | Direct call from spawned threads | HTTP request handler in Flask |
| Thread source | Manually created worker threads | Werkzeug reloader + request handler threads |
| Process model | Single Python process | Flask reloader spawns child process |
| Matches user's report | General case | Exact user scenario |

## Why Flask dev mode matters

Flask's dev server with `debug=True` (or `use_reloader=True`) uses Werkzeug's
`StatReloaderLoop` or `WatchdogReloaderLoop` to monitor Python source files for
changes. This:

- Spawns a **child process** via `subprocess.call()` (the actual server runs
  in this child)
- The child process contains a **filesystem watcher thread** polling for
  modifications
- Combined, these consume additional task slots from `RLIMIT_NPROC`

When the user's Flask endpoint calls `api.Generate()`, the `SyncManager`
created inside `_Generate()` tries to `fork()` yet another child process. Under
resource pressure (common in containers, systemd-managed services, or when
running alongside other services), this `fork()` fails with EAGAIN.

## Root Cause

Same as the base `BlockingIOError` test. In
[`aerleon/api.py`](../../aerleon/api.py):

```python
def _Generate(..., max_renderers: int = 1, ...):
    manager = context.Manager()          # fork() + socket + pipe + thread
    write_files = manager.list()         # IPC proxy object
    ...
```

Every call to `api.Generate()` creates a `multiprocessing.SyncManager`, which
calls `fork()`. This is unnecessary when `max_renderers=1` (the default) — a
regular Python `list()` and `dict()` would suffice.

## Files

| File | Description |
|------|-------------|
| [`repro_flask_dev.py`](repro_flask_dev.py) | Reproduction script (Flask dev mode + errno 11) |
| [`Dockerfile`](Dockerfile) | Docker build with Python 3.13, Flask, and non-root user |
