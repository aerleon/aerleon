# Reproducing BlockingIOError [Errno 11] in `api.Generate()`

This directory contains a self-contained reproduction of a bug where calling
`aerleon.api.Generate()` from multiple threads raises:

```
BlockingIOError: [Errno 11] Resource temporarily unavailable
```

## Quick Start

From the **repository root** (the parent of this `repro/` directory):

```bash
# 1. Build the Docker image
docker build -f repro/Dockerfile -t aerleon-repro .

# 2. Run the reproduction
docker run --rm --ulimit nproc=200:200 aerleon-repro
```

Expected output:

```
Python:    3.13.13
Platform:  linux
UID:       1001
NPROC:     soft=200 hard=200

Baseline Generate() from main thread... OK

Creating 4 worker threads... OK
Lowering RLIMIT_NPROC to 5... OK
Releasing barrier — threads will now call Generate()...

Results (nproc=5, 4 threads):
  OK:                0/4
  BlockingIOError:   4  (errno 11 = EAGAIN)
  RuntimeError:      0  (can't start thread)
  Other errors:      0

REPRODUCED: BlockingIOError [Errno 11] ✓
  'Resource temporarily unavailable'
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

The script [`repro_errno11.py`](repro_errno11.py) works as follows:

1. **Starts with generous nproc** — the container is launched with
   `--ulimit nproc=200:200`, so Python can import libraries and run a baseline
   `api.Generate()` call without issues.

2. **Creates 4 worker threads** — they block at a `threading.Barrier`, waiting
   for the main thread's signal.

3. **Lowers `RLIMIT_NPROC` to 5** — via `resource.setrlimit()`. This simulates
   a production environment (Gunicorn, Celery, Kubernetes, systemd) where most
   of the per-user task slots are already consumed by the server framework.
   The main thread + 4 workers = 5 tasks, exactly at the limit.

4. **Releases the barrier** — all 4 threads simultaneously call
   `api.Generate()`.

5. **Each `Generate()` tries to fork** — internally, `_Generate()` creates a
   `multiprocessing.SyncManager` via `context.Manager()`, which calls `fork()`
   to spawn a child process.

6. **`fork()` returns EAGAIN** — because the 5 task slots are fully consumed by
   existing threads, there's no room for new child processes. The kernel returns
   `EAGAIN` (errno 11), which Python surfaces as `BlockingIOError`.

## Why `--ulimit nproc=200:200`?

The script needs a **finite hard limit** so that `resource.setrlimit()` can
lower the soft limit at runtime. Without `--ulimit`, the hard limit defaults to
unlimited (`-1`), and the kernel won't allow lowering it.

The value 200 is chosen to be generous enough for Python startup but small
enough to be a valid hard limit. The script lowers the soft limit to 5 after
startup — the specific hard limit value doesn't matter as long as it's ≥ 5.

## Why a non-root user?

The Dockerfile creates `aerleon_user` (UID 1001) and runs as that user.
`RLIMIT_NPROC` on Linux counts tasks (threads + processes) **per UID**.
Root (UID 0) receives special kernel treatment and may bypass `nproc` checks
entirely, which would prevent reproduction.

## Root Cause

In [`aerleon/api.py`, line 320](../aerleon/api.py#L320):

```python
def _Generate(..., max_renderers: int = 1, ...):
    manager = context.Manager()          # fork() + socket + pipe + thread
    write_files = manager.list()         # IPC proxy object
    errors = manager.list()              # IPC proxy object
    generated_configs = manager.dict()   # IPC proxy object
```

Every call to `api.Generate()` creates a `multiprocessing.SyncManager`, which:
- Calls `fork()` to spawn a child process
- Creates a Unix domain socket for IPC
- Creates `os.pipe()` pairs for parent-child communication
- Starts an internal `accepter` thread

This is **unnecessary when `max_renderers=1`** (the default). In single-renderer
mode, everything runs in the same process, so a regular Python `list()` and
`dict()` would work — no `SyncManager`, no `fork()`, no IPC overhead.

The same pattern exists in [`aerleon/aclgen.py`, line 397](../aerleon/aclgen.py#L397).

## Files

| File | Description |
|------|-------------|
| [`repro_errno11.py`](repro_errno11.py) | Reproduction script (errno 11 via `RLIMIT_NPROC`) |
| [`Dockerfile`](Dockerfile) | Docker build with Python 3.13 and non-root user |

