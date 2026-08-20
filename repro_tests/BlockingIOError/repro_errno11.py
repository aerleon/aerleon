#!/usr/bin/env python3
"""
Reproduce: BlockingIOError: [Errno 11] Resource temporarily unavailable

USAGE (from the repository root):

  docker build -f repro_tests/BlockingIOError/Dockerfile -t aerleon-repro .
  docker run --rm --ulimit nproc=200:200 aerleon-repro

WHY --ulimit nproc=200:200:
  We start with a generous limit so Python imports and baseline work fine.
  Then we use resource.setrlimit() to LOWER the soft limit inside the process,
  simulating a Gunicorn/Celery/K8s environment where most process slots are
  already consumed by the time our code runs.

  This avoids the deadlock that occurs when nproc is set too low externally
  (the SyncManager partially starts but can't complete its IPC setup).

ROOT CAUSE:
  api.Generate() creates a multiprocessing.SyncManager on every call.
  SyncManager.start() calls fork() to create a child process.
  When fork() exceeds RLIMIT_NPROC, it returns EAGAIN (errno 11),
  which Python surfaces as BlockingIOError.
"""

import os
import resource
import signal
import sys
import threading

# Self-terminate if anything hangs
signal.alarm(20)

print(f"Python:    {sys.version.split()[0]}")
print(f"Platform:  {sys.platform}")
print(f"UID:       {os.getuid()}")
orig_soft, orig_hard = resource.getrlimit(resource.RLIMIT_NPROC)
print(f"NPROC:     soft={orig_soft} hard={orig_hard}")

if orig_hard < 0 or orig_hard > 10000:
    print("\nERROR: Need a finite nproc hard limit.")
    print("Run: docker run --rm --ulimit nproc=200:200 aerleon-repro")
    sys.exit(2)

print()

from aerleon import api
from aerleon.lib import naming

POLICY = {
    "filename": "test",
    "filters": [{
        "header": {"targets": {"cisco": "f"}, "comment": "T"},
        "terms": [{"name": "t1", "destination-address": "B", "action": "deny"}],
    }],
}
NETWORKS = {"networks": {"B": {"values": [{"address": "192.0.0.0/24"}]}}}


def call_generate():
    defs = naming.Naming()
    defs.ParseDefinitionsObject(NETWORKS, "")
    return api.Generate([POLICY], defs)


# Step 1: Baseline (generous nproc)
print("Baseline Generate() from main thread... ", end="", flush=True)
call_generate()
print("OK")
print()

# Step 2: Lower nproc, then test concurrent Generate() calls
# We lower nproc to a value where:
#   - The main thread + 4 worker threads can exist (they're already threads, not new tasks)
#   - But SyncManager.start()'s fork() of a child process exceeds the limit
#
# The trick: set nproc AFTER creating the threads but BEFORE they call Generate().
# This way threads exist but the SyncManager fork() inside Generate() fails.

NPROC_TEST = 5  # Tight limit
N_THREADS = 4

counts = {"ok": 0, "e11": 0, "rt": 0, "other": 0}
lock = threading.Lock()
barrier = threading.Barrier(N_THREADS + 1)  # +1 for main thread


def worker(tid):
    # Wait for main thread to lower nproc
    barrier.wait(timeout=10)
    try:
        call_generate()
        with lock:
            counts["ok"] += 1
    except BlockingIOError as e:
        with lock:
            if e.errno == 11:
                counts["e11"] += 1
            else:
                counts["other"] += 1
    except RuntimeError:
        with lock:
            counts["rt"] += 1
    except Exception:
        with lock:
            counts["other"] += 1


print(f"Creating {N_THREADS} worker threads... ", end="", flush=True)
threads = [threading.Thread(target=worker, args=(i,), daemon=True)
           for i in range(N_THREADS)]
for t in threads:
    t.start()
print("OK")

# Now lower nproc AFTER threads exist
print(f"Lowering RLIMIT_NPROC to {NPROC_TEST}... ", end="", flush=True)
resource.setrlimit(resource.RLIMIT_NPROC, (NPROC_TEST, orig_hard))
print("OK")

print(f"Releasing barrier — threads will now call Generate()...")
print()
barrier.wait(timeout=10)

# Wait for threads (short timeout — some may hang due to SyncManager deadlock)
for t in threads:
    t.join(timeout=3)

# Restore nproc
resource.setrlimit(resource.RLIMIT_NPROC, (orig_hard, orig_hard))

print(f"Results (nproc={NPROC_TEST}, {N_THREADS} threads):")
print(f"  OK:                {counts['ok']}/{N_THREADS}")
print(f"  BlockingIOError:   {counts['e11']}  (errno 11 = EAGAIN)")
print(f"  RuntimeError:      {counts['rt']}  (can't start thread)")
print(f"  Other errors:      {counts['other']}")
print()

if counts["e11"] > 0:
    print("REPRODUCED: BlockingIOError [Errno 11] ✓")
    print("  'Resource temporarily unavailable'")
    os._exit(0)  # Force exit — daemon threads may be hung in SyncManager IPC
elif counts["ok"] == N_THREADS:
    print("All threads succeeded — try lowering NPROC_TEST.")
    os._exit(1)
else:
    print("Errors occurred but no errno 11.")
    os._exit(1)

