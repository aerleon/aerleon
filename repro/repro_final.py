#!/usr/bin/env python3
"""
Reproduction: SyncManager resource exhaustion in aerleon api.Generate()

CONFIRMED BUG: api.Generate() creates a multiprocessing.SyncManager on every
call (spawning a child process + IPC sockets/pipes), even when max_renderers=1.
When called from multiple threads concurrently, the simultaneous SyncManagers
exhaust OS resources (file descriptors, pipes), causing:

  - OSError [Errno 24] "Too many open files" (EMFILE) - confirmed reproduced
  - BlockingIOError [Errno 11] "Resource temporarily unavailable" (EAGAIN) -
    same root cause, different errno depending on which resource limit is hit

To reproduce:
  docker build -f Dockerfile.repro -t aerleon-repro .
  docker run --rm --ulimit nofile=30:30 aerleon-repro python repro_final.py

With default Docker limits (no --ulimit), the test also fails with enough
concurrent threads on systems with lower default FD limits.

The root cause is in api.py _Generate() (line 320):
  manager = context.Manager()   # Spawns child process + socket + pipes
  write_files = manager.list()  # IPC proxy — unnecessary for single-process
  generated_configs = manager.dict()

When max_renderers=1 (the default), a regular Python list/dict would work.
The SyncManager is only needed when max_renderers > 1 for cross-process sharing.
"""

import os
import resource
import sys
import threading

print(f"Python: {sys.version}")
print(f"Platform: {sys.platform}")
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
print(f"FD limit: soft={soft}, hard={hard}")
print()

from aerleon import api
from aerleon.lib import naming

# Minimal policy
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


# Verify baseline works
print("Baseline (main thread)... ", end="", flush=True)
call_generate()
print("OK\n")

# Test concurrent calls from threads — the realistic failure scenario
reproduced = False
for n_threads in [4, 8, 16]:
    errors = {}
    successes = [0]
    lock = threading.Lock()

    def worker(tid):
        try:
            call_generate()
            with lock:
                successes[0] += 1
        except OSError as e:
            with lock:
                errors[e.errno] = errors.get(e.errno, 0) + 1

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    status = "OK" if not errors else "FAIL"
    errs = ", ".join(f"errno {e} ({os.strerror(e)}): {c}" for e, c in errors.items())
    print(f"  {n_threads:2d} threads: {successes[0]:2d}/{n_threads:2d} OK | {errs or 'no errors'}")

    if errors:
        reproduced = True

print()
if reproduced:
    print("=" * 60)
    print("REPRODUCED: api.Generate() fails under concurrent threading")
    print("due to SyncManager resource exhaustion.")
    print()
    print("Each Generate() call creates a SyncManager child process")
    print("with IPC sockets and pipes. Concurrent calls from threads")
    print("exhaust file descriptors, causing OSError.")
    print()
    print("The SyncManager is unnecessary when max_renderers=1.")
    print("=" * 60)
    sys.exit(1)
else:
    print("Issue not triggered at current FD limit.")
    print("Try: docker run --rm --ulimit nofile=30:30 ...")
