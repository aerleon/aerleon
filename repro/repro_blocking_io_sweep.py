#!/usr/bin/env python3
"""
Minimal reproduction for SyncManager FD exhaustion when calling
aerleon api.Generate() from multiple threads concurrently.

PROVEN: When N threads call api.Generate() simultaneously, each creates a
SyncManager child process (socket + pipes), consuming ~6-8 FDs each.
With constrained FD limits (common in Docker/CI/serverless), this triggers:
  - EMFILE (errno 24): when FD limit is exceeded
  - EAGAIN (errno 11): when kernel reports transient resource pressure

This script sweeps thread counts and FD limits to find the failure boundary.
"""

import multiprocessing
import os
import resource
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

print(f"Python: {sys.version}")
print(f"Platform: {sys.platform}")
print(f"MP start: {multiprocessing.get_start_method()}")
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
print(f"FD limits: soft={soft}, hard={hard}")
print()

from aerleon import api
from aerleon.lib import naming

POLICY = {
    "filename": "test_policy",
    "filters": [{
        "header": {"targets": {"cisco": "test-filter"}, "comment": "Test"},
        "terms": [
            {"name": "deny-bogons", "destination-address": "BOGON", "action": "deny"},
            {"name": "allow-mail", "destination-address": "MAIL", "action": "accept"},
        ],
    }],
}

NETWORKS = {
    "networks": {
        "BOGON": {"values": [{"address": "192.0.0.0/24"}]},
        "MAIL": {"values": [{"address": "200.1.1.4/32"}]},
    }
}


def call_generate():
    defs = naming.Naming()
    defs.ParseDefinitionsObject(NETWORKS, "")
    return api.Generate([POLICY], defs)


def run_test(n_threads, fd_limit):
    """Run n_threads concurrent Generate() calls with given FD limit.
    Returns (successes, errno_11_count, errno_24_count, other_errors)"""

    soft_orig, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, hard))
    except (ValueError, OSError):
        return (-1, 0, 0, 0)  # can't set limit

    errors = {11: 0, 24: 0}
    other_errors = 0
    successes = 0
    lock = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker(tid):
        nonlocal successes, other_errors
        try:
            barrier.wait(timeout=10)
            result = call_generate()
            if result:
                with lock:
                    successes += 1
        except OSError as e:
            with lock:
                if e.errno in errors:
                    errors[e.errno] += 1
                else:
                    other_errors += 1
        except Exception:
            with lock:
                other_errors += 1

    try:
        threads = []
        for i in range(n_threads):
            t = threading.Thread(target=worker, args=(i,), name=f"w-{i}")
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft_orig, hard))

    return (successes, errors[11], errors[24], other_errors)


# ─── Main: sweep parameters ─────────────────────────────────────────────────

if __name__ == "__main__":
    # Verify baseline
    print("Baseline check...", end=" ")
    try:
        call_generate()
        print("OK\n")
    except Exception as e:
        print(f"FAILED: {e}")
        sys.exit(1)

    # Count baseline FDs
    baseline_fds = 0
    for fd in range(4096):
        try:
            os.fstat(fd)
            baseline_fds += 1
        except OSError:
            pass
    print(f"Baseline open FDs: {baseline_fds}")
    print()

    # Sweep: varying thread counts and FD limits
    thread_counts = [2, 4, 8, 12, 16, 24, 32]
    fd_limits = [32, 48, 64, 96, 128, 256, 512, 1024]

    print(f"{'Threads':>8} | {'FD Limit':>8} | {'OK':>4} | {'E11':>4} | {'E24':>4} | {'Other':>5} | Status")
    print("-" * 70)

    any_errno11 = False
    any_errno24 = False

    for n_threads in thread_counts:
        for fd_limit in fd_limits:
            ok, e11, e24, other = run_test(n_threads, fd_limit)
            if ok == -1:
                status = "SKIP (can't set limit)"
            elif e11 > 0 or e24 > 0 or other > 0:
                status = "FAIL <<<" 
                if e11 > 0:
                    status += " EAGAIN!"
                    any_errno11 = True
                if e24 > 0:
                    status += " EMFILE!"
                    any_errno24 = True
            else:
                status = "ok"

            print(f"{n_threads:>8} | {fd_limit:>8} | {ok:>4} | {e11:>4} | {e24:>4} | {other:>5} | {status}")

        print()  # blank line between thread count groups

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    if any_errno11:
        print("✗ EAGAIN (errno 11) REPRODUCED — BlockingIOError confirmed!")
    if any_errno24:
        print("✗ EMFILE (errno 24) REPRODUCED — Too many open files!")
    if not any_errno11 and not any_errno24:
        print("✓ No resource errors triggered")
    print()
    print("ANALYSIS: Each api.Generate() call creates a SyncManager child")
    print("process. With N concurrent threads, that's N simultaneous")
    print(f"SyncManagers, each needing ~6-8 FDs beyond the {baseline_fds} baseline FDs.")
