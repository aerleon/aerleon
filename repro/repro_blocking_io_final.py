#!/usr/bin/env python3
"""
Focused reproduction for BlockingIOError [Errno 11] (EAGAIN) and
OSError [Errno 24] (EMFILE) when calling aerleon api.Generate() from threads.

KEY FINDING: Every call to api.Generate() creates a new SyncManager which:
  - Creates a Unix socket (Listener) for IPC
  - Creates pipes via os.pipe() for the child process
  - Forks/spawns a child process
  - The child creates more sockets/pipes internally

When multiple threads call Generate() concurrently, each spawns its own
SyncManager process, rapidly consuming file descriptors. Under:
  - Tight FD limits → EMFILE (errno 24: "Too many open files")
  - Transient FD pressure → EAGAIN (errno 11: "Resource temporarily unavailable")
  - Docker/container defaults → often lower FD limits than bare metal

The SyncManager is completely unnecessary when max_renderers=1 (default).
"""

import errno as errno_module
import multiprocessing
import multiprocessing.managers
import os
import resource
import sys
import threading
import traceback
import time
from concurrent.futures import ThreadPoolExecutor

print(f"Python: {sys.version}")
print(f"Platform: {sys.platform}")
print(f"PID: {os.getpid()}")
print(f"MP start method: {multiprocessing.get_start_method()}")
print(f"EAGAIN={errno_module.EAGAIN}, EMFILE={errno_module.EMFILE}")
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


def count_open_fds():
    """Count currently open file descriptors for this process."""
    count = 0
    for fd in range(resource.getrlimit(resource.RLIMIT_NOFILE)[0]):
        try:
            os.fstat(fd)
            count += 1
        except OSError:
            pass
    return count


# ─── Scenario A: Many concurrent threads (realistic web server scenario) ────

def scenario_realistic_server(n_workers=8, n_requests=32):
    """
    Simulate a web server handling many concurrent requests, each calling
    api.Generate(). This is the most realistic reproduction scenario.
    
    Each Generate() call creates a SyncManager child process + socket + pipes.
    With 8 concurrent workers, that's 8 SyncManagers simultaneously, each
    consuming ~6-8 FDs (listener socket, pipes, connection sockets).
    """
    print("=" * 70)
    print(f"SCENARIO A: Web server simulation ({n_workers} workers, {n_requests} requests)")
    print("=" * 70)

    errors = {11: 0, 24: 0, 'other': 0}
    successes = 0
    lock = threading.Lock()

    def handle_request(request_id):
        nonlocal successes
        try:
            result = call_generate()
            if result:
                with lock:
                    successes += 1
        except OSError as e:
            with lock:
                if e.errno in errors:
                    errors[e.errno] += 1
                else:
                    errors['other'] += 1
            if e.errno in (11, 24):
                print(f"  Request {request_id}: OSError errno={e.errno} ({os.strerror(e.errno)})")
        except Exception as e:
            with lock:
                errors['other'] += 1
            print(f"  Request {request_id}: {type(e).__name__}: {e}")

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        list(pool.map(handle_request, range(n_requests)))

    print(f"  Results: {successes} OK, errno11={errors[11]}, errno24={errors[24]}, other={errors['other']}")
    return errors[11] > 0 or errors[24] > 0


# ─── Scenario B: Constrained environment (Docker/CI/serverless) ─────────────

def scenario_constrained(fd_limit, n_workers=4, n_requests=16):
    """
    Many CI, Docker, and serverless environments have lower FD limits.
    Combined with concurrent Generate() calls, this easily triggers
    EMFILE or EAGAIN.
    """
    print()
    print("=" * 70)
    print(f"SCENARIO B: Constrained FD limit={fd_limit} ({n_workers} workers, {n_requests} requests)")
    print("=" * 70)

    soft_orig, hard = resource.getrlimit(resource.RLIMIT_NOFILE)

    # Count baseline FDs before setting limit
    baseline_fds = 0
    for fd in range(1024):
        try:
            os.fstat(fd)
            baseline_fds += 1
        except OSError:
            pass
    print(f"  Baseline open FDs: {baseline_fds}")
    print(f"  Available FDs under limit: {fd_limit - baseline_fds}")
    print(f"  FDs needed per Generate() call: ~6-8 (socket + pipes + connections)")

    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, hard))
    except (ValueError, OSError) as e:
        print(f"  Cannot set FD limit: {e}")
        return False

    errors = {11: 0, 24: 0, 'other_os': 0, 'other': 0}
    successes = 0
    lock = threading.Lock()
    error_details = []

    def handle_request(request_id):
        nonlocal successes
        try:
            result = call_generate()
            if result:
                with lock:
                    successes += 1
        except OSError as e:
            with lock:
                if e.errno in errors:
                    errors[e.errno] += 1
                else:
                    errors['other_os'] += 1
                error_details.append((request_id, e.errno, str(e)))
        except Exception as e:
            with lock:
                errors['other'] += 1
                error_details.append((request_id, -1, f"{type(e).__name__}: {e}"))

    try:
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            list(pool.map(handle_request, range(n_requests)))
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft_orig, hard))

    print(f"  Results: {successes} OK, EAGAIN(11)={errors[11]}, EMFILE(24)={errors[24]}, other_os={errors['other_os']}, other={errors['other']}")
    if error_details:
        for rid, eno, msg in error_details[:5]:
            print(f"    Request {rid}: errno={eno} → {msg}")
    return errors[11] > 0 or errors[24] > 0


# ─── Scenario C: Leak simulation (Generate called repeatedly without cleanup)

def scenario_fd_leak(n_calls=50):
    """
    Call Generate() many times from a single thread. SyncManager processes
    may not be cleaned up immediately, leaking FDs over time.
    """
    print()
    print("=" * 70)
    print(f"SCENARIO C: Sequential FD leak test ({n_calls} calls)")
    print("=" * 70)

    # Measure FD count before and during
    baseline_fds = 0
    for fd in range(4096):
        try:
            os.fstat(fd)
            baseline_fds += 1
        except OSError:
            pass
    print(f"  Baseline FDs: {baseline_fds}")

    errors = []
    peak_fds = baseline_fds

    for i in range(n_calls):
        try:
            result = call_generate()
        except Exception as e:
            errors.append((i, e))
            print(f"  Call {i}: {type(e).__name__}: {e}")

        if i % 10 == 0:
            current_fds = 0
            for fd in range(4096):
                try:
                    os.fstat(fd)
                    current_fds += 1
                except OSError:
                    pass
            if current_fds > peak_fds:
                peak_fds = current_fds
            print(f"  After call {i}: {current_fds} FDs open (peak: {peak_fds}, baseline: {baseline_fds})")

    final_fds = 0
    for fd in range(4096):
        try:
            os.fstat(fd)
            final_fds += 1
        except OSError:
            pass
    print(f"  Final: {final_fds} FDs (leaked: {final_fds - baseline_fds}, peak: {peak_fds})")
    print(f"  Errors: {len(errors)}")
    return len(errors) > 0


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Baseline: Generate() from main thread...")
    try:
        result = call_generate()
        print(f"  OK: {len(result)} config(s)\n")
    except Exception as e:
        print(f"  FAILED: {e}")
        sys.exit(1)

    any_reproduced = False

    # Scenario A: Realistic - many concurrent requests with default limits
    any_reproduced |= scenario_realistic_server(n_workers=8, n_requests=32)

    # Scenario B: Various constrained FD limits
    # Docker default is often 1024, but in containers with restrictive settings
    # or when running as non-root, it can be much lower.
    # Each Generate() call needs ~6-8 FDs for the SyncManager.
    for fd_limit in [256, 128, 96, 64, 48]:
        any_reproduced |= scenario_constrained(
            fd_limit=fd_limit,
            n_workers=4,
            n_requests=16,
        )

    # Scenario C: FD leak over time
    any_reproduced |= scenario_fd_leak(n_calls=50)

    print()
    print("=" * 70)
    if any_reproduced:
        print("REPRODUCED: SyncManager failures when calling Generate() from threads")
        print()
        print("Root cause: api.Generate() creates a multiprocessing.SyncManager")
        print("on every call (even single-renderer mode). Each SyncManager:")
        print("  1. Opens a Unix socket for its Listener")
        print("  2. Creates os.pipe() pairs for child process communication")
        print("  3. Forks a child process (which inherits parent FDs)")
        print("  4. Creates connection sockets for proxy objects")
        print()
        print("Under concurrent threading, this rapidly exhausts FDs, causing:")
        print("  - EAGAIN (errno 11): transient resource unavailability")
        print("  - EMFILE (errno 24): hard FD limit reached")
        print()
        print("The SyncManager is UNNECESSARY when max_renderers=1 (default).")
        print("Regular Python list/dict would work for single-process mode.")
    else:
        print("NOT REPRODUCED with current conditions")
    print("=" * 70)
