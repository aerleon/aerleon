#!/usr/bin/env python3
"""
Reproduction script for BlockingIOError: [Errno 11] Resource temporarily unavailable
when calling aerleon's api.Generate() from a non-main thread on Python 3.13.

This version uses the FREE-THREADED (nogil) Python 3.13 build to increase
the likelihood of hitting thread-safety issues in SyncManager.

It also directly instruments the problematic code path to add more
diagnostic information about where the failure occurs.
"""

import errno
import multiprocessing
import multiprocessing.connection
import multiprocessing.managers
import os
import socket
import sys
import threading
import traceback
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import patch

print(f"Python version: {sys.version}")
print(f"Platform: {sys.platform}")
print(f"PID: {os.getpid()}")
print(f"Default multiprocessing start method: {multiprocessing.get_start_method()}")
try:
    print(f"GIL enabled: {sys._is_gil_enabled()}")
except AttributeError:
    print("GIL: standard (not free-threaded build)")
print()

from aerleon import api
from aerleon.lib import naming

# ─── Test data ───────────────────────────────────────────────────────────────

POLICY = {
    "filename": "test_policy",
    "filters": [
        {
            "header": {
                "targets": {"cisco": "test-filter"},
                "comment": "Test",
            },
            "terms": [
                {
                    "name": "deny-bogons",
                    "destination-address": "BOGON",
                    "action": "deny",
                },
                {
                    "name": "allow-mail",
                    "destination-address": "MAIL_SERVERS",
                    "action": "accept",
                },
            ],
        }
    ],
}

NETWORKS = {
    "networks": {
        "BOGON": {
            "values": [
                {"address": "192.0.0.0/24"},
                {"address": "192.0.2.0/24"},
            ]
        },
        "MAIL_SERVERS": {
            "values": [
                {"address": "200.1.1.4/32"},
                {"address": "200.1.1.5/32"},
            ]
        },
    }
}


def make_definitions():
    defs = naming.Naming()
    defs.ParseDefinitionsObject(NETWORKS, "")
    return defs


def call_generate():
    defs = make_definitions()
    return api.Generate([POLICY], defs)


# ─── Diagnostic wrapper around SyncManager ───────────────────────────────────

_original_manager_start = multiprocessing.managers.BaseManager.start

def instrumented_manager_start(self, *args, **kwargs):
    """Wrapper that catches and logs errors during Manager.start()."""
    thread_name = threading.current_thread().name
    try:
        return _original_manager_start(self, *args, **kwargs)
    except BlockingIOError as e:
        print(f"\n{'!'*70}")
        print(f"CAUGHT BlockingIOError in Manager.start() on thread '{thread_name}'")
        print(f"  errno: {e.errno} ({errno.errorcode.get(e.errno, 'unknown')})")
        print(f"  strerror: {e.strerror}")
        print(f"  PID: {os.getpid()}")
        print(f"{'!'*70}\n")
        raise
    except OSError as e:
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, 11):
            print(f"\n{'!'*70}")
            print(f"CAUGHT OSError (EAGAIN/EWOULDBLOCK) in Manager.start() on thread '{thread_name}'")
            print(f"  errno: {e.errno} ({errno.errorcode.get(e.errno, 'unknown')})")
            print(f"  strerror: {e.strerror}")
            print(f"  PID: {os.getpid()}")
            print(f"{'!'*70}\n")
        raise


# ─── Test with aggressive concurrent SyncManager creation ───────────────────

def test_aggressive_concurrent(n_threads=32, n_rounds=3):
    """
    Aggressively create SyncManagers from many threads simultaneously.
    
    Each call to api.Generate() creates a SyncManager, which:
    1. Creates a socket pair for the manager server
    2. Forks/spawns a child process  
    3. Sets up a connection listener
    
    When many threads do this simultaneously, the internal socket/pipe
    operations can race, especially with the 'fork' method where the
    child process inherits the parent's thread state.
    """
    print("=" * 70)
    print(f"TEST: {n_threads} threads x {n_rounds} rounds calling Generate()")
    print("=" * 70)

    total_errors = []
    total_successes = 0

    # Monkey-patch for diagnostics
    multiprocessing.managers.BaseManager.start = instrumented_manager_start

    try:
        for round_num in range(n_rounds):
            errors = []
            lock = threading.Lock()
            successes = [0]
            barrier = threading.Barrier(n_threads)

            def worker(thread_id, rnd=round_num):
                try:
                    barrier.wait(timeout=10)
                    result = call_generate()
                    if result:
                        with lock:
                            successes[0] += 1
                except Exception as e:
                    with lock:
                        errors.append((rnd, thread_id, e))
                    # Only print traceback for the interesting errors
                    if isinstance(e, (BlockingIOError, OSError)):
                        traceback.print_exc()

            threads = []
            for i in range(n_threads):
                t = threading.Thread(target=worker, args=(i,), name=f"aggressive-{round_num}-{i}")
                threads.append(t)

            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=120)

            total_successes += successes[0]
            total_errors.extend(errors)
            print(f"  Round {round_num}: {successes[0]}/{n_threads} OK, {len(errors)} errors")
    finally:
        # Restore original
        multiprocessing.managers.BaseManager.start = _original_manager_start

    total_tasks = n_threads * n_rounds
    print(f"\n  Total: {total_successes}/{total_tasks} OK")
    if total_errors:
        print(f"  FAILURES: {len(total_errors)}")
        for rnd, tid, err in total_errors[:10]:  # Show first 10
            print(f"    Round {rnd}, Thread {tid}: {type(err).__name__}: {err}")
        return True
    return False


# ─── Test: Direct SyncManager with non-blocking sockets ─────────────────────

def test_nonblocking_socket_race(n_threads=16):
    """
    Some Python 3.13 changes set sockets to non-blocking internally.
    When the SyncManager's Listener tries accept() on a non-blocking socket,
    it can get EAGAIN. This test tries to reproduce that specific scenario.
    """
    print()
    print("=" * 70)
    print(f"TEST: Non-blocking socket race ({n_threads} threads)")
    print("=" * 70)

    errors = []
    lock = threading.Lock()
    successes = [0]

    # Create contention on socket operations
    _original_socket_init = socket.socket.__init__

    def noisy_socket_init(self, *args, **kwargs):
        _original_socket_init(self, *args, **kwargs)
        # Simulate the race: briefly set socket to non-blocking
        # This mimics what some Python 3.13 internal changes do
        try:
            self.setblocking(False)
            time.sleep(0.0001)  # tiny delay to widen the race window
            self.setblocking(True)
        except Exception:
            pass

    barrier = threading.Barrier(n_threads)

    def worker(thread_id):
        try:
            barrier.wait(timeout=10)
            result = call_generate()
            if result:
                with lock:
                    successes[0] += 1
        except Exception as e:
            with lock:
                errors.append((thread_id, e))
            if isinstance(e, (BlockingIOError, OSError)):
                traceback.print_exc()

    # Patch socket init
    socket.socket.__init__ = noisy_socket_init
    try:
        threads = []
        for i in range(n_threads):
            t = threading.Thread(target=worker, args=(i,), name=f"nbsock-{i}")
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
    finally:
        socket.socket.__init__ = _original_socket_init

    print(f"  Successes: {successes[0]}/{n_threads}")
    if errors:
        print(f"  FAILURES: {len(errors)}")
        for tid, err in errors:
            print(f"    Thread {tid}: {type(err).__name__}: {err}")
        return True
    else:
        print("  All threads completed successfully")
        return False


# ─── Test: Direct SyncManager race (minimal, no aerleon) ────────────────────

def test_bare_syncmanager_race(n_threads=32, n_rounds=5):
    """
    Minimal reproduction: just create SyncManagers from threads.
    This is the core of what api.Generate() does that could fail.
    """
    print()
    print("=" * 70)
    print(f"TEST: Bare SyncManager race ({n_threads} threads x {n_rounds} rounds)")
    print("=" * 70)

    total_errors = []
    total_successes = 0

    for rnd in range(n_rounds):
        errors = []
        lock = threading.Lock()
        successes = [0]
        barrier = threading.Barrier(n_threads)

        def worker(thread_id, round_num=rnd):
            try:
                barrier.wait(timeout=10)
                ctx = multiprocessing.get_context()
                mgr = ctx.Manager()
                d = mgr.dict()
                l = mgr.list()
                d['test'] = thread_id
                l.append(thread_id)
                # Clean up
                mgr.shutdown()
                with lock:
                    successes[0] += 1
            except Exception as e:
                with lock:
                    errors.append((round_num, thread_id, e))
                if isinstance(e, (BlockingIOError, OSError)):
                    traceback.print_exc()

        threads = []
        for i in range(n_threads):
            t = threading.Thread(target=worker, args=(i,), name=f"bare-mgr-{rnd}-{i}")
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        total_successes += successes[0]
        total_errors.extend(errors)
        print(f"  Round {rnd}: {successes[0]}/{n_threads} OK")

    total_tasks = n_threads * n_rounds
    print(f"\n  Total: {total_successes}/{total_tasks} OK")
    if total_errors:
        print(f"  FAILURES: {len(total_errors)}")
        for rnd, tid, err in total_errors[:10]:
            print(f"    Round {rnd}, Thread {tid}: {type(err).__name__}: {err}")
        return True
    return False


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Baseline: calling Generate() from the main thread...")
    try:
        result = call_generate()
        print(f"  OK: generated {len(result)} config(s)")
    except Exception as e:
        print(f"  FAILED: {e}")
        traceback.print_exc()
        sys.exit(1)
    print()

    reproduced = False
    reproduced |= test_aggressive_concurrent(n_threads=32, n_rounds=3)
    reproduced |= test_bare_syncmanager_race(n_threads=32, n_rounds=5)
    # The non-blocking socket test is more of a simulation
    reproduced |= test_nonblocking_socket_race(n_threads=16)

    print()
    print("=" * 70)
    if reproduced:
        print("RESULT: Issue REPRODUCED!")
    else:
        print("RESULT: Issue NOT reproduced on this system")
        print()
        print("ANALYSIS: The BlockingIOError [Errno 11] is Linux-specific (EAGAIN=11).")
        print("On macOS, EAGAIN=35. The user is most likely on Linux where:")
        print("  1. 'fork' is the default multiprocessing start method in Python 3.13")
        print("  2. fork() + threads can cause EAGAIN on pipe()/socket() calls")
        print("  3. SyncManager.start() creates sockets/pipes that can race")
        print()
        print("The underlying issue: api.Generate() and aclgen.Run() both create a")
        print("SyncManager on EVERY call, even when max_renderers=1 (single process).")
        print("SyncManager spawns a background process with socket communication.")
        print("When called from a thread, this is inherently problematic with 'fork'.")
    print("=" * 70)
