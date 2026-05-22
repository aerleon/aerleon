#!/usr/bin/env python3
"""
Reproduction script for BlockingIOError: [Errno 11] Resource temporarily unavailable
when calling aerleon's api.Generate() from a non-main thread on Python 3.13.

The issue: api.Generate() internally calls multiprocessing.get_context().Manager()
which creates a SyncManager (spawns a background process and uses Unix domain sockets).
In Python 3.13, changes to the default multiprocessing start method and internal
pipe/socket handling can cause BlockingIOError when SyncManager is created from a
non-main thread, especially under concurrent pressure.

This script tries several approaches to reproduce:
1. Simple: Call Generate() from a single background thread
2. Concurrent: Call Generate() from multiple threads simultaneously
3. Rapid: Call Generate() many times rapidly from threads
"""

import multiprocessing
import os
import sys
import threading
import traceback
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Setup ───────────────────────────────────────────────────────────────────

print(f"Python version: {sys.version}")
print(f"PID: {os.getpid()}")
print(f"Default multiprocessing start method: {multiprocessing.get_start_method()}")
print()

from aerleon import api
from aerleon.lib import naming

# ─── Test data (minimal policy) ──────────────────────────────────────────────

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
    """Create a fresh Naming/definitions object."""
    defs = naming.Naming()
    defs.ParseDefinitionsObject(NETWORKS, "")
    return defs


def call_generate():
    """Call api.Generate() and return the result."""
    defs = make_definitions()
    return api.Generate([POLICY], defs)


# ─── Test 1: Single thread ──────────────────────────────────────────────────

def test_single_thread():
    """Call Generate from a single non-main thread."""
    print("=" * 70)
    print("TEST 1: Single call from a non-main thread")
    print("=" * 70)

    result = [None]
    error = [None]

    def worker():
        try:
            result[0] = call_generate()
        except Exception as e:
            error[0] = e
            traceback.print_exc()

    t = threading.Thread(target=worker, name="single-worker")
    t.start()
    t.join(timeout=30)

    if error[0]:
        print(f"  FAILED: {error[0]}")
        return True  # reproduced
    elif result[0]:
        print(f"  OK: Generated {len(result[0])} config(s)")
        return False
    else:
        print("  TIMEOUT or no result")
        return True


# ─── Test 2: Concurrent threads ─────────────────────────────────────────────

def test_concurrent_threads(n_threads=8):
    """Call Generate from many threads simultaneously."""
    print()
    print("=" * 70)
    print(f"TEST 2: {n_threads} concurrent threads calling Generate()")
    print("=" * 70)

    errors = []
    successes = 0

    barrier = threading.Barrier(n_threads)

    def worker(thread_id):
        nonlocal successes
        try:
            barrier.wait(timeout=10)  # synchronize start
            result = call_generate()
            if result:
                successes += 1
        except Exception as e:
            errors.append((thread_id, e))
            traceback.print_exc()

    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,), name=f"concurrent-{i}")
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    print(f"  Successes: {successes}/{n_threads}")
    if errors:
        print(f"  FAILURES: {len(errors)}")
        for tid, err in errors:
            print(f"    Thread {tid}: {err}")
        return True  # reproduced
    else:
        print("  All threads completed successfully")
        return False


# ─── Test 3: Rapid sequential from thread ────────────────────────────────────

def test_rapid_sequential(n_calls=20):
    """Rapidly call Generate many times from a single background thread."""
    print()
    print("=" * 70)
    print(f"TEST 3: {n_calls} rapid sequential calls from a background thread")
    print("=" * 70)

    errors = []
    successes = 0

    def worker():
        nonlocal successes
        for i in range(n_calls):
            try:
                result = call_generate()
                if result:
                    successes += 1
            except Exception as e:
                errors.append((i, e))
                traceback.print_exc()

    t = threading.Thread(target=worker, name="rapid-worker")
    t.start()
    t.join(timeout=120)

    print(f"  Successes: {successes}/{n_calls}")
    if errors:
        print(f"  FAILURES: {len(errors)}")
        for call_id, err in errors:
            print(f"    Call {call_id}: {err}")
        return True
    else:
        print("  All calls completed successfully")
        return False


# ─── Test 4: ThreadPoolExecutor (common real-world pattern) ──────────────────

def test_threadpool_executor(n_workers=4, n_tasks=16):
    """Use ThreadPoolExecutor, a common pattern for calling into libraries."""
    print()
    print("=" * 70)
    print(f"TEST 4: ThreadPoolExecutor with {n_workers} workers, {n_tasks} tasks")
    print("=" * 70)

    errors = []
    successes = 0

    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        futures = [executor.submit(call_generate) for _ in range(n_tasks)]
        for i, future in enumerate(as_completed(futures)):
            try:
                result = future.result(timeout=30)
                if result:
                    successes += 1
            except Exception as e:
                errors.append((i, e))
                traceback.print_exc()

    print(f"  Successes: {successes}/{n_tasks}")
    if errors:
        print(f"  FAILURES: {len(errors)}")
        for task_id, err in errors:
            print(f"    Task {task_id}: {err}")
        return True
    else:
        print("  All tasks completed successfully")
        return False


# ─── Test 5: Mixed main + background thread ─────────────────────────────────

def test_main_and_background():
    """Call Generate from main thread AND a background thread simultaneously."""
    print()
    print("=" * 70)
    print("TEST 5: Simultaneous calls from main thread + background thread")
    print("=" * 70)

    barrier = threading.Barrier(2)
    bg_error = [None]
    bg_result = [None]

    def bg_worker():
        try:
            barrier.wait(timeout=10)
            bg_result[0] = call_generate()
        except Exception as e:
            bg_error[0] = e
            traceback.print_exc()

    t = threading.Thread(target=bg_worker, name="bg-simultaneous")
    t.start()

    main_error = None
    main_result = None
    try:
        barrier.wait(timeout=10)
        main_result = call_generate()
    except Exception as e:
        main_error = e
        traceback.print_exc()

    t.join(timeout=30)

    reproduced = False
    if main_error:
        print(f"  Main thread FAILED: {main_error}")
        reproduced = True
    else:
        print(f"  Main thread OK: {len(main_result) if main_result else 0} config(s)")

    if bg_error[0]:
        print(f"  Background thread FAILED: {bg_error[0]}")
        reproduced = True
    else:
        print(f"  Background thread OK: {len(bg_result[0]) if bg_result[0] else 0} config(s)")

    return reproduced


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # First, verify it works from the main thread
    print("Baseline: calling Generate() from the main thread...")
    try:
        result = call_generate()
        print(f"  Main thread OK: generated {len(result)} config(s)")
    except Exception as e:
        print(f"  Main thread FAILED even on main thread: {e}")
        traceback.print_exc()
        sys.exit(1)
    print()

    reproduced = False
    reproduced |= test_single_thread()
    reproduced |= test_concurrent_threads(n_threads=8)
    reproduced |= test_rapid_sequential(n_calls=20)
    reproduced |= test_threadpool_executor(n_workers=4, n_tasks=16)
    reproduced |= test_main_and_background()

    print()
    print("=" * 70)
    if reproduced:
        print("RESULT: Issue REPRODUCED — at least one test hit an error")
    else:
        print("RESULT: Issue NOT reproduced — all tests passed")
    print("=" * 70)
