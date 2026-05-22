#!/usr/bin/env python3
"""
Reproduction script for BlockingIOError: [Errno 11] Resource temporarily unavailable
when calling aerleon's api.Generate() from a non-main thread on Python 3.13.

Root cause analysis:
  api.Generate() calls multiprocessing.get_context() then context.Manager()
  which creates a SyncManager. This spawns a child process that communicates
  over Unix domain sockets. The SyncManager server process has its own
  internal pipes/sockets.

  When called from a non-main thread:
  - With 'fork' start method: the child process inherits the threading state
    of the parent. Signal handlers, locks, and file descriptors can be in
    inconsistent states. The pipe() or socket() calls can return EAGAIN
    (errno 11 = "Resource temporarily unavailable") when OS-level resources
    are contended between forking and threading.
  - Python 3.13 made changes to multiprocessing internals and the default
    start method (spawn on macOS, but fork still on Linux).

  The issue is most likely triggered when using the 'fork' start method
  from within a thread, which can cause the SyncManager's internal
  socket/pipe creation to fail with BlockingIOError.

This script forces the 'fork' start method to reproduce the issue.
"""

import multiprocessing
import os
import sys
import socket
import threading
import traceback
import time
import resource
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Force fork start method to trigger the issue ────────────────────────────
# On macOS Python 3.13 the default is 'spawn'. The bug likely manifests
# when users are on Linux (where 'fork' is still default) or when they
# explicitly use 'fork'.
try:
    multiprocessing.set_start_method('fork', force=True)
except RuntimeError:
    pass

print(f"Python version: {sys.version}")
print(f"Platform: {sys.platform}")
print(f"PID: {os.getpid()}")
print(f"Multiprocessing start method: {multiprocessing.get_start_method()}")
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


# ─── Test 1: Single thread with fork ────────────────────────────────────────

def test_single_thread_fork():
    """Call Generate from a single non-main thread (fork mode)."""
    print("=" * 70)
    print("TEST 1: Single call from a non-main thread (fork mode)")
    print("=" * 70)

    result = [None]
    error = [None]

    def worker():
        try:
            result[0] = call_generate()
        except Exception as e:
            error[0] = e
            traceback.print_exc()

    t = threading.Thread(target=worker, name="single-fork-worker")
    t.start()
    t.join(timeout=30)

    if error[0]:
        print(f"  FAILED: {error[0]}")
        return True
    elif result[0]:
        print(f"  OK: Generated {len(result[0])} config(s)")
        return False
    else:
        print("  TIMEOUT or no result")
        return True


# ─── Test 2: Many concurrent threads with fork ──────────────────────────────

def test_concurrent_threads_fork(n_threads=16):
    """Many threads calling Generate simultaneously (fork mode)."""
    print()
    print("=" * 70)
    print(f"TEST 2: {n_threads} concurrent threads (fork mode)")
    print("=" * 70)

    errors = []
    lock = threading.Lock()
    successes = [0]

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
            traceback.print_exc()

    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,), name=f"concurrent-fork-{i}")
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)

    print(f"  Successes: {successes[0]}/{n_threads}")
    if errors:
        print(f"  FAILURES: {len(errors)}")
        for tid, err in errors:
            print(f"    Thread {tid}: {type(err).__name__}: {err}")
        return True
    else:
        print("  All threads completed successfully")
        return False


# ─── Test 3: Exhaust file descriptors while threading ────────────────────────

def test_fd_pressure(n_threads=8, extra_fds=200):
    """Create FD pressure + concurrent threads to trigger EAGAIN."""
    print()
    print("=" * 70)
    print(f"TEST 3: FD pressure ({extra_fds} extra FDs) + {n_threads} threads")
    print("=" * 70)

    # Consume file descriptors to create pressure
    held_sockets = []
    try:
        for _ in range(extra_fds):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                held_sockets.append(s)
            except OSError:
                break

        print(f"  Holding {len(held_sockets)} extra sockets")

        errors = []
        lock = threading.Lock()
        successes = [0]

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
                traceback.print_exc()

        threads = []
        for i in range(n_threads):
            t = threading.Thread(target=worker, args=(i,), name=f"fd-pressure-{i}")
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        print(f"  Successes: {successes[0]}/{n_threads}")
        if errors:
            print(f"  FAILURES: {len(errors)}")
            for tid, err in errors:
                print(f"    Thread {tid}: {type(err).__name__}: {err}")
            return True
        else:
            print("  All threads completed successfully")
            return False
    finally:
        for s in held_sockets:
            try:
                s.close()
            except Exception:
                pass


# ─── Test 4: Low FD limit + threading ────────────────────────────────────────

def test_low_fd_limit(n_threads=8, fd_limit=64):
    """Set a very low FD limit and try concurrent Generate calls."""
    print()
    print("=" * 70)
    print(f"TEST 4: Low FD limit ({fd_limit}) + {n_threads} threads (fork mode)")
    print("=" * 70)

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"  Current FD limits: soft={soft}, hard={hard}")

    # Set a low soft limit
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, hard))
        new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"  Set FD soft limit to: {new_soft}")
    except (ValueError, OSError) as e:
        print(f"  Could not lower FD limit: {e}")
        return False

    try:
        errors = []
        lock = threading.Lock()
        successes = [0]

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
                traceback.print_exc()

        threads = []
        for i in range(n_threads):
            t = threading.Thread(target=worker, args=(i,), name=f"low-fd-{i}")
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        print(f"  Successes: {successes[0]}/{n_threads}")
        if errors:
            print(f"  FAILURES: {len(errors)}")
            for tid, err in errors:
                print(f"    Thread {tid}: {type(err).__name__}: {err}")
            return True
        else:
            print("  All threads completed successfully")
            return False
    finally:
        # Restore original limit
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        print(f"  Restored FD limit to: {soft}")


# ─── Test 5: Rapid concurrent with SyncManager reuse ────────────────────────

def test_rapid_concurrent_bursts(n_bursts=5, threads_per_burst=8):
    """Rapid bursts of concurrent Generate calls."""
    print()
    print("=" * 70)
    print(f"TEST 5: {n_bursts} bursts of {threads_per_burst} concurrent threads")
    print("=" * 70)

    total_errors = []
    total_successes = 0

    for burst in range(n_bursts):
        errors = []
        lock = threading.Lock()
        successes = [0]

        barrier = threading.Barrier(threads_per_burst)

        def worker(thread_id, burst_id=burst):
            try:
                barrier.wait(timeout=10)
                result = call_generate()
                if result:
                    with lock:
                        successes[0] += 1
            except Exception as e:
                with lock:
                    errors.append((burst_id, thread_id, e))
                traceback.print_exc()

        threads = []
        for i in range(threads_per_burst):
            t = threading.Thread(target=worker, args=(i,), name=f"burst-{burst}-{i}")
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        total_successes += successes[0]
        total_errors.extend(errors)
        print(f"  Burst {burst}: {successes[0]}/{threads_per_burst} OK")

    total_tasks = n_bursts * threads_per_burst
    print(f"  Total: {total_successes}/{total_tasks} OK")
    if total_errors:
        print(f"  FAILURES: {len(total_errors)}")
        for burst_id, tid, err in total_errors:
            print(f"    Burst {burst_id}, Thread {tid}: {type(err).__name__}: {err}")
        return True
    return False


# ─── Test 6: Direct SyncManager from thread (minimal reproduction) ──────────

def test_direct_syncmanager(n_threads=16):
    """Directly create SyncManagers from threads (bypassing aerleon)."""
    print()
    print("=" * 70)
    print(f"TEST 6: Direct SyncManager creation from {n_threads} threads")
    print("=" * 70)

    errors = []
    lock = threading.Lock()
    successes = [0]

    barrier = threading.Barrier(n_threads)

    def worker(thread_id):
        try:
            barrier.wait(timeout=10)
            ctx = multiprocessing.get_context('fork')
            manager = ctx.Manager()
            shared_list = manager.list()
            shared_dict = manager.dict()
            shared_list.append(f"hello from thread {thread_id}")
            shared_dict[f"key_{thread_id}"] = f"value_{thread_id}"
            manager.shutdown()
            with lock:
                successes[0] += 1
        except Exception as e:
            with lock:
                errors.append((thread_id, e))
            traceback.print_exc()

    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,), name=f"syncmgr-{i}")
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    print(f"  Successes: {successes[0]}/{n_threads}")
    if errors:
        print(f"  FAILURES: {len(errors)}")
        for tid, err in errors:
            print(f"    Thread {tid}: {type(err).__name__}: {err}")
        return True
    else:
        print("  All threads completed successfully")
        return False


# ─── Test 7: Threads + explicit fork + resource_tracker race ────────────────

def test_fork_with_busy_threads(n_busy=4, n_generate=4):
    """Run busy threads doing I/O alongside Generate() calls via fork."""
    print()
    print("=" * 70)
    print(f"TEST 7: {n_busy} busy I/O threads + {n_generate} Generate threads (fork)")
    print("=" * 70)

    stop_event = threading.Event()
    errors = []
    lock = threading.Lock()
    successes = [0]

    def busy_io_worker(thread_id):
        """Keep doing socket I/O to create contention during forks."""
        while not stop_event.is_set():
            try:
                s1, s2 = socket.socketpair()
                s1.sendall(b"x" * 1024)
                s2.recv(1024)
                s1.close()
                s2.close()
            except Exception:
                pass
            time.sleep(0.001)

    def generate_worker(thread_id):
        try:
            result = call_generate()
            if result:
                with lock:
                    successes[0] += 1
        except Exception as e:
            with lock:
                errors.append((thread_id, e))
            traceback.print_exc()

    # Start busy threads
    busy_threads = []
    for i in range(n_busy):
        t = threading.Thread(target=busy_io_worker, args=(i,), name=f"busy-io-{i}", daemon=True)
        busy_threads.append(t)
        t.start()

    # Give busy threads time to start
    time.sleep(0.1)

    # Start generate threads
    gen_threads = []
    for i in range(n_generate):
        t = threading.Thread(target=generate_worker, args=(i,), name=f"gen-fork-{i}")
        gen_threads.append(t)

    for t in gen_threads:
        t.start()
    for t in gen_threads:
        t.join(timeout=60)

    stop_event.set()
    for t in busy_threads:
        t.join(timeout=5)

    print(f"  Successes: {successes[0]}/{n_generate}")
    if errors:
        print(f"  FAILURES: {len(errors)}")
        for tid, err in errors:
            print(f"    Thread {tid}: {type(err).__name__}: {err}")
        return True
    else:
        print("  All generate threads completed successfully")
        return False


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Verify baseline works from main thread
    print("Baseline: calling Generate() from the main thread (fork mode)...")
    try:
        result = call_generate()
        print(f"  Main thread OK: generated {len(result)} config(s)")
    except Exception as e:
        print(f"  Main thread FAILED: {e}")
        traceback.print_exc()
        sys.exit(1)
    print()

    reproduced = False
    reproduced |= test_single_thread_fork()
    reproduced |= test_concurrent_threads_fork(n_threads=16)
    reproduced |= test_fd_pressure(n_threads=8, extra_fds=200)
    reproduced |= test_low_fd_limit(n_threads=8, fd_limit=64)
    reproduced |= test_rapid_concurrent_bursts(n_bursts=5, threads_per_burst=8)
    reproduced |= test_direct_syncmanager(n_threads=16)
    reproduced |= test_fork_with_busy_threads(n_busy=4, n_generate=8)

    print()
    print("=" * 70)
    if reproduced:
        print("RESULT: Issue REPRODUCED — at least one test hit an error")
    else:
        print("RESULT: Issue NOT reproduced with current conditions")
        print()
        print("NOTE: The BlockingIOError may require:")
        print("  - Linux (where 'fork' is still the default in Python 3.13)")
        print("  - Higher system load / more concurrent threads")
        print("  - Specific timing conditions in the SyncManager socket setup")
        print("  - The free-threaded (nogil) Python 3.13 build")
    print("=" * 70)
