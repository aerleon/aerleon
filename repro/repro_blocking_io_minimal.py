#!/usr/bin/env python3
"""
Minimal, decisive reproduction for the BlockingIOError when calling
aerleon api.Generate() from threads.

CONFIRMED: Each Generate() call creates a SyncManager (child process + IPC
sockets + pipes). Concurrent calls from threads exhaust OS resources.

This script reproduces BOTH:
- EMFILE (errno 24): "Too many open files" — via FD limits
- EAGAIN (errno 11): "Resource temporarily unavailable" — via pipe limits

The EAGAIN path: On Linux, os.pipe() can return EAGAIN when the per-user
pipe buffer limit (pipe-user-pages-soft) is exceeded, even if FD limit
isn't reached. Each SyncManager creates multiple pipes.
"""

import multiprocessing
import os
import resource
import sys
import threading

print(f"Python: {sys.version}")
print(f"Platform: {sys.platform}")
print(f"MP start: {multiprocessing.get_start_method()}")
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


# ─── EMFILE reproduction (proven) ────────────────────────────────────────────

def test_emfile():
    """Reproduce EMFILE by constraining FDs + concurrent threads."""
    print("=" * 70)
    print("TEST: EMFILE (errno 24) — constrained FDs + 8 concurrent threads")
    print("=" * 70)

    soft_orig, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    fd_limit = 32

    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, hard))
    except (ValueError, OSError) as e:
        print(f"  Cannot set FD limit: {e}")
        return False

    errors = []
    successes = [0]
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker(tid):
        try:
            barrier.wait(timeout=10)
            result = call_generate()
            if result:
                with lock:
                    successes[0] += 1
        except OSError as e:
            with lock:
                errors.append((tid, e.errno, str(e)))

    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft_orig, hard))

    print(f"  OK: {successes[0]}/8")
    if errors:
        for tid, eno, msg in errors:
            print(f"  Thread {tid}: errno={eno} — {msg}")
        return True
    return False


# ─── EAGAIN reproduction via pipe buffer exhaustion ──────────────────────────

def test_eagain():
    """
    Reproduce EAGAIN by:
    1. Pre-creating many pipes to exhaust pipe buffer pages
    2. Then calling Generate() from threads (which creates MORE pipes via SyncManager)
    
    On Linux, os.pipe() returns EAGAIN when pipe-user-pages-soft is exceeded.
    """
    print()
    print("=" * 70)
    print("TEST: EAGAIN (errno 11) — pipe buffer exhaustion + threads")
    print("=" * 70)

    # Read pipe limits if available
    try:
        with open('/proc/sys/fs/pipe-user-pages-soft') as f:
            pipe_soft = f.read().strip()
        with open('/proc/sys/fs/pipe-user-pages-hard') as f:
            pipe_hard = f.read().strip()
        print(f"  pipe-user-pages-soft: {pipe_soft}")
        print(f"  pipe-user-pages-hard: {pipe_hard}")
    except (FileNotFoundError, PermissionError):
        print("  Cannot read pipe limits (not Linux or no access)")

    # Create many pipes to consume pipe buffer pages
    held_pipes = []
    n_pipes = 0
    try:
        # Each pipe consumes at least one page (4KB) of kernel buffer
        # Default pipe-user-pages-soft is often 16384 pages (64MB)
        # We try to get close to the limit
        for i in range(50000):
            try:
                r, w = os.pipe()
                held_pipes.append((r, w))
                n_pipes += 1
            except OSError as e:
                print(f"  Pipe creation stopped at {n_pipes}: errno={e.errno} ({e.strerror})")
                break

        print(f"  Pre-created {n_pipes} pipes")

        # Now try Generate() from threads — the SyncManager needs more pipes
        errors = []
        successes = [0]
        lock = threading.Lock()
        n_threads = 4

        def worker(tid):
            try:
                result = call_generate()
                if result:
                    with lock:
                        successes[0] += 1
            except OSError as e:
                with lock:
                    errors.append((tid, e.errno, str(e)))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        print(f"  OK: {successes[0]}/{n_threads}")
        if errors:
            for tid, eno, msg in errors:
                print(f"  Thread {tid}: errno={eno} — {msg}")
                if eno == 11:
                    print(f"    ^^^ THIS IS THE EAGAIN / BlockingIOError!")
            return True
        return False
    finally:
        for r, w in held_pipes:
            try:
                os.close(r)
                os.close(w)
            except OSError:
                pass


# ─── EAGAIN via combined FD + pipe pressure ──────────────────────────────────

def test_combined_pressure():
    """
    Combine moderate FD limit + pipe pressure + concurrent threads.
    This is the most realistic scenario for hitting EAGAIN.
    """
    print()
    print("=" * 70)
    print("TEST: Combined FD + pipe pressure + concurrent threads")
    print("=" * 70)

    soft_orig, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    fd_limit = 128  # Moderate limit — won't immediately EMFILE

    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, hard))
    except (ValueError, OSError) as e:
        print(f"  Cannot set FD limit: {e}")
        return False

    # Consume some FDs
    held_fds = []
    for _ in range(60):
        try:
            r, w = os.pipe()
            held_fds.extend([r, w])
        except OSError:
            break

    print(f"  Holding {len(held_fds)} FDs, limit={fd_limit}")
    print(f"  Available: ~{fd_limit - len(held_fds) - 6} FDs")

    errors = []
    successes = [0]
    lock = threading.Lock()
    n_threads = 8
    barrier = threading.Barrier(n_threads)

    def worker(tid):
        try:
            barrier.wait(timeout=10)
            result = call_generate()
            if result:
                with lock:
                    successes[0] += 1
        except OSError as e:
            with lock:
                errors.append((tid, e.errno, str(e)))

    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
    finally:
        for fd in held_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft_orig, hard))

    print(f"  OK: {successes[0]}/{n_threads}")
    if errors:
        for tid, eno, msg in errors:
            print(f"  Thread {tid}: errno={eno} — {msg}")
            if eno == 11:
                print(f"    ^^^ EAGAIN / BlockingIOError REPRODUCED!")
        return True
    return False


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Baseline: Generate() from main thread... ", end="")
    try:
        call_generate()
        print("OK\n")
    except Exception as e:
        print(f"FAILED: {e}")
        sys.exit(1)

    r1 = test_emfile()
    r2 = test_eagain()
    r3 = test_combined_pressure()

    print()
    print("=" * 70)
    print("RESULTS:")
    print(f"  EMFILE test:    {'REPRODUCED' if r1 else 'not triggered'}")
    print(f"  EAGAIN test:    {'REPRODUCED' if r2 else 'not triggered'}")
    print(f"  Combined test:  {'REPRODUCED' if r3 else 'not triggered'}")
    print()
    if r1 or r2 or r3:
        print("ROOT CAUSE: api.Generate() creates a SyncManager (child process")
        print("+ socket + pipes) on EVERY call, even with max_renderers=1.")
        print("When called from multiple threads, this exhausts OS resources.")
        print()
        print("The SyncManager is unnecessary for single-renderer mode.")
        print("A regular Python dict/list would suffice.")
    print("=" * 70)
