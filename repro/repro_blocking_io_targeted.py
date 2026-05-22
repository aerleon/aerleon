#!/usr/bin/env python3
"""
Targeted reproduction for BlockingIOError [Errno 11] with SyncManager from threads.

After initial tests didn't reproduce, this script tries more specific scenarios:

1. Running inside a ThreadPoolExecutor that's already warm (reuses threads)
2. Using daemon threads (which have different cleanup semantics)
3. Combining with signal handling (common in servers)
4. Running with forkserver start method
5. Creating nested threading + multiprocessing scenarios
6. High thread count + low resource limits
7. Simulating an asyncio event loop calling Generate() in a thread executor
8. Multiple SyncManagers sharing the same auth key (the actual race)
"""

import asyncio
import gc
import multiprocessing
import multiprocessing.managers
import os
import resource
import signal
import socket
import sys
import threading
import traceback
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

print(f"Python version: {sys.version}")
print(f"Platform: {sys.platform}")
print(f"PID: {os.getpid()}")
print(f"Default mp start method: {multiprocessing.get_start_method()}")
print(f"EAGAIN value: {__import__('errno').EAGAIN}")
print()

from aerleon import api
from aerleon.lib import naming

# ─── Test data ───────────────────────────────────────────────────────────────

POLICY = {
    "filename": "test_policy",
    "filters": [{
        "header": {"targets": {"cisco": "test-filter"}, "comment": "Test"},
        "terms": [
            {"name": "deny-bogons", "destination-address": "BOGON", "action": "deny"},
            {"name": "allow-mail", "destination-address": "MAIL_SERVERS", "action": "accept"},
        ],
    }],
}

NETWORKS = {
    "networks": {
        "BOGON": {"values": [{"address": "192.0.0.0/24"}, {"address": "192.0.2.0/24"}]},
        "MAIL_SERVERS": {"values": [{"address": "200.1.1.4/32"}, {"address": "200.1.1.5/32"}]},
    }
}


def make_definitions():
    defs = naming.Naming()
    defs.ParseDefinitionsObject(NETWORKS, "")
    return defs


def call_generate():
    defs = make_definitions()
    return api.Generate([POLICY], defs)


errors_seen = []
errors_lock = threading.Lock()

def record_error(test_name, thread_id, exc):
    with errors_lock:
        errors_seen.append((test_name, thread_id, exc))
    traceback.print_exc()


# ─── Test 1: Asyncio event loop + thread executor ───────────────────────────

def test_asyncio_executor(n_tasks=20):
    """Simulates an asyncio web server dispatching Generate() to a thread pool."""
    print("=" * 70)
    print(f"TEST 1: asyncio loop + ThreadPoolExecutor ({n_tasks} tasks)")
    print("=" * 70)

    async def run():
        loop = asyncio.get_event_loop()
        successes = 0
        errors = 0

        futs = []
        for i in range(n_tasks):
            fut = loop.run_in_executor(None, call_generate)
            futs.append((i, fut))

        for i, fut in futs:
            try:
                result = await fut
                if result:
                    successes += 1
            except Exception as e:
                errors += 1
                record_error("asyncio_executor", i, e)

        print(f"  Successes: {successes}/{n_tasks}, Errors: {errors}")
        return errors > 0

    return asyncio.run(run())


# ─── Test 2: Daemon threads ─────────────────────────────────────────────────

def test_daemon_threads(n_threads=16):
    """Daemon threads have different lifecycle - may trigger cleanup races."""
    print()
    print("=" * 70)
    print(f"TEST 2: {n_threads} daemon threads")
    print("=" * 70)

    successes = [0]
    errs = []
    lock = threading.Lock()
    done = threading.Event()

    def worker(tid):
        try:
            result = call_generate()
            if result:
                with lock:
                    successes[0] += 1
        except Exception as e:
            with lock:
                errs.append((tid, e))
            record_error("daemon_threads", tid, e)

    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,), daemon=True, name=f"daemon-{i}")
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    print(f"  Successes: {successes[0]}/{n_threads}, Errors: {len(errs)}")
    return len(errs) > 0


# ─── Test 3: Thread reuse (warm pool) ───────────────────────────────────────

def test_warm_threadpool(n_workers=4, n_rounds=10, tasks_per_round=4):
    """
    Uses a warm thread pool - threads are reused across rounds.
    This tests whether thread-local state from previous SyncManager
    calls interferes with new ones.
    """
    print()
    print("=" * 70)
    print(f"TEST 3: Warm ThreadPoolExecutor ({n_workers} workers, {n_rounds} rounds x {tasks_per_round} tasks)")
    print("=" * 70)

    successes = 0
    errs = []
    total = n_rounds * tasks_per_round

    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        for rnd in range(n_rounds):
            futures = [executor.submit(call_generate) for _ in range(tasks_per_round)]
            for i, fut in enumerate(as_completed(futures)):
                try:
                    result = fut.result(timeout=30)
                    if result:
                        successes += 1
                except Exception as e:
                    errs.append((rnd, i, e))
                    record_error("warm_threadpool", f"r{rnd}-t{i}", e)

    print(f"  Successes: {successes}/{total}, Errors: {len(errs)}")
    return len(errs) > 0


# ─── Test 4: Nested threading + multiprocessing ─────────────────────────────

def test_nested_mp_from_threads(n_threads=8):
    """
    Simulate the actual problematic pattern: thread creates SyncManager
    which forks. The forked child has only one thread (the calling one)
    but inherits all the parent's locks, FDs, etc.
    """
    print()
    print("=" * 70)
    print(f"TEST 4: Nested multiprocessing from {n_threads} threads")
    print("=" * 70)

    successes = [0]
    errs = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker(tid):
        try:
            barrier.wait(timeout=10)
            # Directly create a SyncManager (what _Generate does)
            ctx = multiprocessing.get_context()
            mgr = ctx.Manager()
            try:
                shared_list = mgr.list()
                shared_dict = mgr.dict()
                shared_list.append(f"from thread {tid}")
                shared_dict[f"key_{tid}"] = tid
                
                # Now also call Generate which creates ANOTHER SyncManager
                result = call_generate()
                if result:
                    with lock:
                        successes[0] += 1
            finally:
                mgr.shutdown()
        except Exception as e:
            with lock:
                errs.append((tid, e))
            record_error("nested_mp", tid, e)

    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,), name=f"nested-{i}")
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)

    print(f"  Successes: {successes[0]}/{n_threads}, Errors: {len(errs)}")
    return len(errs) > 0


# ─── Test 5: Signal handler interference ────────────────────────────────────

def test_with_signal_handlers(n_threads=8):
    """
    Install signal handlers (like a server would) and then call
    Generate from threads. Signal delivery during fork can cause issues.
    """
    print()
    print("=" * 70)
    print(f"TEST 5: With SIGALRM + SIGUSR1 handlers + {n_threads} threads")
    print("=" * 70)

    # Install signal handlers
    original_sigalrm = signal.getsignal(signal.SIGALRM)
    original_sigusr1 = signal.getsignal(signal.SIGUSR1)

    signal_count = [0]

    def sig_handler(signum, frame):
        signal_count[0] += 1

    signal.signal(signal.SIGALRM, sig_handler)
    signal.signal(signal.SIGUSR1, sig_handler)

    # Send ourselves periodic signals during the test
    def signal_sender():
        for _ in range(50):
            try:
                os.kill(os.getpid(), signal.SIGUSR1)
            except Exception:
                pass
            time.sleep(0.01)

    sig_thread = threading.Thread(target=signal_sender, daemon=True)
    sig_thread.start()

    successes = [0]
    errs = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker(tid):
        try:
            barrier.wait(timeout=10)
            result = call_generate()
            if result:
                with lock:
                    successes[0] += 1
        except Exception as e:
            with lock:
                errs.append((tid, e))
            record_error("signal_handlers", tid, e)

    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,), name=f"sig-{i}")
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)

    sig_thread.join(timeout=5)

    # Restore
    signal.signal(signal.SIGALRM, original_sigalrm)
    signal.signal(signal.SIGUSR1, original_sigusr1)

    print(f"  Successes: {successes[0]}/{n_threads}, Errors: {len(errs)}, Signals received: {signal_count[0]}")
    return len(errs) > 0


# ─── Test 6: Very low FD + high thread count ────────────────────────────────

def test_very_constrained(n_threads=16, fd_limit=48):
    """Very tight FD limit with many threads - each SyncManager needs ~4 FDs."""
    print()
    print("=" * 70)
    print(f"TEST 6: Very constrained (FD limit={fd_limit}, {n_threads} threads)")
    print("=" * 70)

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, hard))
    except (ValueError, OSError) as e:
        print(f"  Could not set FD limit: {e}")
        return False

    try:
        successes = [0]
        errs = []
        lock = threading.Lock()
        barrier = threading.Barrier(n_threads)

        def worker(tid):
            try:
                barrier.wait(timeout=10)
                result = call_generate()
                if result:
                    with lock:
                        successes[0] += 1
            except Exception as e:
                with lock:
                    errs.append((tid, e))
                record_error("very_constrained", tid, e)

        threads = []
        for i in range(n_threads):
            t = threading.Thread(target=worker, args=(i,), name=f"constrained-{i}")
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        print(f"  Successes: {successes[0]}/{n_threads}, Errors: {len(errs)}")
        return len(errs) > 0
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


# ─── Test 7: Rapid create+destroy SyncManagers from threads ─────────────────

def test_rapid_manager_churn(n_threads=8, n_iters=20):
    """
    Rapidly create and destroy SyncManagers from threads.
    This stresses the resource_tracker and socket cleanup paths.
    """
    print()
    print("=" * 70)
    print(f"TEST 7: Rapid SyncManager churn ({n_threads} threads, {n_iters} iters each)")
    print("=" * 70)

    successes = [0]
    errs = []
    lock = threading.Lock()

    def worker(tid):
        for i in range(n_iters):
            try:
                ctx = multiprocessing.get_context()
                mgr = ctx.Manager()
                try:
                    d = mgr.dict()
                    d['x'] = i
                finally:
                    mgr.shutdown()
                with lock:
                    successes[0] += 1
            except Exception as e:
                with lock:
                    errs.append((tid, i, e))
                record_error("rapid_churn", f"t{tid}-i{i}", e)

    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,), name=f"churn-{i}")
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=300)

    total = n_threads * n_iters
    print(f"  Successes: {successes[0]}/{total}, Errors: {len(errs)}")
    return len(errs) > 0


# ─── Test 8: Simulate the exact _Generate path with fork context ────────────

def test_exact_generate_path_fork(n_threads=16):
    """
    Exactly replicate what _Generate does, but force 'fork' context.
    On Python 3.13 Linux, get_context() returns fork by default.
    """
    print()
    print("=" * 70)
    print(f"TEST 8: Exact _Generate code path with fork ({n_threads} threads)")
    print("=" * 70)

    successes = [0]
    errs = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker(tid):
        try:
            barrier.wait(timeout=10)
            # This is exactly what _Generate does:
            context = multiprocessing.get_context('fork')
            manager = context.Manager()
            write_files = manager.list()
            errors_list = manager.list()
            generated_configs = manager.dict()

            # Simulate _GenerateACL writing results
            generated_configs[f"test_{tid}.acl"] = f"result from thread {tid}"
            write_files.append((f"/tmp/test_{tid}.acl", f"content {tid}"))

            # Read back
            _ = dict(generated_configs)

            manager.shutdown()
            with lock:
                successes[0] += 1
        except Exception as e:
            with lock:
                errs.append((tid, e))
            record_error("exact_path_fork", tid, e)

    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,), name=f"exact-{i}")
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)

    print(f"  Successes: {successes[0]}/{n_threads}, Errors: {len(errs)}")
    return len(errs) > 0


# ─── Test 9: Stress GC + threading + fork ────────────────────────────────────

def test_gc_pressure(n_threads=8):
    """Force GC collections during threaded Generate calls."""
    print()
    print("=" * 70)
    print(f"TEST 9: GC pressure + {n_threads} threads")
    print("=" * 70)

    successes = [0]
    errs = []
    lock = threading.Lock()
    stop = threading.Event()

    def gc_stressor():
        while not stop.is_set():
            gc.collect()
            time.sleep(0.005)

    gc_thread = threading.Thread(target=gc_stressor, daemon=True)
    gc_thread.start()

    barrier = threading.Barrier(n_threads)

    def worker(tid):
        try:
            barrier.wait(timeout=10)
            # Create garbage to stress GC
            garbage = [list(range(1000)) for _ in range(100)]
            result = call_generate()
            del garbage
            if result:
                with lock:
                    successes[0] += 1
        except Exception as e:
            with lock:
                errs.append((tid, e))
            record_error("gc_pressure", tid, e)

    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,), name=f"gc-{i}")
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)

    stop.set()
    gc_thread.join(timeout=5)

    print(f"  Successes: {successes[0]}/{n_threads}, Errors: {len(errs)}")
    return len(errs) > 0


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Baseline: Generate() from main thread...")
    try:
        result = call_generate()
        print(f"  OK: {len(result)} config(s)")
    except Exception as e:
        print(f"  FAILED: {e}")
        sys.exit(1)
    print()

    reproduced = False
    reproduced |= test_asyncio_executor(n_tasks=20)
    reproduced |= test_daemon_threads(n_threads=16)
    reproduced |= test_warm_threadpool(n_workers=4, n_rounds=10, tasks_per_round=4)
    reproduced |= test_nested_mp_from_threads(n_threads=8)
    reproduced |= test_with_signal_handlers(n_threads=8)
    reproduced |= test_very_constrained(n_threads=16, fd_limit=48)
    reproduced |= test_rapid_manager_churn(n_threads=8, n_iters=20)
    reproduced |= test_exact_generate_path_fork(n_threads=16)
    reproduced |= test_gc_pressure(n_threads=8)

    print()
    print("=" * 70)
    if reproduced:
        print("RESULT: Issue REPRODUCED!")
        print(f"  Total errors seen: {len(errors_seen)}")
        error_types = {}
        for name, tid, exc in errors_seen:
            key = f"{type(exc).__name__}"
            error_types[key] = error_types.get(key, 0) + 1
        for k, v in error_types.items():
            print(f"    {k}: {v} occurrences")
    else:
        print("RESULT: Issue NOT reproduced")
    print("=" * 70)
