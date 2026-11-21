from bounty_agent.queue import JobQueue, drain, run_once


def test_priority_then_fifo(conn):
    q = JobQueue(conn)
    a = q.enqueue("t", {"n": 1})
    b = q.enqueue("t", {"n": 2}, priority=5)
    c = q.enqueue("t", {"n": 3})
    assert [q.claim().id for _ in range(3)] == [b, a, c]
    assert q.claim() is None


def test_retries_then_fails(conn):
    q = JobQueue(conn)
    q.enqueue("boom", {}, max_attempts=2)

    def boom(_):
        raise RuntimeError("llm-server timeout")

    assert drain(q, {"boom": boom}) == 2  # attempted twice
    row = conn.execute("SELECT state, attempts, error FROM jobs").fetchone()
    assert row["state"] == "failed" and row["attempts"] == 2
    assert "llm-server timeout" in row["error"]


def test_success_stores_result(conn):
    q = JobQueue(conn)
    q.enqueue("echo", {"x": 42})
    drain(q, {"echo": lambda p: p["x"] * 2})
    row = conn.execute("SELECT state, result FROM jobs").fetchone()
    assert row["state"] == "done" and row["result"] == "84"


def test_unknown_kind_fails_without_retry(conn):
    q = JobQueue(conn)
    q.enqueue("mystery", {}, max_attempts=5)
    assert run_once(q, {}) is True
    row = conn.execute("SELECT state, attempts FROM jobs").fetchone()
    assert row["state"] == "failed" and row["attempts"] == 1


def test_requeue_stale_running_jobs(conn):
    q = JobQueue(conn)
    q.enqueue("t", {})
    q.claim()
    conn.execute("UPDATE jobs SET claimed_at = datetime('now', '-2 hours')")
    assert q.requeue_stale(older_than_minutes=60) == 1
    assert q.counts() == {"queued": 1}
