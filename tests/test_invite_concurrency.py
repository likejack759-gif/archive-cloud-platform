"""PostgreSQL row-lock tests for invitation use under concurrent registration.

These tests exercise the same SELECT ... FOR UPDATE + increment transaction
used by app.main.register, against a real PostgreSQL instance.
"""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.errors import UniqueViolation


@pytest.fixture
def isolated_schema():
    dsn = __import__("os").environ.get("TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("TEST_DATABASE_URL is not configured")
    schema = "invite_test_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    try:
        with psycopg.connect(dsn) as conn:
            conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            conn.execute("""
                CREATE TABLE invites (
                    id INTEGER PRIMARY KEY,
                    is_active BOOLEAN NOT NULL,
                    max_uses INTEGER NOT NULL,
                    uses INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE users (
                    username TEXT PRIMARY KEY
                )
            """)
            conn.execute("INSERT INTO invites (id, is_active, max_uses, uses) VALUES (1, TRUE, %s, 0)", (10,))
            conn.commit()
        yield dsn, schema
    finally:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def register_simulated(dsn, schema, username, start):
    # The barrier makes workers race for the same invite row.
    start.wait(timeout=10)
    try:
        with psycopg.connect(dsn) as conn:
            conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            invite = conn.execute(
                "SELECT id, is_active, max_uses, uses FROM invites WHERE id=1 FOR UPDATE"
            ).fetchone()
            if not invite or not invite[1] or invite[3] >= invite[2]:
                return False
            conn.execute("INSERT INTO users (username) VALUES (%s)", (username,))
            next_uses = invite[3] + 1
            conn.execute(
                "UPDATE invites SET uses=%s, is_active=CASE WHEN %s >= max_uses THEN FALSE ELSE is_active END WHERE id=1",
                (next_uses, next_uses),
            )
            conn.commit()
            return True
    except UniqueViolation:
        return False


def run_race(dsn, schema, usernames):
    barrier = Barrier(len(usernames))
    with ThreadPoolExecutor(max_workers=len(usernames)) as pool:
        results = list(pool.map(lambda name: register_simulated(dsn, schema, name, barrier), usernames))
    with psycopg.connect(dsn) as conn:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        uses, active = conn.execute("SELECT uses, is_active FROM invites WHERE id=1").fetchone()
        users = conn.execute("SELECT count(*) FROM users").fetchone()[0]
    return sum(results), uses, active, users


def test_single_use_invite_cannot_be_consumed_by_concurrent_registrations(isolated_schema):
    dsn, schema = isolated_schema
    # Use a single-use invite for this race.
    with psycopg.connect(dsn) as conn:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute("UPDATE invites SET max_uses=1 WHERE id=1")
        conn.commit()

    successes, uses, active, users = run_race(dsn, schema, [f"user{i}" for i in range(12)])
    assert successes == uses == users == 1
    assert active is False


def test_multi_use_invite_never_exceeds_max_uses_under_race(isolated_schema):
    dsn, schema = isolated_schema
    with psycopg.connect(dsn) as conn:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute("UPDATE invites SET max_uses=5 WHERE id=1")
        conn.commit()

    successes, uses, active, users = run_race(dsn, schema, [f"user{i}" for i in range(20)])
    assert successes == uses == users == 5
    assert active is False


def test_concurrent_duplicate_username_does_not_consume_extra_invite_use(isolated_schema):
    dsn, schema = isolated_schema
    with psycopg.connect(dsn) as conn:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute("UPDATE invites SET max_uses=5 WHERE id=1")
        conn.commit()

    successes, uses, active, users = run_race(dsn, schema, ["same-user"] * 8)
    assert successes == uses == users == 1
    assert active is True
