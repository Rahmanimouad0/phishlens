"""
agent/db.py — SQLite logging for every tool call and investigation.

phishlens.db (created automatically, in the project root) is the metrics
SOURCE for Week 3's evaluation harness -- accuracy, avg tool calls, avg
latency, failure rate, etc. all come from querying this table, not from
re-running investigations or hand-counting terminal output.
"""

import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "phishlens.db"


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tool_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL,
            step INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            args_json TEXT NOT NULL,
            result_json TEXT NOT NULL,
            success INTEGER NOT NULL,
            latency_ms REAL NOT NULL,
            created_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            system TEXT NOT NULL,
            verdict TEXT,
            confidence TEXT,
            steps_used INTEGER,
            completed INTEGER,
            total_latency_ms REAL,
            created_at REAL NOT NULL
        )
    """)
    return conn


def log_tool_call(investigation_id, step, tool_name, args, result, success, latency_ms):
    conn = _connect()
    conn.execute(
        "INSERT INTO tool_calls (investigation_id, step, tool_name, args_json, "
        "result_json, success, latency_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (investigation_id, step, tool_name, json.dumps(args), json.dumps(result),
         int(success), latency_ms, time.time()),
    )
    conn.commit()
    conn.close()


def log_investigation(investigation_id, url, system, verdict, confidence,
                       steps_used, completed, total_latency_ms):
    conn = _connect()
    conn.execute(
        "INSERT OR REPLACE INTO investigations (investigation_id, url, system, "
        "verdict, confidence, steps_used, completed, total_latency_ms, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (investigation_id, url, system, verdict, confidence, steps_used,
         int(completed), total_latency_ms, time.time()),
    )
    conn.commit()
    conn.close()
