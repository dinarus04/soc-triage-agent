from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from typing import Optional


def get_db_url() -> str:
    return os.getenv("DATABASE_URL", "postgresql+psycopg2://soctriage:soctriage@localhost:5433/soctriage")


def make_engine() -> Engine:
    return create_engine(get_db_url(), pool_pre_ping=True)


ENGINE = make_engine()


def init_db() -> None:
    ddl = """
    CREATE TABLE IF NOT EXISTS audit_log (
        id BIGSERIAL PRIMARY KEY,
        trace_id TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        source TEXT,
        event_text TEXT NOT NULL,
        category TEXT,
        severity TEXT,
        confidence DOUBLE PRECISION,
        route TEXT,
        latency_ms INTEGER,
        rag_sources JSONB,
        response JSONB
    );

    CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_log_trace_id ON audit_log(trace_id);
    CREATE INDEX IF NOT EXISTS idx_audit_category_severity ON audit_log(category, severity);
    """
    with ENGINE.begin() as conn:
        conn.execute(text(ddl))


def write_audit(
    *,
    trace_id: str,
    source: str | None,
    event_text: str,
    category: str | None,
    severity: str | None,
    confidence: float | None,
    route: str | None,
    latency_ms: int | None,
    rag_sources: dict | list | None,
    response: dict,
) -> None:
    q = """
    INSERT INTO audit_log
      (trace_id, created_at, source, event_text, category, severity, confidence, route, latency_ms, rag_sources, response)
    VALUES
      (:trace_id, :created_at, :source, :event_text, :category, :severity, :confidence, :route, :latency_ms,
       CAST(:rag_sources AS jsonb), CAST(:response AS jsonb));
    """
    payload = {
        "trace_id": trace_id,
        "created_at": datetime.now(timezone.utc),
        "source": source,
        "event_text": event_text,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "route": route,
        "latency_ms": latency_ms,
        "rag_sources": json.dumps(rag_sources if rag_sources is not None else [], ensure_ascii=False),
        "response": json.dumps(response, ensure_ascii=False),
    }
    with ENGINE.begin() as conn:
        conn.execute(text(q), payload)

def get_audit_by_trace_id(trace_id: str) -> Optional[dict]:
    q = """
    SELECT
      id,
      trace_id,
      created_at,
      source,
      event_text,
      category,
      severity,
      confidence,
      route,
      latency_ms,
      rag_sources::text AS rag_sources,
      response::text AS response
    FROM audit_log
    WHERE trace_id = :trace_id
    ORDER BY id DESC
    LIMIT 1;
    """
    with ENGINE.connect() as conn:
        row = conn.execute(text(q), {"trace_id": trace_id}).mappings().first()

    if not row:
        return None

    d = dict(row)
    d["rag_sources"] = json.loads(d["rag_sources"]) if d["rag_sources"] else []
    d["response"] = json.loads(d["response"]) if d["response"] else {}
    return d


def list_audit(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    base = """
    SELECT
      id,
      trace_id,
      created_at,
      source,
      event_text,
      category,
      severity,
      confidence,
      route,
      latency_ms,
      rag_sources::text AS rag_sources,
      response::text AS response
    FROM audit_log
    WHERE 1=1
    """
    params = {"limit": limit, "offset": offset}

    if category:
        base += " AND category = :category"
        params["category"] = category
    if severity:
        base += " AND severity = :severity"
        params["severity"] = severity
    if time_from:
        base += " AND created_at >= :time_from"
        params["time_from"] = time_from
    if time_to:
        base += " AND created_at <= :time_to"
        params["time_to"] = time_to

    base += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset;"

    with ENGINE.connect() as conn:
        rows = conn.execute(text(base), params).mappings().all()

    out = []
    for r in rows:
        d = dict(r)
        d["rag_sources"] = json.loads(d["rag_sources"]) if d["rag_sources"] else []
        d["response"] = json.loads(d["response"]) if d["response"] else {}
        out.append(d)
    return out