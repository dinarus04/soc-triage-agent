from __future__ import annotations

from enum import Enum
from typing import Any, Optional, List
from pydantic import BaseModel, Field

from datetime import datetime

class AuditRecord(BaseModel):
    id: int
    trace_id: str
    created_at: datetime

    source: Optional[str] = None
    event_text: str

    category: str
    severity: str
    confidence: float

    route: Optional[str] = None
    latency_ms: int

    rag_sources: list[Any] = Field(default_factory=list)
    response: dict[str, Any] = Field(default_factory=dict)

class Severity(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(str, Enum):
    account_takeover = "account_takeover"
    bruteforce = "bruteforce"
    phishing = "phishing"
    unknown = "unknown"


class TriageRequest(BaseModel):
    event_text: str = Field(..., min_length=5)
    source: Optional[str] = "manual"
    artifacts: dict[str, Any] = Field(default_factory=dict)


class SourceRef(BaseModel):
    doc_id: str
    chunk_id: Optional[str] = None
    score: Optional[float] = None


class TriageResponse(BaseModel):
    trace_id: str
    category: Category
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)

    summary: str
    rationale: List[str]
    recommended_actions: List[str]
    evidence_to_collect: List[str]

    sources: List[SourceRef] = Field(default_factory=list)
    latency_ms: int
