from __future__ import annotations

import time
import uuid
from fastapi import FastAPI, HTTPException, Query

from app.db import init_db, write_audit, get_audit_by_trace_id, list_audit
from app.router import route
from app.schemas import TriageRequest, TriageResponse, AuditRecord

from datetime import datetime, timezone

app = FastAPI(title="SOC Triage Agent", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/triage", response_model=TriageResponse)
def triage(req: TriageRequest) -> TriageResponse:
    t0 = time.perf_counter()
    trace_id = str(uuid.uuid4())

    category, severity, confidence, route_tag = route(req.event_text)

    # MVP: шаблоны ответа
    if category.value == "account_takeover":
        summary = "Вероятный захват аккаунта (account takeover)."
        rationale = [
            "Обнаружены признаки аномального входа/поведения.",
            "Сценарий похож на компрометацию учётных данных.",
        ]
        actions = [
            "Завершить активные сессии пользователя.",
            "Инициировать сброс пароля / re-auth.",
            "Проверить историю логинов за 24 часа и IP-репутацию.",
        ]
        evidence = ["login logs", "ip reputation", "device fingerprint", "geo history"]
    elif category.value == "bruteforce":
        summary = "Похоже на перебор пароля (bruteforce)."
        rationale = [
            "Есть множественные неуспешные попытки аутентификации.",
            "Паттерн соответствует автоматизированным попыткам входа.",
        ]
        actions = [
            "Включить rate-limit / временную блокировку по IP/аккаунту.",
            "Проверить IP-репутацию и распределение попыток по пользователям.",
            "Эскалировать, если был успешный вход после серии фейлов.",
        ]
        evidence = ["auth logs", "ip reputation", "rate-limit logs"]
    elif category.value == "phishing":
        summary = "Похоже на фишинг."
        rationale = [
            "В описании присутствуют маркеры письма/ссылки.",
            "Типовой вектор атаки — вредоносная ссылка/вложение.",
        ]
        actions = [
            "Изолировать артефакты (URL/хэши), проверить репутацию домена.",
            "Предупредить пользователя/подразделение, запретить переход по ссылке.",
            "Проверить, были ли клики/запуски вложения и последующие алерты.",
        ]
        evidence = ["email headers", "url/domain reputation", "endpoint logs", "proxy logs"]
    else:
        summary = "Недостаточно данных для уверенной классификации."
        rationale = [
            "Сигнал может быть шумом или неполным описанием инцидента.",
            "Нужны дополнительные артефакты для анализа.",
        ]
        actions = [
            "Уточнить источник события и временной диапазон.",
            "Запросить сырые логи и коррелирующие алерты (SIEM).",
            "Собрать таймлайн пользователя/хоста.",
        ]
        evidence = ["raw event", "related alerts", "user/host timeline"]

    latency_ms = int((time.perf_counter() - t0) * 1000)

    resp = TriageResponse(
        trace_id=trace_id,
        category=category,
        severity=severity,
        confidence=confidence,
        summary=summary,
        rationale=rationale,
        recommended_actions=actions,
        evidence_to_collect=evidence,
        sources=[],
        latency_ms=latency_ms,
    )

    write_audit(
        trace_id=trace_id,
        source=req.source,
        event_text=req.event_text,
        category=resp.category.value,
        severity=resp.severity.value,
        confidence=resp.confidence,
        route=route_tag,
        latency_ms=latency_ms,
        rag_sources=[],
        response=resp.model_dump(),
    )
    
    return resp

@app.get("/audit/{trace_id}", response_model=AuditRecord)
def audit_by_trace_id(trace_id: str) -> AuditRecord:
    rec = get_audit_by_trace_id(trace_id)
    if not rec:
        raise HTTPException(status_code=404, detail="trace_id not found")
    return AuditRecord(**rec)


@app.get("/audit", response_model=list[AuditRecord])
def audit_list(
    category: str | None = None,
    severity: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[AuditRecord]:
    def parse_dt(s: str | None) -> datetime | None:
        if not s:
            return None
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    rows = list_audit(
        category=category,
        severity=severity,
        time_from=parse_dt(time_from),
        time_to=parse_dt(time_to),
        limit=limit,
        offset=offset,
    )
    return [AuditRecord(**r) for r in rows]