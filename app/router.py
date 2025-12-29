from __future__ import annotations
from app.schemas import Category, Severity


def route(event_text: str) -> tuple[Category, Severity, float, str]:
    t = event_text.lower()

    # Account takeover (ATO): новый девайс + успешный вход после аномалий
    if (("new device" in t) or ("новое устройство" in t)) and (("login" in t) or ("вход" in t)) and (("success" in t) or ("успеш" in t)):
        return Category.account_takeover, Severity.P1, 0.85, "rules:ato"

    # Bruteforce: много неудачных логинов
    if (("failed login" in t) or ("неудач" in t) or ("bruteforce" in t) or ("брут" in t)) and (("many" in t) or ("много" in t) or ("multiple" in t) or ("несколько" in t)):
        return Category.bruteforce, Severity.P2, 0.78, "rules:bruteforce"

    # Phishing: письмо + ссылка
    if ("phish" in t) or ("фиш" in t) or (("email" in t) and ("link" in t)) or (("письмо" in t) and ("ссылка" in t)):
        return Category.phishing, Severity.P2, 0.72, "rules:phishing"

    return Category.unknown, Severity.P3, 0.55, "rules:unknown"
