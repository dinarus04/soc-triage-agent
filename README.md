# SOC Triage Agent (RAG + LLM)

Сервис первичного triage инцидентов информационной безопасности для SOC-команд.

SOC - Security Operations Center

Проект реализует **детерминированную классификацию инцидентов**, **RAG-подтверждение через плейбуки** и **LLM-explainability**, с полным аудитом решений.

---

## Назначение проекта

Сервис принимает текст события (алерт SIEM, обращение пользователя, сообщение SOC-аналитика) и:

1. **Классифицирует инцидент правилами** (account takeover, bruteforce, phishing и т.д.)
2. **Подтягивает релевантные плейбуки реагирования** (RAG)
3. **Генерирует объяснение и рекомендации** с помощью LLM (опционально)
4. **Сохраняет полный аудит** принятого решения в БД

Проект имитирует реальный backend-сервис SOC / SOAR-системы.

---

## Архитектура (High Level)

```text
Client
  ↓
POST /triage
  ↓
Rule-based classification (deterministic)
  ↓
RAG (Chroma + embeddings)
  ↓
LLM explanation (feature-flagged)
  ↓
Audit log (PostgreSQL)
```
---

## Основные компоненты

### Rule-based triage

* Детерминированная классификация (`route()`)
* Предсказуемость и контроль (SOC-friendly)

### RAG (Retrieval-Augmented Generation)

* Векторное хранилище: **Chroma**
* Эмбеддинги: **fastembed / GigaChat**
* База знаний:

  * NIST / PICERL
  * Account Takeover
  * Bruteforce
  * Phishing
  * Escalation policy
  * Evidence collection

### LLM (опционально)

* Используется только для explainability
* Управляется feature-флагом (`LLM_ENABLED`)
* Интеграция с **GigaChat**

### Аудит

* PostgreSQL
* Хранится:

  * входной текст
  * категория / severity
  * confidence
  * RAG-источники
  * итоговый ответ

---

## Стек

* **Python 3.11**
* **FastAPI**
* **PostgreSQL**
* **SQLAlchemy**
* **LangChain**
* **Chroma**
* **GigaChat**
* **Docker / docker-compose**

---

## Запуск проекта

### 1. Поднять БД

```bash
docker compose up -d
```

### 2. Установить зависимости

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Загрузить базу знаний (RAG)

```bash
python scripts/ingest.py
```

### 4. Запустить API

```bash
uvicorn app.main:app --reload
```

---

## Feature flags

### Включение / выключение LLM

```bash
export LLM_ENABLED=true   # или false
```

### GigaChat

```bash
export API_KEY=...
export GIGACHAT_SCOPE=...
```

---

## Пример запроса

```bash
curl -X POST http://localhost:8000/triage \
  -H "Content-Type: application/json" \
  -d '{
    "event_text": "Multiple failed logins from new device followed by successful login",
    "source": "siem"
  }'
```

### Пример ответа

```json
{
  "category": "account_takeover",
  "severity": "P1",
  "confidence": 0.85,
  "summary": "Наблюдается попытка взлома аккаунта с множественными неудачными попытками входа с нового устройства, завершившаяся успехом.",
  "recommended_actions": ["Провести проверку устройства на наличие вредоносного ПО.",
                          "Усилить политики аутентификации и авторизации.","Обновить пользовательские уведомления о безопасности.",
                          "Мониторить активность учетной записи в реальном времени."],
  "rationale":["Необычные попытки входа могут указывать на попытку фишинга или брутфорса.",
                "Геолокация и устройство могут быть индикаторами компрометации учетной записи.",
                "Необходим мониторинг активности для предотвращения дальнейших инцидентов."],
  "evidence_to_collect":["Журналы аутентификации для анализа последовательности событий.",
                          "Журналы геолокации для определения необычной активности.",
                          "Журналы устройств для идентификации нового оборудования.",
                          "Журналы почтовых правил и доступа для выявления аномалий."]
  "sources": [{"doc_id":"account_takeover.md","chunk_id":"c00016","score":0.6302967667579651,"snippet":"## Identification (Идентификация)\n\n### Триггеры инцидента\n\n- Multiple failed login attempts с последующим успешным входом\n- Вход с нетипичных геолокаций, ASN или устройств\n- Отключение или обход MFA\n- Жалоба пользователя на подозрительную а"},{"doc_id":"account_takeover.md","chunk_id":"c00019","score":0.7559762597084045,"snippet":"## Recovery (Восстановление)\n\n- Восстановление корректного доступа пользователю\n- Контроль повторных попыток входа\n- Мониторинг активности учетной записи\n- Проверка затронутых конечных точек на наличие вредоносного ПО\n- Усиление политик аут"},{"doc_id":"account_takeover.md","chunk_id":"c00020","score":0.776915967464447,"snippet":"## Evidence to Collect\n\n- Authentication logs\n- IP / ASN reputation\n- Device fingerprint\n- Geo-location history\n- Почтовые правила и журналы доступа\n- История действий пользователя\n\
}
```

---

## Структура проекта

```text
app/
 ├── main.py        # FastAPI endpoints
 ├── router.py      # rule-based triage
 ├── rag.py         # retrieval
 ├── llm.py         # explanation generation
 ├── schemas.py    # Pydantic models
 ├── db.py          # audit storage
scripts/
 └── ingest.py      # RAG ingestion
storage/
 └── chroma/        # vector store
```

---

## SOC-подходы, реализованные в проекте

* Deterministic decision making
* Explainability вместо “LLM decides”
* Playbook-driven response
* Полный audit trail
* Feature-flagged AI

---

## Возможные улучшения

* LangGraph для orchestration
* Batch triage
* Feedback loop (confidence tuning)
* SIEM/SOAR integrations
* RBAC и auth

---

