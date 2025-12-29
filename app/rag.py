from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from langchain_chroma import Chroma
from langchain_community.embeddings.fastembed import FastEmbedEmbeddings

PERSIST_DIR = "storage/chroma"
COLLECTION = "soc_playbooks"


@dataclass
class RagHit:
    doc_id: str
    chunk_id: Optional[str]
    score: Optional[float]
    text: str
    metadata: dict[str, Any]


def _vs() -> Chroma:
    embeddings = FastEmbedEmbeddings()
    return Chroma(
        collection_name=COLLECTION,
        persist_directory=PERSIST_DIR,
        embedding_function=embeddings,
    )


def retrieve(event_text: str, k: int = 4, category: Optional[str] = None) -> list[RagHit]:
    vs = _vs()

    where: dict[str, Any]
    if category:
        where = {"$and": [{"doc_type": "playbook"}, {"category_primary": category}]}
    else:
        where = {"doc_type": "playbook"}

    pairs = vs.similarity_search_with_score(event_text, k=k, filter=where)

    hits: list[RagHit] = []
    for doc, score in pairs:
        meta = doc.metadata or {}
        hits.append(
            RagHit(
                doc_id=str(meta.get("doc_id", "unknown")),
                chunk_id=str(meta.get("chunk_id")) if meta.get("chunk_id") else None,
                score=float(score),
                text=doc.page_content,
                metadata=meta,
            )
        )
    return hits
