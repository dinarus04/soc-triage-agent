from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_community.embeddings.fastembed import FastEmbedEmbeddings
from langchain_community.vectorstores.utils import filter_complex_metadata


DATA_DIR = Path("data/playbooks")
PERSIST_DIR = Path("storage/chroma")
COLLECTION = "soc_playbooks"


def infer_metadata(doc_source: str) -> dict[str, Any]:
    name = Path(doc_source).name.lower()

    if name.startswith("methodology"):
        return {"doc_type": "methodology", "category_primary": ""}

    if "evidence" in name:
        return {"doc_type": "policy", "category_primary": ""}

    if "escalation" in name:
        return {"doc_type": "policy", "category_primary": ""}

    if "phishing" in name:
        return {"doc_type": "playbook", "category_primary": "phishing"}

    if "bruteforce" in name:
        return {"doc_type": "playbook", "category_primary": "bruteforce"}

    if "account_takeover" in name or "ato" in name:
        return {"doc_type": "playbook", "category_primary": "account_takeover"}

    return {"doc_type": "playbook", "category_primary": ""}


def main() -> None:
    if not DATA_DIR.exists():
        raise SystemExit(f"DATA_DIR not found: {DATA_DIR.resolve()}")

    loader = DirectoryLoader(
        str(DATA_DIR),
        glob="**/*.md",
        loader_cls=TextLoader,
        loader_kwargs={"encoding": "utf-8"},
        show_progress=True,
    )
    docs = loader.load()

    for d in docs:
        src = d.metadata.get("source", "")
        d.metadata["doc_id"] = Path(src).name
        d.metadata.update(infer_metadata(src))

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=900,
        chunk_overlap=150,
        separators=["\n## ", "\n### ", "\n- ", "\n", " "],
    )
    chunks = splitter.split_documents(docs)
    chunks = filter_complex_metadata(chunks)

    for i, ch in enumerate(chunks):
        ch.metadata["chunk_id"] = f"c{i:05d}"

    embeddings = FastEmbedEmbeddings()

    os.makedirs(PERSIST_DIR, exist_ok=True)
    vs = Chroma.from_documents(
        chunks,
        embedding=embeddings,
        persist_directory=str(PERSIST_DIR),
        collection_name=COLLECTION,
    )

    print(f"Loaded docs: {len(docs)}")
    print(f"Indexed chunks: {len(chunks)}")
    print(f"Persist dir: {PERSIST_DIR.resolve()}")
    print(f"Collection: {COLLECTION}")


if __name__ == "__main__":
    main()
