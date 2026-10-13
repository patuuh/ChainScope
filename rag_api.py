'''rag_api.py
A lightweight FastAPI wrapper around the RAG pipeline.
It loads the FAISS index and chunk list once at start‑up, checks a SQLite cache for previous queries,
and if a cache miss occurs it runs the same retrieval + LLM call logic as `query_rag.py`.

Endpoints:
  POST /query
    {"query": "...", "top_k": 5}
    → returns {"answer": "...", "cached": false}

  GET /health
    → simple JSON health check.

Run with:
    uvicorn rag_api:app --host 0.0.0.0 --port 8001

Prereqs (installed automatically if missing):
    fastapi, uvicorn, faiss-cpu, sentence-transformers, requests, tiktoken, sqlite3 (builtin).
''' 

import argparse
import os
import sys
import json
import sqlite3
from typing import List
import logging

# ------------------------------------------------------------
# Helper to ensure a Python package is present (install if needed)
# ------------------------------------------------------------
def ensure_pkg(name, import_name=None):
    import_name = import_name or name
    try:
        __import__(import_name)
    except ImportError:
        print(f"[INFO] Installing {name}…", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", name])
        __import__(import_name)

# Ensure runtime dependencies
ensure_pkg("faiss-cpu", "faiss")
ensure_pkg("sentence-transformers")
ensure_pkg("fastapi")
ensure_pkg("uvicorn")
ensure_pkg("requests")
ensure_pkg("tiktoken")
ensure_pkg("slowapi")

import faiss
import requests
import tiktoken
from sentence_transformers import SentenceTransformer
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from pydantic import BaseModel

# ------------------------------------------------------------
# Logging configuration (audit log)
# ------------------------------------------------------------
logging.basicConfig(
    filename=os.path.join(os.getenv("RAG_INDEX_DIR", "."), "rag_api.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("rag_api")

# ------------------------------------------------------------
# Configuration (can be overridden via CLI args when running uvicorn)
# ------------------------------------------------------------
INDEX_DIR = os.getenv("RAG_INDEX_DIR", ".")
FAISS_PATH = os.path.join(INDEX_DIR, "rag_index.faiss")
CHUNKS_PATH = os.path.join(INDEX_DIR, "chunks.pkl")
CACHE_DB = os.path.join(INDEX_DIR, "rag_cache.db")
LLM_PORT = int(os.getenv("LLM_PORT", "8000"))
DEFAULT_TOP_K = int(os.getenv("RAG_TOP_K", "5"))

# ------------------------------------------------------------
# Load FAISS index and chunks (once at startup)
# ------------------------------------------------------------
if not os.path.exists(FAISS_PATH) or not os.path.exists(CHUNKS_PATH):
    raise RuntimeError("FAISS index or chunks file not found – run build_rag_index.py first.")

index = faiss.read_index(FAISS_PATH)
import pickle
with open(CHUNKS_PATH, "rb") as f:
    chunks: List[str] = pickle.load(f)

# Sentence‑Transformer model (same as indexing)
embedder = SentenceTransformer("all-MiniLM-L6-v2")

# ------------------------------------------------------------
# SQLite cache helpers
# ------------------------------------------------------------
def init_cache():
    conn = sqlite3.connect(CACHE_DB)
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS query_cache (
            query TEXT PRIMARY KEY,
            answer TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.commit()
    conn.close()

def get_cached_answer(query: str):
    conn = sqlite3.connect(CACHE_DB)
    cur = conn.cursor()
    cur.execute("SELECT answer FROM query_cache WHERE query = ?", (query,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def set_cached_answer(query: str, answer: str):
    conn = sqlite3.connect(CACHE_DB)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO query_cache (query, answer) VALUES (?,?)", (query, answer))
    conn.commit()
    conn.close()

init_cache()

# ------------------------------------------------------------
# Retrieval / LLM call helpers (same as in query_rag.py)
# ------------------------------------------------------------
def embed_query(query: str):
    return embedder.encode([query])[0]

def retrieve_top_k(query_vec, k: int):
    distances, ids = index.search(query_vec.reshape(1, -1), k)
    return ids[0]

def build_prompt(selected_chunks: List[str], user_query: str) -> str:
    context = "\n\n---\n\n".join(selected_chunks)
    return f"""You are a cybersecurity assistant. Use the following retrieved context to answer the user question.

Context:
{context}

Question: {user_query}

Answer:"""

def call_llm(prompt: str) -> str:
    url = f"http://127.0.0.1:{LLM_PORT}/v1/chat/completions"
    payload = {
        "model": "any",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
        "temperature": 0.2,
    }
    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()

# ------------------------------------------------------------
# FastAPI app, CORS, and rate limiting
# ------------------------------------------------------------
app = FastAPI(title="ChainScope RAG API", version="0.1")
origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiter – 5 requests per minute per IP
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

class QueryRequest(BaseModel):
    query: str
    top_k: int = DEFAULT_TOP_K

@app.get("/health")
def health_check():
    return {"status": "ok"}

@limiter.limit("5/minute")
@app.post("/query")
def rag_query(req: QueryRequest, request: Request, api_key: str = Header(None, alias="X-API-Key")):
    # 🔐 Authentication (optional – set API_KEY env var to enable)
    expected_key = os.getenv("API_KEY")
    if expected_key and api_key != expected_key:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # 🛡️ Basic input validation
    if len(req.query) > 500:
        raise HTTPException(status_code=400, detail="Query too long (max 500 characters)")
    unsafe_substrings = ["<script", "</script>", "javascript:"]
    if any(s in req.query.lower() for s in unsafe_substrings):
        raise HTTPException(status_code=400, detail="Query contains potentially unsafe content")

    # 1️⃣ Cache lookup
    cached = get_cached_answer(req.query)
    if cached:
        logger.info(f"IP={request.client.host} query_hash={hash(req.query)} cached=True")
        return {"answer": cached, "cached": True}

    # 2️⃣ Retrieval
    q_vec = embed_query(req.query)
    ids = retrieve_top_k(q_vec, req.top_k)
    selected = [chunks[i] for i in ids]

    # 3️⃣ Prompt & LLM
    prompt = build_prompt(selected, req.query)
    try:
        answer = call_llm(prompt)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # 4️⃣ Store in cache
    set_cached_answer(req.query, answer)
    logger.info(f"IP={request.client.host} query_hash={hash(req.query)} cached=False")
    return {"answer": answer, "cached": False}

# ------------------------------------------------------------
# Optional CLI entry point for quick testing (uvicorn can also be used directly)
# ------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    parser = argparse.ArgumentParser(description="Run the RAG FastAPI server.")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8001, help="Port to bind (default 8001)")
    args = parser.parse_args()
    uvicorn.run("rag_api:app", host=args.host, port=args.port, log_level="info")
