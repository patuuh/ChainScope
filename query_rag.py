'''query_rag.py
Utility script that loads a FAISS RAG index built by `build_rag_index.py`, retrieves the most relevant chunks for a user query, and forwards them to the locally‑running LLM (served via the vllm OpenAI‑compatible endpoint) to generate a response.

Usage:
    python query_rag.py "<your question>" [--top-k 5] [--model-port 8000]

Prerequisites:
  * The LLM container must be running (e.g., after `./run_on_existing_vm.sh foundation-gguf`).
  * `faiss`, `requests`, and `tiktoken` are installed (the script will install them if missing).
''' 

import argparse
import os
import sys
import json

def ensure_package(pkg_name, import_name=None):
    import_name = import_name or pkg_name
    try:
        __import__(import_name)
    except ImportError:
        print(f"[INFO] Installing {pkg_name}…", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", pkg_name])
        __import__(import_name)

# Ensure dependencies
ensure_package("faiss-cpu", "faiss")
ensure_package("requests")
ensure_package("tiktoken")

import faiss
import requests
import tiktoken

def load_index_and_chunks(index_path: str, chunks_path: str):
    index = faiss.read_index(index_path)
    with open(chunks_path, "rb") as f:
        chunks = pickle.load(f)
    return index, chunks

def embed_query(query: str):
    # Re‑use the same Sentence‑Transformer model used for indexing.
    ensure_package("sentence-transformers")
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("all-MiniLM-L6-v2")
    return model.encode([query])[0]

def retrieve_top_k(index, query_vec, k: int = 5):
    distances, ids = index.search(query_vec.reshape(1, -1), k)
    return ids[0]

def build_prompt(context_chunks, user_query):
    # Simple prompt template – you can customise.
    context = "\n\n---\n\n".join(context_chunks)
    prompt = f"""You are a cybersecurity assistant. Use the following retrieved context to answer the user question.

Context:
{context}

Question: {user_query}

Answer:"""
    return prompt

def call_llm(prompt: str, model_port: int = 8000):
    url = f"http://127.0.0.1:{model_port}/v1/chat/completions"
    payload = {
        "model": "any",  # vllm ignores the name but expects a field
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
        "temperature": 0.2,
    }
    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    # vllm returns a list under "choices"
    return data["choices"][0]["message"]["content"].strip()

def main():
    parser = argparse.ArgumentParser(description="RAG query against a local LLM.")
    parser.add_argument("query", help="User question / query string.")
    parser.add_argument("--top-k", type=int, default=5, help="Number of retrieved chunks (default 5).")
    parser.add_argument("--model-port", type=int, default=8000, help="Port where the LLM container is listening.")
    parser.add_argument("--index-dir", default=".", help="Directory containing rag_index.faiss and chunks.pkl.")
    args = parser.parse_args()

    index_path = os.path.join(args.index_dir, "rag_index.faiss")
    chunks_path = os.path.join(args.index_dir, "chunks.pkl")
    if not os.path.exists(index_path) or not os.path.exists(chunks_path):
        print("[ERROR] RAG index files not found. Run build_rag_index.py first.", file=sys.stderr)
        sys.exit(1)

    import pickle
    import numpy as np

    index, chunks = load_index_and_chunks(index_path, chunks_path)
    query_vec = embed_query(args.query)
    top_ids = retrieve_top_k(index, query_vec, k=args.top_k)
    top_chunks = [chunks[i] for i in top_ids]
    prompt = build_prompt(top_chunks, args.query)
    answer = call_llm(prompt, model_port=args.model_port)
    print("--- Answer ---\n")
    print(answer)

if __name__ == "__main__":
    main()
