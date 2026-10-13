'''build_rag_index.py
Utility script to create a simple RAG index from a large text document.
It:
  1️⃣ Splits the document into ~7.5k‑token chunks (leaving room for a response).
  2️⃣ Computes dense embeddings for each chunk using a lightweight Sentence‑Transformer.
  3️⃣ Stores the embeddings in a FAISS index (cpu) and saves the chunk texts.

Usage:
    python build_rag_index.py <path-to-document> [--chunk-tokens 7500]

The resulting files (`rag_index.faiss` and `chunks.pkl`) are written to the same directory as the script.
''' 

import argparse
import os
import pickle
import sys

# ------------------------------------------------------------
# 1️⃣ Token‑based chunking (uses tiktoken – same as the bash helper)
# ------------------------------------------------------------
def chunk_text_by_tokens(text: str, max_tokens: int = 7500) -> list[str]:
    try:
        import tiktoken
    except ImportError:
        print("[ERROR] tiktoken not installed – installing now…", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "tiktoken"])
        import tiktoken
    enc = tiktoken.get_encoding("cl100k_base")
    tokens = enc.encode(text)
    chunks = []
    for i in range(0, len(tokens), max_tokens):
        chunk_tokens = tokens[i:i + max_tokens]
        chunks.append(enc.decode(chunk_tokens))
    return chunks

# ------------------------------------------------------------
# 2️⃣ Embedding generation (sentence‑transformers)
# ------------------------------------------------------------
def embed_chunks(chunks: list[str]):
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("[INFO] Installing sentence‑transformers…", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "sentence-transformers"])
        from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("all-MiniLM-L6-v2")  # ~384‑dim, cpu‑friendly
    embeddings = model.encode(chunks, show_progress_bar=True, batch_size=32)
    return embeddings

# ------------------------------------------------------------
# 3️⃣ Build FAISS index and persist data
# ------------------------------------------------------------
def build_and_save_index(embeddings, chunks, out_dir: str):
    try:
        import faiss
    except ImportError:
        print("[INFO] Installing faiss‑cpu…", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "faiss-cpu"])
        import faiss
    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(embeddings)
    # Persist index
    faiss_path = os.path.join(out_dir, "rag_index.faiss")
    faiss.write_index(index, faiss_path)
    # Persist chunk texts
    chunks_path = os.path.join(out_dir, "chunks.pkl")
    with open(chunks_path, "wb") as f:
        pickle.dump(chunks, f)
    print(f"[INFO] FAISS index saved to {faiss_path}")
    print(f"[INFO] Chunk texts saved to {chunks_path}")

# ------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Create a simple FAISS RAG index from a large text file.")
    parser.add_argument("document", help="Path to the large .txt document.")
    parser.add_argument("--chunk-tokens", type=int, default=7500, help="Maximum tokens per chunk (default 7500).")
    parser.add_argument("--out-dir", default=".", help="Directory to write rag_index.faiss and chunks.pkl (default current dir).")
    args = parser.parse_args()

    if not os.path.isfile(args.document):
        print(f"[ERROR] Document not found: {args.document}", file=sys.stderr)
        sys.exit(1)

    with open(args.document, "r", encoding="utf-8") as f:
        text = f.read()

    print("[INFO] Splitting document into token‑based chunks…")
    chunks = chunk_text_by_tokens(text, max_tokens=args.chunk_tokens)
    print(f"[INFO] Created {len(chunks)} chunks.")

    print("[INFO] Generating embeddings for each chunk…")
    embeddings = embed_chunks(chunks)

    print("[INFO] Building FAISS index and saving files…")
    os.makedirs(args.out_dir, exist_ok=True)
    build_and_save_index(embeddings, chunks, args.out_dir)

if __name__ == "__main__":
    main()
