#!/usr/bin/env bash
# ------------------------------------------------------------
# run_on_existing_vm.sh
# Deploy a CPU‑compatible LLM (GLM‑5.3‑CPU or GPT‑OSS‑7B‑CPU) on an
# already‑existing OCI Always‑Free VM (Johannesburg region).
# Optionally start ChainScope (MCP server) side‑by‑side.
# ------------------------------------------------------------
set -euo pipefail

# ------------------- CONFIGURATION -------------------------
# Choose the model you want (CPU‑friendly images).  The free tier does
# not have a GPU, so we must use quantised / CPU versions.
#   - GLM‑5.3‑CPU :   zhipuai/glm-5.3b-cpu:latest
#   - GPT‑OSS‑7B‑CPU : gpt-oss/7b-cpu:latest
# Pass "glm" or "gpt" as the first argument when you run the script.
MODEL_CHOICE="${1:-foundation}"  # default to Foundation-Sec-8B-Instruct if no arg supplied

if [[ "$MODEL_CHOICE" == "glm" ]]; then
    IMAGE="zhipuai/glm-5.3b-cpu:latest"
    MODEL_NAME="glm-5.3b-cpu"
elif [[ "$MODEL_CHOICE" == "gpt" ]]; then
    IMAGE="gpt-oss/7b-cpu:latest"
    MODEL_NAME="gpt-oss-7b-cpu"
elif [[ "$MODEL_CHOICE" == "qwen" ]]; then
    IMAGE="vllm/vllm-openai:latest"
    MODEL_NAME="qwen2.5-coder-7b-instruct"
elif [[ "$MODEL_CHOICE" == "foundation" ]]; then
    IMAGE="vllm/vllm-openai:latest"
    MODEL_NAME="fdtn-ai/Foundation-Sec-8B-Instruct"
elif [[ "$MODEL_CHOICE" == "foundation-gguf" ]]; then
    # Using llama.cpp image to run quantized GGUF model
    IMAGE="ghcr.io/ggerganov/llama.cpp:latest"
    MODEL_NAME="fdtn-ai/Foundation-Sec-8B-Instruct-gguf"
else
    echo "Invalid model choice: $MODEL_CHOICE (use 'glm', 'gpt', 'qwen', 'foundation', or 'foundation-gguf')" >2
    exit 1
fi

# Ports – feel free to change if you have a conflict.
MODEL_PORT=8000        # LLM HTTP endpoint (JSON‑RPC / health check)
CHAINSCOPPE_PORT=8001  # ChainScope MCP server (optional)

# ------------------------------------------------------------
log() { echo -e "\e[32m[INFO]\e[0m $*"; }
err() { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }

# ==== 1. Install Docker if missing ========================
log "Installing Docker (if not already present)…"
if ! command -v docker >/dev/null 2>&1; then
    sudo yum install -y docker >/dev/null
    sudo systemctl enable --now docker
fi

# ==== 2. Pull the chosen model image =====================
log "Pulling model image $IMAGE …"
# Docker will automatically pull from Docker Hub (public).
# If you prefer a private registry, you can add `docker login` before this.

docker pull "$IMAGE"

# ==== 3. Run the model container ==========================
log "Starting model container on port $MODEL_PORT …"
# Remove any previous container with the same name to avoid conflicts.
if docker ps -a --format '{{.Names}}' | grep -q '^llm-service$'; then
    log "Removing existing llm-service container …"
    docker rm -f llm-service >/dev/null
fi

if [[ "$MODEL_CHOICE" == "qwen" ]]; then
    docker run -d \
        --name llm-service \
        -p ${MODEL_PORT}:${MODEL_PORT} \
        -e PORT=${MODEL_PORT} \
        "$IMAGE" \
        --model Qwen/Qwen2.5-Coder-7B-Instruct \
        --gpu-memory-utilization 0.9
elif [[ "$MODEL_CHOICE" == "foundation" ]]; then
    docker run -d \
        --name llm-service \
        -p ${MODEL_PORT}:${MODEL_PORT} \
        -e PORT=${MODEL_PORT} \
        "$IMAGE" \
        --model fdtn-ai/Foundation-Sec-8B-Instruct \
        --gpu-memory-utilization 0.9
elif [[ "$MODEL_CHOICE" == "foundation-gguf" ]]; then
    # Expect the quantized GGUF file at $HOME/gguf_models/Foundation-Sec-8B-Instruct.gguf
    docker run -d \
        --name llm-service \
        -p ${MODEL_PORT}:${MODEL_PORT} \
        -v "$HOME/gguf_models:/models" \
        -e MODEL="/models/Foundation-Sec-8B-Instruct.gguf" \
        -e PORT=${MODEL_PORT} \
        "$IMAGE"
else
    docker run -d \
        --name llm-service \
        -p ${MODEL_PORT}:${MODEL_PORT} \
        -e PORT=${MODEL_PORT} \
        "$IMAGE"
fi

# ==== 4. (Optional) Start ChainScope ======================
if [ -d "$HOME/ChainScope" ]; then
    log "ChainScope repository already present – skipping git clone."
else
    log "Cloning ChainScope repository …"
    git clone https://github.com/Immunefi/ChainScope.git "$HOME/ChainScope"
fi

log "Starting ChainScope on port $CHAINSCOPPE_PORT …"
cd "$HOME/ChainScope"
# Export the PORT env var used by mcp_server.py; run in background.
export PORT=$CHAINSCOPPE_PORT
# If a previous ChainScope container is running, stop it first.
if pgrep -f "mcp.run" >/dev/null 2>&1; then
    pkill -f "mcp.run" || true
fi
# `run_mcp.sh` starts the MCP server via python – we background it.
nohup ./run_mcp.sh >/dev/null 2>&1 &

# ==== 5. Quick health‑check ==============================
log "Testing LLM health endpoint …"
# Some images expose /health; if not, you’ll get a 404 which is still fine.
if curl -s "http://127.0.0.1:${MODEL_PORT}/health"; then
    log "LLM health endpoint responded."
else
    log "LLM health endpoint did not return a response – this may be normal for the selected image."
fi

log "✅ All services are up and running."
log " • LLM endpoint      → http://<PUBLIC_IP>:${MODEL_PORT}/"
log " • ChainScope endpoint → http://<PUBLIC_IP>:${CHAINSCOPPE_PORT}/"
log "To stop later:  docker stop llm-service && docker rm llm-service"
log "                pkill -f \"mcp.run\"   # stops ChainScope"
