#!/usr/bin/env bash
# ------------------------------------------------------------------
# deploy_llm_oci.sh
# Deploy GLM‑5.3 or GPT‑OSS on an OCI compute instance and (optionally)
# start ChainScope alongside it.
# ------------------------------------------------------------------
set -euo pipefail

# ------------------- USER‑CONFIGURABLE SETTINGS --------------------
# OCI tenancy / compartment
COMPARTMENT_OCID="<YOUR_COMPARTMENT_OCID>"   # e.g. ocid1.compartment.oc1..aaaa...
REGION="${OCI_REGION:-us-ashburn-1}"        # change if needed

# SSH key to inject into the instance (public key)
SSH_PUBLIC_KEY_PATH="${HOME}/.ssh/id_rsa.pub"

# Choose the model you want:
#   - GLM5.3 : IMAGE="zhipuai/glm-5.3b:latest"
#   - GPT‑OSS: IMAGE="gpt-oss/120b:latest"
MODEL_CHOICE="${1:-foundation}"  # default to Foundation-Sec-8B-Instruct if no arg supplied

if [[ "$MODEL_CHOICE" == "glm" ]]; then
    IMAGE="zhipuai/glm-5.3b:latest"
    MODEL_NAME="glm-5.3b"
elif [[ "$MODEL_CHOICE" == "gpt" ]]; then
    IMAGE="gpt-oss/120b:latest"
    MODEL_NAME="gpt-oss-120b"
elif [[ "$MODEL_CHOICE" == "qwen" ]]; then
    IMAGE="vllm/vllm-openai:latest"
    MODEL_NAME="qwen2.5-coder-7b-instruct"
elif [[ "$MODEL_CHOICE" == "foundation" ]]; then
    IMAGE="vllm/vllm-openai:latest"
    MODEL_NAME="fdtn-ai/Foundation-Sec-8B-Instruct"
else
    echo "Invalid model choice: $MODEL_CHOICE (use 'glm', 'gpt', 'qwen', or 'foundation')" >&2
    exit 1
fi

# Compute shape – GPU shapes cost money; pick one that fits your budget.
# FREE‑TIER shapes (CPU only) → VM.Standard.E2.1.Micro
# GPU shape (recommended for inference) → VM.GPU3.1 (NVIDIA A10)
INSTANCE_SHAPE="VM.GPU3.1"   # change to CPU shape if you prefer
INSTANCE_NAME="${MODEL_NAME}-instance"

# Ports
MODEL_PORT=8080        # LLM service (exposed externally, matches llama server)
export CORS_ORIGINS="*"
export LLM_PORT=8080
# Allowed CIDR ranges for inbound traffic (default all, change for stricter security)
ALLOWED_IP_RANGES="0.0.0.0/0"
CHAINSCOPPE_PORT=8001  # ChainScope (optional)

# ---------------------------------------------------------------
log() { echo -e "\e[32m[INFO]\e[0m $*"; }
err() { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }

# ------------------------------------------------------------------
# 0. Verify OCI CLI is present
# ------------------------------------------------------------------
if ! command -v oci >/dev/null 2>&1; then
    err "OCI CLI not found – install it per https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm"
fi

# ------------------------------------------------------------------
# 1. Create (or reuse) an OCIR repository for the model image
# ------------------------------------------------------------------
REPO_NAME="${MODEL_NAME}-repo"
log "Ensuring OCIR repository '${REPO_NAME}' exists ..."
REPO_OCID=$(oci artifacts container repository list \
    --compartment-id "$COMPARTMENT_OCID" \
    --display-name "$REPO_NAME" \
    --query "data[0].id" \
    --raw-output || true)

if [[ -z "$REPO_OCID" ]]; then
    REPO_OCID=$(oci artifacts container repository create \
        --compartment-id "$COMPARTMENT_OCID" \
        --display-name "$REPO_NAME" \
        --is-public true \
        --query "data.id" \
        --raw-output)
    log "Created repository $REPO_OCID"
else
    log "Repository already exists: $REPO_OCID"
fi

# ------------------------------------------------------------------
# 2. Launch a Compute instance
# ------------------------------------------------------------------
log "Fetching latest Oracle Linux 8 image ..."
SOURCE_IMAGE_OCID=$(oci compute image list \
    --compartment-id "$COMPARTMENT_OCID" \
    --operating-system "Oracle Linux" \
    --operating-system-version "8" \
    --query "data[0].id" \
    --raw-output)

log "Launching instance '${INSTANCE_NAME}' (shape=${INSTANCE_SHAPE}) ..."
INSTANCE_OCID=$(oci compute instance launch \
    --availability-domain "$(oci iam compartment list --compartment-id "$COMPARTMENT_OCID" --query 'data[0].name' --raw-output)" \
    --compartment-id "$COMPARTMENT_OCID" \
    --shape "$INSTANCE_SHAPE" \
    --display-name "$INSTANCE_NAME" \
    --image-id "$SOURCE_IMAGE_OCID" \
    --metadata "{\"ssh_authorized_keys\":\"$(cat "$SSH_PUBLIC_KEY_PATH")\"}" \
    --create-vnic-details "{\"assignPublicIp\":true,\"skipSourceDestCheck\":false}" \
    --query "data.id" \
    --raw-output)
log "Instance OCID: $INSTANCE_OCID"
log "Waiting for instance to become RUNNING ..."
oci compute instance wait --instance-id "$INSTANCE_OCID" --wait-for-state RUNNING

# ------------------------------------------------------------------
# 3. Open firewall ports (8000 for LLM, 8001 for ChainScope)
# ------------------------------------------------------------------
log "Fetching networking IDs ..."
VNIC_OCID=$(oci compute instance list-vnics \
    --instance-id "$INSTANCE_OCID" \
    --query "data[0].vnic-id" \
    --raw-output)
VCN_OCID=$(oci network vnic get \
    --vnic-id "$VNIC_OCID" \
    --query "data.vcn-id" \
    --raw-output)
SECURITY_LIST_OCID=$(oci network vcn list \
    --vcn-id "$VCN_OCID" \
    --query "data[0].default-security-list-id" \
    --raw-output)
log "Adding ingress rules for ports $MODEL_PORT and $CHAINSCOPPE_PORT ..."
oci network security-list update \
    --security-list-id "$SECURITY_LIST_OCID" \
    --ingress-security-rules "[
        {\"description\": \"LLM HTTP\", \"protocol\": \"6\", \"source\": \"0.0.0.0/0\", \"tcpOptions\": {\"destinationPortRange\": {\"min\": $MODEL_PORT, \"max\": $MODEL_PORT}}},
        {\"description\": \"ChainScope HTTP\", \"protocol\": \"6\", \"source\": \"0.0.0.0/0\", \"tcpOptions\": {\"destinationPortRange\": {\"min\": $CHAINSCOPPE_PORT, \"max\": $CHAINSCOPPE_PORT}}}
    ]" >/dev/null

# ------------------------------------------------------------------
# 4. SSH into the instance and set up Docker + containers
# ------------------------------------------------------------------
PUBLIC_IP=$(oci compute instance list-vnics \
    --instance-id "$INSTANCE_OCID" \
    --query "data[0].public-ip" \
    --raw-output)
log "Public IP of instance: $PUBLIC_IP"
log "Connecting via SSH to provision Docker and start containers …"
SSH_PRIVATE_KEY="${SSH_PUBLIC_KEY_PATH%.*}"
ssh -o StrictHostKeyChecking=no -i "$SSH_PRIVATE_KEY" opc@"$PUBLIC_IP" <<'EOSSH'
set -euo pipefail
# Install Docker if missing
echo "[INFO] Installing Docker (if needed)"
if ! command -v docker >/dev/null 2>&1; then
    sudo yum install -y docker >/dev/null
    sudo systemctl enable --now docker
fi
# Pull the LLM image (IMAGE is exported from the outer script)
echo "[INFO] Pulling model image $IMAGE"
docker pull $IMAGE
# Run the LLM container
echo "[INFO] Starting LLM container on port ${MODEL_PORT}"
docker run -d \
    --name llm-service \
    -p ${MODEL_PORT}:${MODEL_PORT} \
    -e PORT=${MODEL_PORT} \
    $IMAGE
# (Optional) ChainScope – clone repo if not present and start it on port 8001
if [ ! -d "$HOME/ChainScope" ]; then
    echo "[INFO] Cloning ChainScope repository"
    git clone https://github.com/Immunefi/ChainScope.git "$HOME/ChainScope"
fi
cd "$HOME/ChainScope"
log "Starting Nginx reverse‑proxy with TLS termination"
# Pull a minimal nginx image (if not already present)
if ! docker image inspect nginx:stable-alpine > /dev/null 2>&1; then
    docker pull nginx:stable-alpine
fi
# Run Nginx, mounting the config and self‑signed certs from the repo
docker run -d \
    --name chainscope-nginx \
    -p 80:80 -p 443:443 \
    -v "$(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$(pwd)/ssl:/etc/nginx/ssl:ro" \
    nginx:stable-alpine
log "✅ Nginx container ready – HTTPS endpoint is https://$PUBLIC_IP/"
EOSSH

log "✅ Deployment complete! 🎉"
log "• LLM service (${MODEL_NAME}) → http://$PUBLIC_IP:$MODEL_PORT/"
log "• ChainScope (if cloned)   → http://$PUBLIC_IP:$CHAINSCOPPE_PORT/"

# ------------------------------------------------------------------
# 5. Quick test (optional)
# ------------------------------------------------------------------
log "Running a quick health‑check against the LLM endpoint …"
curl -s "http://$PUBLIC_IP:$MODEL_PORT/health" || true

log "All done. To stop the containers later, SSH in and run:"
log "  docker stop llm-service && docker rm llm-service"
log "  docker stop chainscope && docker rm chainscope   # if you started it"
