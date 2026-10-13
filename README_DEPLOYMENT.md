# ChainScope & LLM Deployment on OCI

## Overview
This guide walks you through deploying a large‑language model (GLM‑5.3 or GPT‑OSS) on Oracle Cloud Infrastructure (OCI) **and** optionally running the ChainScope MCP server on the same VM. The deployment is entirely scripted with the **OCI CLI** and a single Bash helper (`deploy_llm_oci.sh`).

---

## 1. Prerequisites
| Requirement | How to satisfy |
|------------|----------------|
| **OCI CLI** installed & configured (`~/.oci/config`) | `oci setup config` – follow the interactive prompts. |
| **SSH key pair** (`~/.ssh/id_rsa` + `~/.ssh/id_rsa.pub`) | Generate with `ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa` if you don’t have one. |
| **Docker** locally (for building images – optional)** | `docker --version`. The script only needs Docker if you wish to push a custom image; it pulls the public model image directly on the VM. |
| **Compartment OCID** where you can create instances & OCIR repos | Run `oci iam compartment list --compartment-id <tenancy-ocid>` to locate it. |
| **Quota** for the chosen shape (GPU shapes require a paid compartment) | Verify with `oci limits service list --service-name compute`.

---

## 2. File Structure
```
ChainScope/
├─ deploy_llm_oci.sh          # <– **the script you just created**
└─ README_DEPLOYMENT.md      # <– **this documentation** (you are reading it)
```
Place `deploy_llm_oci.sh` at the root of the ChainScope repo (the path is already set in the script).

---

## 3. Step‑by‑Step Execution
### 3.1. Fill in the placeholders
Edit `deploy_llm_oci.sh` and replace:
- `<YOUR_COMPARTMENT_OCID>` with the OCID of the compartment you’ll use.
- (Optional) Change `INSTANCE_SHAPE` if you want a CPU‑only shape (`VM.Standard.E2.1.Micro`) or a different GPU shape.
- If you prefer a region other than `us‑ashburn‑1`, change `REGION`.

### 3.2. Make the script executable
```bash
chmod +x deploy_llm_oci.sh
```

### 3.3. Run the deployment
```bash
# Deploy GLM‑5.3 (default)
./deploy_llm_oci.sh glm

# Or deploy GPT‑OSS‑120B
./deploy_llm_oci.sh gpt
```
The script will:
1. **Create an OCIR repository** (public) – used only if you later push a custom image.
2. **Launch a Compute instance** (GPU by default). It waits until the instance reaches the `RUNNING` state.
3. **Open inbound TCP ports** `8000` (LLM) and `8001` (ChainScope) on the VCN’s default security list.
4. **SSH into the VM**, install Docker (if missing), pull the model image, and start it on port `8000`.
5. **Optionally clone & start ChainScope** (the repo is cloned into `/home/opc/ChainScope` and started on port `8001`).
6. Prints the public IP and URLs for both services.

### 3.4. Verify the deployment
```bash
# Replace <PUBLIC_IP> with the IP printed by the script
curl http://<PUBLIC_IP>:8000/health   # Expected: some JSON health payload
curl http://<PUBLIC_IP>:8001/        # Should return ChainScope’s JSON‑RPC "help" output
```
If you see JSON responses, both services are up and reachable.

### 3.5. Stop / clean up
```bash
# SSH into the instance
ssh -i ~/.ssh/id_rsa opc@<PUBLIC_IP>
# Stop containers
docker stop llm-service && docker rm llm-service
docker stop chainscope && docker rm chainscope   # only if ChainScope was started
# OPTIONAL: terminate the instance (and any associated resources)
oci compute instance terminate --instance-id <INSTANCE_OCID> --preserve-boot-volume false
```

---

## 4. Optional Next Steps (Production‑Ready Enhancements)
### 4.1. Load Balancer & DNS
Create an OCI **Load Balancer** with two backend sets:
- **LLM‑backend** → port `8000`
- **ChainScope‑backend** → port `8001`
Add a **listener** on port `443` (HTTPS) that uses **path‑based routing** (`/llm/*` → LLM, `/chainscope/*` → ChainScope).
Assign a **DNS record** (e.g., `ai.mycompany.com`) pointing to the LB’s public IP.

### 4.2. TLS Termination
If you use a Load Balancer, enable **TLS** with a certificate from Let’s Encrypt or a commercial CA. Alternatively, run **Caddy** or **NGINX** inside the same VM as a reverse‑proxy:
```bash
# Example NGINX snippet (place in /etc/nginx/conf.d/oci-llm.conf)
server {
    listen 443 ssl;
    server_name ai.mycompany.com;
    ssl_certificate /etc/letsencrypt/live/ai.mycompany.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ai.mycompany.com/privkey.pem;

    location /llm/ {
        proxy_pass http://127.0.0.1:8000/;
    }
    location /chainscope/ {
        proxy_pass http://127.0.0.1:8001/;
    }
}
```
### 4.3. Autoscaling & Instance Pools
If you anticipate high request volume, create an **Instance Pool** using the same launch script as a cloud‑init script. Pair it with an **Autoscaling Configuration** that adds/removes VMs based on CPU or custom Cloud‑Watch metrics.
### 4.4. Logging & Monitoring
- **OCI Logging**: enable the **Log OCI‑CLI** integration for Docker (`--log-driver=oci`).
- **Metrics**: expose Prometheus metrics from your model container (many images have `/metrics`). Add a **Monitoring Alarm** for CPU/GPU utilization.
### 4.5. Persistent Storage for the Graph DB
If you keep ChainScope, mount a **Block Volume** at `/home/opc/ChainScope` and configure `graph.db` to live on that volume so the graph persists after instance termination.
```bash
# Example during launch (add to the script)
oci compute volume create --compartment-id $COMPARTMENT_OCID --availability-domain $AD --size-in-gbs 50 --display-name chain-db
# Attach and mount the volume inside the SSH block before starting ChainScope.
```
### 4.6. Secure Model Access
- **IAM policies** to restrict who can invoke the LLM endpoint.
- **API token** validation inside the container (wrap the model server behind a tiny Flask auth layer).

---

## 5. TL;DR Cheat‑Sheet
```bash
# 1️⃣ Edit placeholders in deploy_llm_oci.sh
# 2️⃣ Make it executable
chmod +x deploy_llm_oci.sh
# 3️⃣ Deploy GLM‑5.3 (or GPT‑OSS)
./deploy_llm_oci.sh glm   # or ./deploy_llm_oci.sh gpt
# 4️⃣ Verify
curl http://<IP>:8000/health
curl http://<IP>:8001/
# 5️⃣ (Optional) Add LB, TLS, autoscaling, persistent storage as described above.
```

---

## 6. References
- OCI CLI docs: https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/
- FastMCP / ChainScope repo: https://github.com/Immunefi/ChainScope
- GLM‑5.3 Docker image (public): `zhipuai/glm-5.3b`
- GPT‑OSS Docker image (public): `gpt-oss/120b`
- OCI Load Balancer guide: https://docs.oracle.com/en-us/iaas/Content/Balance/Concepts/balanceoverview.htm

---

**Enjoy your new AI‑powered OCI deployment!** If you need any of the optional pieces (Terraform modules, Load‑Balancer YAML, etc.) just let me know.
