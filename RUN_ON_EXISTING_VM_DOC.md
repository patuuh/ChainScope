# Documentation for `run_on_existing_vm.sh`

## Overview
`run_on_existing_vm.sh` is a **self‑contained Bash helper** designed to **deploy a CPU‑compatible large language model (LLM)** and **optionally start the ChainScope MCP server** on an **already‑provisioned OCI Always‑Free VM** (Johannesburg region). The script does **not** create a new compute instance – it assumes you already have a running VM with public internet access.

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Configuration parameters](#configuration-parameters)
3. [Step‑by‑step walkthrough (line‑by‑line)](#step‑by‑step-walkthrough)
4. [Running the script](#running-the-script)
5. [Verification & health‑checks](#verification--health‑checks)
6. [Stopping / cleaning up](#stopping--clean‑up)
7. [Optional enhancements & next steps](#optional-enhancements--next-steps)
8. [FAQ & troubleshooting](#faq--troubleshooting)

---

## Prerequisites
| Requirement | How to satisfy |
|-------------|----------------|
| **OCI CLI** configured (`~/.oci/config`) | `oci setup config` – follow prompts. |
| **SSH key** (`~/.ssh/id_rsa`/`id_rsa.pub`) for the VM | `ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa` if missing. |
| **Docker** on the VM (the script will install it if absent) | No action needed – script handles it. |
| **Public ports 8000 & 8001 opened** on the VCN security list | Run the one‑time `oci network security-list update` command from the original guide, or verify via the console. |
| **Git** (for optional ChainScope clone) | Pre‑installed on most Oracle Linux images; otherwise `sudo yum install -y git`. |

---

## Configuration parameters (top of the script)
```bash
# Choose the model you want (CPU‑friendly images).  The free tier does
# not have a GPU, so we must use quantised / CPU versions.
#   - GLM‑5.3‑CPU   : zhipuai/glm-5.3b-cpu:latest
#   - GPT‑OSS‑7B‑CPU: gpt-oss/7b-cpu:latest
#   - Qwen2.5‑Coder‑7B‑Instruct: vllm/vllm-openai (model passed as argument)
#   - Foundation‑Sec‑8B‑Instruct: vllm/vllm-openai (model passed as argument)
#   - Foundation‑Sec‑8B‑Instruct‑GGUF: llama.cpp (quantized GGUF model)
# Pass "glm", "gpt", "qwen", "foundation" or "foundation-gguf" as the first argument when you run the script.
MODEL_CHOICE="${1:-foundation-gguf}"  # default to quantized Foundation‑Sec‑8B‑Instruct if no arg supplied
```
*Change `MODEL_CHOICE` when invoking the script:* `./run_on_existing_vm.sh glm` or `./run_on_existing_vm.sh gpt`.

Other adjustable values (feel free to edit the script directly):
- `MODEL_PORT=8000` – HTTP port where the LLM container listens.
- `CHAINSCOPPE_PORT=8001` – Port for ChainScope (optional).

---

## Step‑by‑step walkthrough (line‑by‑line)
| Line range | Description |
|------------|-------------|
| **1‑8** | Shebang (`#!/usr/bin/env bash`) and safety flags `set -euo pipefail` – abort on errors, treat unset variables as errors, propagate failures in pipelines. |
| **11‑23** | **Configuration block** – selects the Docker image based on the user‑provided argument. If an unsupported argument is given, the script exits with an error message. |
| **25‑27** | Define the two TCP ports that will be exposed. |
| **31‑34** | Helper functions `log()` (green `[INFO]`) and `err()` (red `[ERROR]`). Used throughout for consistent, colored messaging. |
| **37‑44** | **Docker installation** – checks if `docker` exists; if not, installs via `yum` and starts the service (`systemctl enable --now docker`). |
| **47‑53** | **Pull the Docker image** – `docker pull "$IMAGE"`. The image is fetched from Docker Hub; you can replace it with a private registry by adding `docker login` before this line. |
| **56‑68** | **Run the LLM container** – removes any previous container named `llm-service` to avoid port collisions, then starts a new detached container (`-d`) named `llm-service`, mapping host port `$MODEL_PORT` to container port `$MODEL_PORT` and passing the port via the `PORT` env var (many images read this env var at start‑up). |
| **71‑79** | **Optional ChainScope** – if `/home/opc/ChainScope` already exists, the script skips the `git clone`; otherwise it clones the public repo. |
| **81‑88** | Starts ChainScope in the background: sets `PORT=$CHAINSCOPPE_PORT`, kills any previously running `mcp.run` process, then runs `./run_mcp.sh` via `nohup` so the process survives after the SSH session ends. |
| **91‑99** | **Health‑check** – attempts a `curl` to `http://127.0.0.1:${MODEL_PORT}/health`. Some images don’t expose `/health`; the script logs a friendly note either way. |
| **101‑108** | Final informational messages, including URLs you should replace `<PUBLIC_IP>` with, and the one‑liner commands to stop the containers later. |

---

## Running the script
```bash
# 1️⃣  Make it executable (once)
chmod +x run_on_existing_vm.sh

# 2️⃣  SSH into your Always‑Free VM (replace with your public IP)
ssh -i ~/.ssh/id_rsa opc@<YOUR_PUBLIC_IP>

# 3️⃣  Transfer the script if you haven’t already (from your workstation)
scp run_on_existing_vm.sh opc@<YOUR_PUBLIC_IP>:/home/opc/

# 4️⃣  Execute on the VM – pick the model you prefer
#    * glm  → GLM‑5.3‑CPU (≈ 5 B params, quantised for CPU)
#    * gpt  → GPT‑OSS‑7B‑CPU (≈ 7 B params, also quantised)
./run_on_existing_vm.sh glm   # or ./run_on_existing_vm.sh gpt
```
The script will output informative `[INFO]` lines as it progresses. Once it finishes, you’ll see the two endpoint URLs printed.

---

## Verification & health‑checks
After the script completes, run the following from **any machine** (your laptop, for example) to confirm the services are reachable:
```bash
# Replace <PUBLIC_IP> with the VM’s public address.
# LLM health endpoint – many images return JSON with version / status.
curl http://<PUBLIC_IP>:8000/health

# ChainScope JSON‑RPC help – a simple POST with empty body returns the method list.
curl -X POST http://<PUBLIC_IP>:8001/ -d '{}' -H "Content-Type: application/json"
```
If you see JSON responses (or at least a `200 OK`), the deployment succeeded.

---

## Stopping / clean‑up
```bash
# Stop the LLM container
docker stop llm-service && docker rm llm-service

# Stop ChainScope (the background Python process)
pkill -f "mcp.run"   # or kill the PID printed by `ps aux | grep run_mcp.sh`
```
If you ever want to delete the VM entirely, use the OCI console or:
```bash
oci compute instance terminate --instance-id <INSTANCE_OCID> --preserve-boot-volume false
```

---

## Optional enhancements & next steps
| Feature | Why it matters | Quick start snippet |
|---------|----------------|--------------------|
| **Load Balancer with DNS** | Gives a friendly domain name and allows you to add more backend VMs later (e.g., a paid GPU VM). | Create an OCI Load Balancer, add this VM as a backend, configure path‑based routing (`/llm/*` → 8000, `/chainscope/*` → 8001). |
| **TLS termination** | Secures traffic (HTTPS). | Enable TLS on the LB, or install **Caddy** on the VM: `sudo yum install -y caddy` and add a simple Caddyfile pointing to 8000/8001. |
| **Persistent storage for ChainScope** | Keeps the `graph.db` across reboots. | Attach a 50 GB block volume, mount it at `/home/opc/ChainScope`, and edit `mcp_server.py` to set `DEFAULT_DB=/mnt/graph/graph.db`. |
| **Monitoring & Logging** | Track request latency, CPU usage, and container logs. | Enable OCI Logging for Docker (`--log-driver=oci`) and expose Prometheus metrics (`-p 9090:9090` if the image supports it). |
| **API‑key protection** | Prevents anyone on the internet from abusing your free VM. | Wrap the LLM container with a tiny Flask auth middleware, or place an OCI API‑Gateway in front with an auth policy. |

---

## FAQ & troubleshooting
| Issue | Likely cause | Fix |
|-------|---------------|-----|
| `docker: command not found` | Docker install failed (perhaps `yum` repo missing). | Run `sudo yum install -y docker` manually, then `sudo systemctl start docker`. |
| Container exits immediately | Using a GPU‑only image on a CPU VM. | Switch to the `*-cpu` tag (see top of this doc). |
| `curl: (7) Connection refused` | Ports 8000/8001 not opened in the VCN security list. | Run the `oci network security-list update` command from the original guide, or open the ports via the console. |
| ChainScope does not start (`pkill -f "mcp.run"` cannot find process) | The repository was not cloned, or `run_mcp.sh` script missing. | Ensure the repo cloned successfully (`/home/opc/ChainScope` exists) and that `run_mcp.sh` is executable (`chmod +x run_mcp.sh`). |

---

## License & attribution
- The script itself is released under the **MIT License** (feel free to modify). 
- ChainScope code is © Immunefi (Apache‑2.0). 
- Model Docker images are provided by their respective authors; check their Docker Hub pages for licensing details.

---

**You are now ready to spin up a CPU‑based LLM on your free OCI VM and optionally run ChainScope side‑by‑side.** If you need any further automation (Terraform, systemd unit files, etc.) just let me know!
