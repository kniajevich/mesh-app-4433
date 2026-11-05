# Vexon (vexond)

Autonomous, Zero-Dependency Edge AI QoS Engine for OpenWrt / ImmortalWrt (MediaTek MT7981 Filogic 820 & aarch64 architectures).

Vexon implements an intelligent, low-latency traffic classification pipeline without inspecting packet payloads (Zero-DPI). It uses a kernel-space eBPF TC classifier for telemetry extraction and marking, coupled with a lightweight Rust control-plane daemon (vexond) running pure INT8 saturating MLP inference.

---

## Key Highlights

* Zero Dependency Inference: No ONNX Runtime or TensorFlow-Lite. Model weights (model.bin) occupy exactly 1308 bytes, eliminating overhead and preserving CPU cycles.
* Kernel & fw4 Friendly: Packets are tagged strictly in the high-byte of skb->mark (0xFF000000), ensuring zero conflicts with OpenWrt fw4, NAT, or Multi-WAN routing tables.
* Deterministic & Memory Safe: Saturation arithmetic (saturating_mul, saturating_add) prevents integer overflow crashes. eBPF verifier compliant (ihl >= 5 protection).
* Automated MLOps: GitHub Actions handles nightly model retraining and updates. The daemon checks for new weights via CDN-safe cache-busting and updates weights in-memory using ArcSwap without restarting or dropping packets.

---

## Specifications

* Target Architecture: ARM64 (aarch64-unknown-linux-musl) / MediaTek MT7981
* Classification Topology: MLP 16 -> 32 -> 16 -> 4 (ReLU activation)
* Model Footprint: Exactly 1308 bytes
* Flow Hashing: Fibonacci Multiplicative Hashing (0x9E3779B9)
* Memory Footprint: < 4 MB RSS in user-space
* QoS Classes: 0: Gaming/Voice (EF) | 1: Streaming (AF41) | 2: Web (CS0) | 3: Bulk (CS1)

---

## Directory Structure

* .github/workflows/ci.yml — Cross-compiles musl-static Rust binary & eBPF bytecode
* .github/workflows/train.yml — Automated daily retraining and release of model.bin
* ebpf/filter.bpf.c — Kernel TC classifier and telemetry extractor
* ebpf/vmlinux.h — Architecture-specific BTF definitions
* rules/mlqos.nft — nftables mangle table for DSCP tagging
* src/main.rs — vexond daemon (sys_bpf listener + INT8 MLP + hot-reloader)
* train/train.py — Quantized INT8 export pipeline (Deterministic Little-Endian)
* etc/init.d/vexond — OpenWrt procd service definition
* Cargo.toml — Rust package & release profile definition

---

## Deployment on ImmortalWrt / OpenWrt

### 1. Download Release Artifacts

mkdir -p /opt/vexon && cd /opt/vexon
wget -O vexond https://github.com/kniajevich/vexon/releases/download/latest/vexond
wget -O filter.bpf.o https://github.com/kniajevich/vexon/releases/download/latest/filter.bpf.o
wget -O mlqos.nft https://github.com/kniajevich/vexon/releases/download/latest/mlqos.nft
wget -O model.bin https://github.com/kniajevich/vexon/releases/download/latest/model.bin
chmod +x vexond

### 2. Configure Service & Start

cp etc/init.d/vexond /etc/init.d/vexond
chmod +x /etc/init.d/vexond
/etc/init.d/vexond enable
/etc/init.d/vexond start

### 3. Verify Operational Status

ps | grep vexond
logread | grep vexond
tc filter show dev br-lan ingress

---

## License

Licensed under MIT / eBPF kernel program licensed under GPL.
