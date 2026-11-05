# Vexon (vexond)

Autonomous, Zero-Dependency Edge AI QoS Engine for OpenWrt / ImmortalWrt (MediaTek MT7981 Filogic 820 & aarch64 architectures).

Vexon implements an intelligent, low-latency traffic classification pipeline without inspecting packet payloads (Zero-DPI). It uses a kernel-space eBPF TC classifier with LRU eviction for telemetry extraction and marking, coupled with a lightweight Rust control-plane daemon (vexond) running pure INT8 saturating MLP inference with fully autonomous zero-touch self-updates.

---

### Key Highlights

- **Zero-Dependency Inference:** No ONNX Runtime or TensorFlow-Lite. Model weights (model.bin) occupy exactly 1308 bytes, eliminating overhead and preserving CPU cycles.

- **LRU Session Tracking:** Kernel data-plane uses BPF_MAP_TYPE_LRU_HASH (65k entries) to automatically evict stale flows during heavy P2P/torrent traffic, preventing table overflow.

- **Kernel & Fwd Friendly:** Packets are tagged strictly in the high-byte of skb->mark (0xFF000000), ensuring zero conflicts with OpenWrt forward rules, NAT, or Multi-WAN routing tables.

- **Deterministic & Memory Safe:** Saturation arithmetic prevents integer overflow crashes. Memory layout is fully aligned and eBPF verifier compliant.

- **Autonomous Self-Updater:** The daemon periodically pulls release metadata, validates payload integrity via SHA256SUMS, and performs atomic in-memory (ArcSwap), kernel (tc filter replace), and binary updates without manual intervention.

---

### Specifications

- **Target Architecture:** ARM64 (aarch64-unknown-linux-musl) / MediaTek MT7981
- **Classification Topology:** MLP 16 -> 32 -> 16 -> 4 (ReLU activation)
- **Model Footprint:** Exactly 1308 bytes
- **Flow Table:** Hardware-backed LRU hash map (65,536 entries)
- **Memory Footprint:** < 4 MB RSS in user-space
- **QoS Classes:** 0: Gaming/Voice (EF) | 1: Streaming (AF41) | 2: Web (CS0) | 3: Bulk (CS1)

---

### Directory Structure

- `.github/workflows/ci.yml` — Cross-compiles musl-static Rust binary, eBPF bytecode, and SHA256 sums
- `bpf/filter.bpf.c` — Kernel TC classifier and telemetry extractor (LRU map)
- `bpf/vmlinux.h` — Architecture-specific BTF definitions
- `rules/mlqos.nft` — nftables mangle table for DSCP tagging
- `src/main.rs` — vexond daemon (sys_bpf listener + INT8 MLP + atomic self-updater)
- `etc/init.d/vexond` — OpenWrt procd service definition (respawn enabled)
- `Cargo.toml` — Rust package & release profile definition

---

### Deployment on OpenWrt / ImmortalWrt

**1. Download Release Artifacts:**  
`mkdir -p /opt/vexon && cd /opt/vexon && for f in vexond filter.bpf.o model.bin mlqos.nft SHA256SUMS; do wget -qO "$f" "https://github.com/kniajevich/vexon/releases/download/latest/$f"; done && chmod +x vexond`

**2. Configure Service & Start:**  
`nft -f /opt/vexon/mlqos.nft && /opt/vexon/vexond &`

**3. Verify Operational Status:**  
`tc -s filter show dev br-lan ingress`  
`logread -e vexond`

---

### License

Licensed under MIT / eBPF kernel program licensed under GPL.
