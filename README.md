# Vexon (vexond)

> Autonomous, Zero-Dependency Edge AI QoS Engine for OpenWrt / ImmortalWrt (MediaTek MT7981 Filogic 820 & aarch64 architectures).

Vexon implements an intelligent, low-latency traffic classification pipeline without inspecting packet payloads (Zero-DPI). It uses a kernel-space **eBPF TC classifier** for telemetry extraction and marking, coupled with a lightweight **Rust control-plane daemon (`vexond`)** running pure INT8 saturating MLP inference.

---

## Architecture Overview

