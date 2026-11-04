# mesh-app-4433

## Technical Blueprint

# OpenEdge‑MLQoS – Authoritative System Architecture  

**Autonomous, on‑device ML‑based packet classification for OpenWrt ImmortalWrt MT7981**  
*Data‑plane: XDP + eBPF feature extraction*  
*Control‑plane: Rust **smart‑qosd** daemon (in‑process inference, policy engine)*  
*Policy enforcement: nftables DSCP tagging*  

---

## 1. Design Goals & Success Metrics  

| Goal | Quantitative Success Metric | Acceptance Test |
|------|-----------------------------|-----------------|
| **Zero‑day QoS adaptation** – the router learns new traffic patterns without manual rule updates. | ≥ 95 % classification accuracy on a held‑out test set after 24 h of on‑device incremental learning. | Deploy a synthetic traffic mix, run the learning loop for 24 h, then evaluate on a separate capture (pcap). |
| **Deterministic fast‑path latency** – classification must not add > 5 µs per packet in the XDP hook. | XDP program measured < 5 µs per packet (average, `bpftool perf` on a 10 M‑packet burst). | Run `perf record -e xdp:...` on a 10 M‑packet burst; verify 95‑th percentile ≤ 5 µs. |
| **Low resource footprint** – run comfortably on MT7981 (4 × Cortex‑A53, 1 GiB RAM). | • eBPF bytecode ≤ 8 MiB (including maps)  <br>• Rust daemon RSS ≤ 4 MiB  <br>• Quantised model ≤ 30 MiB (preferably ≤ 8 MiB). | `cat /proc/<pid>/status` after daemon start; `bpftool map show` for map sizes. |
| **OpenWrt‑native deployment** – one‑click install via `opkg`. | `opkg install openedge-mlqos` succeeds, all services start automatically, no manual kernel recompilation. | Fresh OpenWrt image, run the command, verify `systemctl status openedge-mlqos`. |
| **Extensible pipeline** – new features (per‑client policies, additional classifiers) can be added without rebuilding the kernel. | Plug‑in API versioned, CI passes for added Rust crates, eBPF program remains unchanged. | Add a dummy plug‑in, run CI, confirm successful build and runtime load. |

---

## 2. High‑Level Data Flow  

```
+-------------------+      perf ring / BPF map      +-------------------+   netlink   +-------------------+
|  eBPF XDP (kernel) |  <------------------------>  |  Rust smart‑qosd | <---------> |  nftables (DSCP) |
|  (feature extract) |   (zero‑copy, per‑CPU)       |  (in‑process ML) |   API      |  (policy enforcement) |
+-------------------+                               +-------------------+            +-------------------+
        ^                                                    ^                         ^
        |                                                    |                         |
        | 1️⃣  Packet arrives on NIC (RX queue)              | 2️⃣  Classification result (DSCP) |
        |    – XDP runs in interrupt context                |    – sent via perf ring or BPF map   |
        |    – extracts a fixed‑size feature vector (≤ 64 B) |    – looks up/updates per‑flow state |
        |    – writes vector to per‑CPU perf buffer          |    – decides DSCP, QoS class        |
        |    – optionally drops or redirects to AF_XDP      |    – pushes DSCP to nftables rule   |
        |                                                    |    – updates statistics             |
        +----------------------------------------------------+-----------------------------------+
```

* **Step 1 – Fast‑path (kernel):**  
  * XDP program runs on every received packet.  
  * It **never performs inference**; it only extracts a *compact, deterministic feature vector* (e.g., 5‑tuple hash, packet length, L4 protocol, first N bytes of payload).  
  * The vector is written to a **per‑CPU perf ring buffer** (`BPF_MAP_TYPE_PERCPU_ARRAY` + `bpf_perf_event_output`). No locks, zero‑copy, bounded size (max 64 bytes).  

* **Step 2 – Control‑plane (user‑space):**  
  * `smart‑qosd` (Rust) reads the perf ring via `libbpf`’s `perf_buffer_poll`.  
  * The daemon holds a **quantised, on‑device ML model** (e.g., 8‑bit TensorFlow‑Lite or ONNX Runtime).  
  * Inference is performed **per‑flow** (or per‑packet if needed) using the feature vector.  
  * The result is a **DSCP value** (0‑63) and optionally a QoS class identifier.  

* **Step 3 – Policy enforcement (kernel):**  
  * `smart‑qosd` pushes the decision back to the kernel via **netlink** to the **nftables** subsystem.  
  * A **dynamic nftables set** (`set @mlqos { type inet_service; flags interval; }`) holds the mapping *flow‑hash → DSCP*.  
  * An nft rule in the `postrouting` chain reads the DSCP from the set and tags the packet (`ip dscp set <value>`).  
  * Because the set lookup is O(1) and performed in the fast‑path (nftables runs after XDP but before TX), the per‑packet overhead is < 1 µs.  

---

## 3. Component‑Level Architecture  

### 3.1 eBPF XDP Program  

| Item | Details |
|------|---------|
| **Language** | C (compiled with clang‑14, `-O2 -target bpf`). |
| **Verifier‑friendly design** | *No loops* (unrolled at compile time). *No pointer arithmetic* beyond map access. *All memory accesses bounded* (feature vector size fixed). |
| **Maps** | • `struct bpf_map_def perf_ring` – `BPF_MAP_TYPE_PERCPU_ARRAY` (size = 1, used as perf buffer). <br>• `struct bpf_map_def flow_stats` – `BPF_MAP_TYPE_PERCPU_HASH` (key = flow hash, value = counters). |
| **Feature vector** (example, 48 bytes) <br>1. 5‑tuple hash (u32) <br>2. Packet length (u16) <br>3. L4 protocol (u8) <br>4. First 8 bytes of payload (u64) <br>5. Timestamp (u64) – optional for drift detection. |
| **Actions** | • `bpf_perf_event_output` to perf ring. <br>• Increment per‑CPU stats. <br>• Pass (`XDP_PASS`) – packet continues to normal stack. |
| **Safety** | All maps declared with `BPF_MAP_TYPE_PERCPU_ARRAY` to avoid cross‑CPU contention. No helper that can sleep. |

### 3.2 Rust **smart‑qosd** Daemon  

| Sub‑system | Implementation notes |
|------------|----------------------|
| **Perf‑buffer consumer** | Uses `libbpf-rs` (safe wrapper). One thread per‑CPU (or a single poller with `epoll`). |
| **Model loader** | Model stored in `/etc/openedge-mlqos/model.tflite` (or `.onnx`). Loaded at start with **tflite‑rust** or **tract‑onnx** compiled for `armv8-a`. Model is **post‑training quantised to 8‑bit** → ≤ 8 MiB. |
| **Inference engine** | *Stateless* – each feature vector is fed directly; no dynamic memory allocation per inference. Uses a **pre‑allocated tensor buffer** from a `Vec<u8>` pool. |
| **Decision logic** | Output layer is a *softmax* over 64 classes (DSCP values). Arg‑max → DSCP. Optional hysteresis (e.g., only change DSCP if confidence > 0.8). |
| **Policy push** | Netlink socket (`nl::socket::NlSocket`) to the **nftables** kernel API (`NFNL_SUBSYS_NFTABLES`). Updates a **named set** (`mlqos_map`) with `<flow_hash, dscp>`. |
| **State & statistics** | Per‑flow counters stored in an **in‑memory LRU hash