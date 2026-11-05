use std::ffi::CString;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use tokio::time;

pub const MODEL_BIN_SIZE: usize = 1308;
pub const PHI_32: u32 = 0x9E3779B9;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FlowMetrics {
    pub class_id: u8,
    pub classified: u8,
    pub pkt_count: u16,
    pub last_len: u32,
    pub last_time: u64,
}

// BPF_OBJ_GET (7): получение валидного BPF FD из виртуальной FS ядра
unsafe fn bpf_obj_get(path: &str) -> i32 {
    #[repr(C)]
    struct BpfAttrObjGet {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }

    let c_path = match CString::new(path) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    let attr = BpfAttrObjGet {
        pathname: c_path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };

    libc::syscall(libc::SYS_bpf, 7, &attr, std::mem::size_of::<BpfAttrObjGet>()) as i32
}

// BPF_MAP_UPDATE_ELEM (2)
unsafe fn bpf_map_update(fd: i32, key: *const FlowKey, val: *const FlowMetrics) -> i32 {
    #[repr(C)]
    struct BpfAttrUpdate {
        map_fd: u32,
        pad0: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let attr = BpfAttrUpdate {
        map_fd: fd as u32,
        pad0: 0,
        key: key as u64,
        value: val as u64,
        flags: 0,
    };

    libc::syscall(libc::SYS_bpf, 2, &attr, std::mem::size_of::<BpfAttrUpdate>()) as i32
}

// BPF_MAP_GET_NEXT_KEY (4)
unsafe fn bpf_map_get_next_key(fd: i32, key: *const FlowKey, next_key: *mut FlowKey) -> i32 {
    #[repr(C)]
    struct BpfAttrNext {
        map_fd: u32,
        pad0: u32,
        key: u64,
        next_key: u64,
    }

    let attr = BpfAttrNext {
        map_fd: fd as u32,
        pad0: 0,
        key: key as u64,
        next_key: next_key as u64,
    };

    libc::syscall(libc::SYS_bpf, 4, &attr, std::mem::size_of::<BpfAttrNext>()) as i32
}

// BPF_MAP_LOOKUP_ELEM (1)
unsafe fn bpf_map_lookup(fd: i32, key: *const FlowKey, val: *mut FlowMetrics) -> i32 {
    #[repr(C)]
    struct BpfAttrLookup {
        map_fd: u32,
        pad0: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let attr = BpfAttrLookup {
        map_fd: fd as u32,
        pad0: 0,
        key: key as u64,
        value: val as u64,
        flags: 0,
    };

    libc::syscall(libc::SYS_bpf, 1, &attr, std::mem::size_of::<BpfAttrLookup>()) as i32
}

#[derive(Clone, Debug)]
pub struct Int8Mlp {
    pub w1: [[i8; 16]; 32],
    pub b1: [i32; 32],
    pub scale1: f32,

    pub w2: [[i8; 32]; 16],
    pub b2: [i32; 16],
    pub scale2: f32,

    pub w3: [[i8; 16]; 4],
    pub b3: [i32; 4],
    pub scale3: f32,
}

impl Int8Mlp {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != MODEL_BIN_SIZE {
            return Err("Invalid model.bin size: byte count mismatch");
        }

        let mut offset = 0;
        let mut read_w1 = [[0i8; 16]; 32];
        for row in &mut read_w1 {
            for val in row {
                *val = bytes[offset] as i8;
                offset += 1;
            }
        }

        let mut read_b1 = [0i32; 32];
        for val in &mut read_b1 {
            *val = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
        }
        let scale1 = f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let mut read_w2 = [[0i8; 32]; 16];
        for row in &mut read_w2 {
            for val in row {
                *val = bytes[offset] as i8;
                offset += 1;
            }
        }

        let mut read_b2 = [0i32; 16];
        for val in &mut read_b2 {
            *val = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
        }
        let scale2 = f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let mut read_w3 = [[0i8; 16]; 4];
        for row in &mut read_w3 {
            for val in row {
                *val = bytes[offset] as i8;
                offset += 1;
            }
        }

        let mut read_b3 = [0i32; 4];
        for val in &mut read_b3 {
            *val = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
        }
        let scale3 = f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());

        Ok(Self {
            w1: read_w1,
            b1: read_b1,
            scale1,
            w2: read_w2,
            b2: read_b2,
            scale2,
            w3: read_w3,
            b3: read_b3,
            scale3,
        })
    }

    pub fn fallback() -> Self {
        Self {
            w1: [[1i8; 16]; 32],
            b1: [0; 32],
            scale1: 1.0,
            w2: [[1i8; 32]; 16],
            b2: [0; 16],
            scale2: 1.0,
            w3: [[1i8; 16]; 4],
            b3: [0; 4],
            scale3: 1.0,
        }
    }

    #[inline(always)]
    pub fn forward(&self, input: &[i8; 16]) -> [i32; 4] {
        let mut l1_out = [0i8; 32];
        for i in 0..32 {
            let mut acc = self.b1[i];
            for j in 0..16 {
                let prod = (self.w1[i][j] as i32).saturating_mul(input[j] as i32);
                acc = acc.saturating_add(prod);
            }
            let val = acc.max(0);
            l1_out[i] = (val / 128).clamp(0, 127) as i8;
        }

        let mut l2_out = [0i8; 16];
        for i in 0..16 {
            let mut acc = self.b2[i];
            for j in 0..32 {
                let prod = (self.w2[i][j] as i32).saturating_mul(l1_out[j] as i32);
                acc = acc.saturating_add(prod);
            }
            let val = acc.max(0);
            l2_out[i] = (val / 128).clamp(0, 127) as i8;
        }

        let mut l3_out = [0i32; 4];
        for i in 0..4 {
            let mut acc = self.b3[i];
            for j in 0..16 {
                let prod = (self.w3[i][j] as i32).saturating_mul(l2_out[j] as i32);
                acc = acc.saturating_add(prod);
            }
            l3_out[i] = acc;
        }

        l3_out
    }

    #[inline(always)]
    pub fn classify(&self, input: &[i8; 16]) -> u8 {
        let logits = self.forward(input);
        let mut max_idx = 0;
        let mut max_val = logits[0];
        for (i, &val) in logits.iter().enumerate().skip(1) {
            if val > max_val {
                max_val = val;
                max_idx = i;
            }
        }
        max_idx as u8
    }
}

fn start_kernel_classifier(model: Arc<ArcSwap<Int8Mlp>>) {
    tokio::spawn(async move {
        let map_path = "/sys/fs/bpf/tc/globals/flow_table";
        let mut interval = time::interval(Duration::from_millis(100));
        let mut map_fd = -1;

        loop {
            interval.tick().await;

            if map_fd < 0 {
                map_fd = unsafe { bpf_obj_get(map_path) };
                if map_fd < 0 {
                    continue;
                }
                println!("[Data-Plane] eBPF map connected successfully! FD: {}", map_fd);
            }

            let mut prev_key = FlowKey::default();
            let mut next_key = FlowKey::default();

            while unsafe { bpf_map_get_next_key(map_fd, &prev_key, &mut next_key) } == 0 {
                let mut metric = FlowMetrics::default();
                if unsafe { bpf_map_lookup(map_fd, &next_key, &mut metric) } == 0 {
                    if metric.classified == 0 && metric.pkt_count >= 3 {
                        let mut features = [0i8; 16];
                        features[0] = ((metric.last_len as i32 * 127) / 1500).clamp(-128, 127) as i8;
                        features[3] = next_key.protocol as i8;
                        features[11] = (next_key.dst_port % 127) as i8;
                        features[12] = (next_key.src_port % 127) as i8;

                        let class = model.load().classify(&features);
                        metric.class_id = class;
                        metric.classified = 1;

                        unsafe {
                            bpf_map_update(map_fd, &next_key, &metric);
                        }
                    }
                }
                prev_key = next_key;
            }
        }
    });
}

async fn spawn_model_updater(active_model: Arc<ArcSwap<Int8Mlp>>, repo: String) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("vexond-updater")
        .build()
        .unwrap_or_default();

    let mut current_sha = String::new();
    let mut interval = time::interval(Duration::from_secs(12 * 3600));

    tokio::spawn(async move {
        loop {
            interval.tick().await;

            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let sha_url = format!("https://github.com/{}/releases/download/latest/model.sha256?t={}", repo, ts);
            let bin_url = format!("https://github.com/{}/releases/download/latest/model.bin?t={}", repo, ts);

            let sha_resp = match client.get(&sha_url).send().await {
                Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
                _ => continue,
            };

            let remote_sha = sha_resp.split_whitespace().next().unwrap_or("").to_lowercase();
            if remote_sha.is_empty() || remote_sha == current_sha {
                continue;
            }

            let bin_resp = match client.get(&bin_url).send().await {
                Ok(r) if r.status().is_success() => match r.bytes().await {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                _ => continue,
            };

            if bin_resp.len() != MODEL_BIN_SIZE {
                continue;
            }

            let mut hasher = Sha256::new();
            hasher.update(&bin_resp);
            let calculated_sha = format!("{:x}", hasher.finalize());

            if calculated_sha != remote_sha {
                continue;
            }

            if let Ok(new_mlp) = Int8Mlp::from_bytes(&bin_resp) {
                active_model.store(Arc::new(new_mlp));
                current_sha = remote_sha;
                println!("[Model Update] Successfully applied new INT8 weights. SHA: {}", current_sha);
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting vexond autonomous QoS daemon...");

    let initial_model = Arc::new(ArcSwap::from_pointee(Int8Mlp::fallback()));
    
    start_kernel_classifier(initial_model.clone());
    spawn_model_updater(initial_model.clone(), "kniajevich/vexon".to_string()).await;

    println!("vexond engine running. Listening to kernel eBPF map /sys/fs/bpf/tc/globals/flow_table");

    tokio::signal::ctrl_c().await?;
    println!("Shutting down vexond...");
    Ok(())
}
