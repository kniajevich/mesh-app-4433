use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use tokio::time;

pub const MODEL_BIN_SIZE: usize = 1308;

// Константа Золотого Сечения (Golden Ratio) ядра Linux для 32-битного Фибоначчиева хэширования
pub const PHI_32: u32 = 0x9E3779B9;

/// Фибоначчиево хэширование 5-tuple сетевого соединения в 1 такт CPU
#[inline(always)]
pub fn fibonacci_flow_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> usize {
    let ports = ((src_port as u32) << 16) | (dst_port as u32);
    let mut h = src_ip.wrapping_mul(PHI_32);
    h = (h ^ dst_ip).wrapping_mul(PHI_32);
    h = (h ^ ports).wrapping_mul(PHI_32);
    h = (h ^ (proto as u32)).wrapping_mul(PHI_32);
    (h >> 22) as usize
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

    /// Инференс с защитой от переполнения через насыщающую арифметику (saturating)
    #[inline(always)]
    pub fn forward(&self, input: &[i8; 16]) -> [i32; 4] {
        // Слой 1: 16 -> 32 (ReLU)
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

        // Слой 2: 32 -> 16 (ReLU)
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

        // Слой 3: 16 -> 4 (Линейные логиты)
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
                eprintln!("[Model Update] Size mismatch: got {}, expected {}", bin_resp.len(), MODEL_BIN_SIZE);
                continue;
            }

            let mut hasher = Sha256::new();
            hasher.update(&bin_resp);
            let calculated_sha = format!("{:x}", hasher.finalize());

            if calculated_sha != remote_sha {
                eprintln!("[Model Update] SHA256 mismatch: calculated {}, expected {}", calculated_sha, remote_sha);
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
    println!("Starting vexond with INT8 MLP classification engine...");

    let initial_model = Arc::new(ArcSwap::from_pointee(Int8Mlp::fallback()));
    // Привязка к переименованному репозиторию kniajevich/vexon
    spawn_model_updater(initial_model.clone(), "kniajevich/vexon".to_string()).await;

    let sample_bucket = fibonacci_flow_hash(0xC0A80101, 0x08080808, 4433, 443, 6);
    println!("Fibonacci Hash Engine initialized. Sample bucket: {}", sample_bucket);

    let sample_features: [i8; 16] = [40, 6, 2, 0, 15, 3, 12, 8, 0, 1, 4, 10, 0, 0, 5, 2];
    let class_id = initial_model.load().classify(&sample_features);
    println!("Engine booted. Self-test prediction: Class {}", class_id);

    tokio::signal::ctrl_c().await?;
    println!("Shutting down vexond...");
    Ok(())
}
