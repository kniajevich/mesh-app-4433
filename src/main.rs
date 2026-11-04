use std::sync::Arc;
use std::time::Duration;
use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use tokio::time;

// ============================================================================
// 1. MLP INT8 Pure Rust Engine (Топология: 16 -> 32 -> 16 -> 4)
// ============================================================================
// Точный размер бинарника в байтах:
// W1: 32 * 16 = 512
// B1: 32 * 4  = 128
// Scale1: 4
// W2: 16 * 32 = 512
// B2: 16 * 4  = 64
// Scale2: 4
// W3: 4 * 16  = 64
// B3: 4 * 4   = 16
// Scale3: 4
// Итого: 512 + 128 + 4 + 512 + 64 + 4 + 64 + 16 + 4 = 1308 байт
pub const MODEL_BIN_SIZE: usize = 1308;

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
    /// Загрузка весов из плоского бинарного буфера
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

    /// Безопасные дефолтные веса для холодного старта без сети
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

    /// Zero-allocation прямой проход: 16 признаков -> 4 логита классов QoS
    #[inline(always)]
    pub fn forward(&self, input: &[i8; 16]) -> [i32; 4] {
        // Слой 1: 16 -> 32 с активацией ReLU
        let mut l1_out = [0i8; 32];
        for i in 0..32 {
            let mut acc = self.b1[i];
            for j in 0..16 {
                acc += (self.w1[i][j] as i32) * (input[j] as i32);
            }
            // ReLU + реквантование в i8
            let val = acc.max(0);
            l1_out[i] = (val / 128).clamp(0, 127) as i8;
        }

        // Слой 2: 32 -> 16 с активацией ReLU
        let mut l2_out = [0i8; 16];
        for i in 0..16 {
            let mut acc = self.b2[i];
            for j in 0..32 {
                acc += (self.w2[i][j] as i32) * (l1_out[j] as i32);
            }
            let val = acc.max(0);
            l2_out[i] = (val / 128).clamp(0, 127) as i8;
        }

        // Слой 3: 16 -> 4 (Линейные выходные логиты без ReLU)
        let mut l3_out = [0i32; 4];
        for i in 0..4 {
            let mut acc = self.b3[i];
            for j in 0..16 {
                acc += (self.w3[i][j] as i32) * (l2_out[j] as i32);
            }
            l3_out[i] = acc;
        }

        l3_out
    }

    /// Возвращает индекс класса с наивысшим приоритетом:
    /// 0: Gaming / EF
    /// 1: Streaming / AF41
    /// 2: Web / Best Effort
    /// 3: Bulk / CS1
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

// ============================================================================
// 2. Фоновый сервис безопасного обновления весов
// ============================================================================
async fn spawn_model_updater(active_model: Arc<ArcSwap<Int8Mlp>>, repo: String) {
    let sha_url = format!("https://github.com/{}/releases/download/latest/model.sha256", repo);
    let bin_url = format!("https://github.com/{}/releases/download/latest/model.bin", repo);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("smart-qosd-updater")
        .build()
        .unwrap_or_default();

    let mut current_sha = String::new();
    let mut interval = time::interval(Duration::from_secs(12 * 3600));

    tokio::spawn(async move {
        loop {
            interval.tick().await;

            // 1. Проверяем контрольную сумму
            let sha_resp = match client.get(&sha_url).send().await {
                Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
                _ => continue,
            };

            let remote_sha = sha_resp.split_whitespace().next().unwrap_or("").to_lowercase();
            if remote_sha.is_empty() || remote_sha == current_sha {
                continue;
            }

            // 2. Скачиваем бинарник весов
            let bin_resp = match client.get(&bin_url).send().await {
                Ok(r) if r.status().is_success() => match r.bytes().await {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                _ => continue,
            };

            // 3. Строгая валидация размера (ровно 1308 байт)
            if bin_resp.len() != MODEL_BIN_SIZE {
                eprintln!("[Model Update] Rejected: size mismatch (got {}, expected {})", bin_resp.len(), MODEL_BIN_SIZE);
                continue;
            }

            // 4. Проверка SHA256
            let mut hasher = Sha256::new();
            hasher.update(&bin_resp);
            let calculated_sha = format!("{:x}", hasher.finalize());

            if calculated_sha != remote_sha {
                eprintln!("[Model Update] Rejected: SHA256 checksum mismatch");
                continue;
            }

            // 5. Парсинг и атомарная подмена указателя в памяти
            if let Ok(new_mlp) = Int8Mlp::from_bytes(&bin_resp) {
                active_model.store(Arc::new(new_mlp));
                current_sha = remote_sha;
                println!("[Model Update] Successfully applied new INT8 weights (SHA: {})", current_sha);
            }
        }
    });
}

// ============================================================================
// 3. Точка входа демона
// ============================================================================
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting smart-qosd with INT8 MLP classification engine...");

    // Инициализация fallback-модели в памяти
    let initial_model = Arc::new(ArcSwap::from_pointee(Int8Mlp::fallback()));

    // Запуск фонового автообновления
    spawn_model_updater(initial_model.clone(), "kniajevich/mesh-app-4433".to_string()).await;

    // Демонстрационный проверочный прогон
    let sample_features: [i8; 16] = [40, 6, 2, 0, 15, 3, 12, 8, 0, 1, 4, 10, 0, 0, 5, 2];
    let class_id = initial_model.load().classify(&sample_features);
    println!("Engine booted. Test classification verdict: class {}", class_id);

    // Главный цикл обработки событий eBPF
    tokio::signal::ctrl_c().await?;
    println!("Shutting down smart-qosd...");
    Ok(())
}
