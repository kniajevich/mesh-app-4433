use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use ringbuf::RingBuffer;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "/etc/openedge-mlqos/config.toml")]
    config: String,

    #[arg(short, long, default_value = "eth0")]
    interface: String,

    #[arg(short, long, default_value = "8192")]
    ringbuf_size: usize,

    #[arg(short, long, default_value = "100")]
    batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    model_path: String,
    nftables_chain: String,
    dscp_map: HashMap<String, u8>,
    learning_rate: f32,
    min_confidence: f32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PacketFeatures {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packet_size: u16,
    pub inter_arrival_time: u32,
    pub flow_id: u64,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Copy)]
struct ClassificationResult {
    pub class_id: u8,
    pub confidence: f32,
    pub flow_id: u64,
}

struct SmartQosd {
    config: Config,
    ringbuf: RingBuffer<PacketFeatures>,
    model: Mutex<SimpleMLModel>,
    nftables: NftablesManager,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
}

#[derive(Debug, Default)]
struct Stats {
    packets_processed: AtomicU64,
    classifications_made: AtomicU64,
    nftables_updates: AtomicU64,
    errors: AtomicU64,
    last_update_time: Mutex<Instant>,
}

struct SimpleMLModel {
    weights: Vec<f32>,
    bias: f32,
    version: u32,
}

impl SimpleMLModel {
    fn new() -> Self {
        Self {
            weights: vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
            bias: 0.0,
            version: 1,
        }
    }

    fn load_from_file(&mut self, path: &str) -> Result<()> {
        let data = fs::read(path).with_context(|| format!("Failed to read model file: {}", path))?;
        // Simplified deserialization for demonstration
        // In production, use a proper serialization format
        if data.len() >= 4 {
            self.version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        }
        info!("Loaded ML model version {} from {}", self.version, path);
        Ok(())
    }

    fn predict(&self, features: &PacketFeatures) -> ClassificationResult {
        let mut score = self.bias;
        let feature_values = [
            (features.src_port as f32) / 65535.0,
            (features.dst_port as f32) / 65535.0,
            (features.protocol as f32) / 255.0,
            (features.packet_size as f32) / 65535.0,
            (features.inter_arrival_time as f32) / 1_000_000.0,
            ((features.src_ip & 0xFF) as f32) / 255.0,
            ((features.dst_ip & 0xFF) as f32) / 255.0,
            1.0,
        ];

        for (i, &val) in feature_values.iter().enumerate() {
            if i < self.weights.len() {
                score += self.weights[i] * val;
            }
        }

        // Simple sigmoid activation
        let confidence = 1.0 / (1.0 + (-score).exp());
        let class_id = if confidence > 0.5 { 1 } else { 0 };

        ClassificationResult {
            class_id,
            confidence: confidence as f32,
            flow_id: features.flow_id,
        }
    }

    fn update(&mut self, features: &PacketFeatures, label: u8) {
        let prediction = self.predict(features);
        let error = (label as f32) - prediction.confidence;
        
        let feature_values = [
            (features.src_port as f32) / 65535.0,
            (features.dst_port as f32) / 65535.0,
            (features.protocol as f32) / 255.0,
            (features.packet_size as f32) / 65535.0,
            (features.inter_arrival_time as f32) / 1_000_000.0,
            ((features.src_ip & 0xFF) as f32) / 255.0,
            ((features.dst_ip & 0xFF) as f32) / 255.0,
            1.0,
        ];

        let lr = 0.01;
        for (i, &val) in feature_values.iter().enumerate() {
            if i < self.weights.len() {
                self.weights[i] += lr * error * val;
            }
        }
        self.bias += lr * error;
    }
}

struct NftablesManager {
    chain_name: String,
    dscp_map: HashMap<String, u8>,
}

impl NftablesManager {
    fn new(chain_name: String, dscp_map: HashMap<String, u8>) -> Self {
        Self {
            chain_name,
            dscp_map,
        }
    }

    fn apply_dscp_tag(&self, flow_id: u64, class_id: u8) -> Result<()> {
        let dscp_value = self.dscp_map.get(&class_id.to_string())
            .copied()
            .unwrap_or(0);
        
        let dscp_hex = format!("{:02x}", dscp_value);
        
        // Use nftables command to add/update rule
        let cmd = format!(
            "nft add rule inet filter {} meta mark 0x{:08x} dscp set {}",
            self.chain_name,
            flow_id as u32,
            dscp_hex
        );
        
        debug!("Applying DSCP tag: {}", cmd);
        
        let output = Command::new("nft")
            .args(cmd.split_whitespace())
            .output()
            .context("Failed to execute nft command")?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("nft command failed: {}", stderr));
        }
        
        Ok(())
    }

    fn flush_rules(&self) -> Result<()> {
        let cmd = format!("nft flush chain inet filter {}", self.chain_name);
        let output = Command::new("nft")
            .args(cmd.split_whitespace())
            .output()
            .context("Failed to execute nft flush command")?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("nft flush failed: {}", stderr));
        }
        
        Ok(())
    }
}

impl SmartQosd {
    fn new(config: Config, ringbuf: RingBuffer<PacketFeatures>) -> Result<Self> {
        let model = Mutex::new(SimpleMLModel::new());
        let nftables = NftablesManager::new(
            config.nftables_chain.clone(),
            config.dscp_map.clone(),
        );
        
        Ok(Self {
            config,
            ringbuf,
            model,
            nftables,
            running: Arc::new(AtomicBool::new(true)),
            stats: Arc::new(Stats::default()),
        })
    }

    fn setup_signal_handlers(&self) -> Result<()> {
        // Install SIGHUP handler for config reload
        let running = Arc::clone(&self.running);
        
        signal::signal(Signal::SIGHUP, move |_| {
            info!("Received SIGHUP, reloading configuration...");
            // In production, this would trigger a config reload
            // For now, just log it
        })?;
        
        signal::signal(Signal::SIGTERM, move |_| {
            info!("Received SIGTERM, shutting down...");
            running.store(false, Ordering::SeqCst);
        })?;
        
        signal::signal(Signal::SIGINT, move |_| {
            info!("Received SIGINT, shutting down...");
            running.store(false, Ordering::SeqCst);
        })?;
        
        Ok(())
    }

    fn process_batch(&mut self, batch: Vec<PacketFeatures>) -> Result<()> {
        let mut classifications = Vec::with_capacity(batch.len());
        
        for features in &batch {
            let model = self.model.lock().unwrap();
            let result = model.predict(features);
            classifications.push((features.clone(), result));
        }
        
        for (features, result) in &classifications {
            if result.confidence >= self.config.min_confidence {
                if let Err(e) = self.nftables.apply_dscp_tag(result.flow_id, result.class_id) {
                    warn!("Failed to apply DSCP tag for flow {}: {}", result.flow_id, e);
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.nftables_updates.fetch_add(1, Ordering::Relaxed);
                }
            }
            
            // Update model with new data (online learning)
            let mut model = self.model.lock().unwrap();
            model.update(features, result.class_id);
        }
        
        self.stats.packets_processed.fetch_add(batch.len() as u64, Ordering::Relaxed);
        self.stats.classifications_made.fetch_add(batch.len() as u64, Ordering::Relaxed);
        
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        info!("Starting smart-qosd daemon");
        
        self.setup_signal_handlers()?;
        
        let mut batch = Vec::with_capacity(self.config.min_confidence as usize * 100);
        let mut last_stats_update = Instant::now();
        
        while self.running.load(Ordering::SeqCst) {
            // Read from ring buffer
            match self.ringbuf.read() {
                Ok(Some(features)) => {
                    batch.push(features);
                    
                    if batch.len() >= 100 {
                        if let Err(e) = self.process_batch(std::mem::take(&mut batch)) {
                            error!("Failed to process batch: {}", e);
                            self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Ok(None) => {
                    // No data available, sleep briefly
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    error!("Error reading from ring buffer: {}", e);
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(10));
                }
            }
            
            // Periodic stats logging
            if last_stats_update.elapsed() > Duration::from_secs(10) {
                let stats = &self.stats;
                info!(
                    "Stats: packets={}, classifications={}, nft_updates={}, errors={}",
                    stats.packets_processed.load(Ordering::Relaxed),
                    stats.classifications_made.load(Ordering::Relaxed),
                    stats.nftables_updates.load(Ordering::Relaxed),
                    stats.errors.load(Ordering::Relaxed)
                );
                last_stats_update = Instant::now();
            }
        }
        
        // Process remaining batch
        if !batch.is_empty() {
            if let Err(e) = self.process_batch(batch) {
                error!("Failed to process final batch: {}", e);
            }
        }
        
        info!("smart-qosd daemon stopped");
        Ok(())
    }
}

fn load_config(path: &str) -> Result<Config> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path))?;
    
    let config: Config = toml::from_str(&content)
        .with_context(|| "Failed to parse TOML config")?;
    
    info!("Loaded configuration from {}", path);
    Ok(config)
}

fn create_ringbuf(interface: &str, size: usize) -> Result<RingBuffer<PacketFeatures>> {
    // In production, this would create a BPF ring buffer
    // For demonstration, we use a mock implementation
    info!("Creating ring buffer for interface {} with