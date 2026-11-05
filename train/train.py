#!/usr/bin/env python3
"""
Vexon Training Pipeline:
1. Синтез/парсинг сетевых фичей на базе профилей реального трафика (CIC/ISCX/Game UDP).
2. Обучение MLP (16 -> 32 -> 16 -> 4) в PyTorch (Adam, CrossEntropyLoss).
3. Пост-тренировочное симметричное квантование в INT8 (scale + clamp).
4. Экспорт в детерминированный бинарник model.bin ровно на 1308 байт (<i1, <i4).
"""
import struct
import hashlib
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

MODEL_SIZE_EXPECTED = 1308

# 1. Генератор профилей сетевого трафика (16 фичей)
def generate_traffic_dataset(samples_per_class=12000):
    np.random.seed(42)
    torch.manual_seed(42)

    X = []
    y = []

    # Класс 0: Real-Time / Gaming & Voice (Fortnite, CS2, Discord UDP)
    # Признаки: короткие UDP пакеты (50-160B), высокий темп, низкий джиттер IAT
    for _ in range(samples_per_class):
        f = np.zeros(16, dtype=np.float32)
        f[0] = np.random.normal(90, 25)           # Средний размер пакета (байты)
        f[1] = np.random.normal(15, 5)            # IAT среднее (мс) ~ 60-128 Гц
        f[2] = np.random.exponential(3)           # Джиттер (минимальный)
        f[3] = 17.0                               # Протокол UDP (17)
        f[4] = np.random.choice([7000, 27015, 9000, 5060, 443]) # Порты
        f[5] = np.random.normal(64, 10)           # Минимальный размер пакета
        f[6] = np.random.normal(140, 30)          # Максимальный размер пакета
        f[7] = np.random.normal(8, 2)             # Число пакетов в бурсте
        f[8] = 0.95                               # Асимметрия трафика (симметричный duplex)
        f[9] = np.random.normal(20, 5)            # Размер payload
        f[10] = 0.0                               # TCP flags (none)
        f[11] = f[4] % 127
        f[12] = np.random.randint(1024, 65535) % 127
        f[13] = np.random.normal(1.2, 0.4)        # Энтропия
        f[14] = np.random.normal(12, 3)           # Частота тиков
        f[15] = 0.0                               # Ретрансмиты (минимальные)
        X.append(f)
        y.append(0)

    # Класс 1: Streaming / Media (YouTube, Twitch, Video)
    # Признаки: длинные TCP/UDP burst, размеры MTU ~1400-1500B, периодические паузы
    for _ in range(samples_per_class):
        f = np.zeros(16, dtype=np.float32)
        f[0] = np.random.normal(1350, 120)        # Крупные пакеты
        f[1] = np.random.normal(45, 20)           # IAT пульсирующий
        f[2] = np.random.normal(25, 10)
        f[3] = np.random.choice([6.0, 17.0])      # TCP / QUIC
        f[4] = 443.0                              # HTTPS / QUIC
        f[5] = np.random.normal(80, 40)
        f[6] = 1500.0
        f[7] = np.random.normal(60, 15)           # Длинные очереди пакетов
        f[8] = 0.15                               # Сильная асимметрия (Download > Upload)
        f[9] = np.random.normal(1300, 100)
        f[10] = 16.0                              # ACK
        f[11] = 443 % 127
        f[12] = np.random.randint(1024, 65535) % 127
        f[13] = np.random.normal(3.8, 0.5)
        f[14] = np.random.normal(5, 2)
        f[15] = np.random.exponential(1.5)
        X.append(f)
        y.append(1)

    # Класс 2: Interactive Web / Browsing (HTTP, API, DNS)
    # Признаки: умеренные burst-пакеты, частый SYN/FIN, смешанные размеры
    for _ in range(samples_per_class):
        f = np.zeros(16, dtype=np.float32)
        f[0] = np.random.normal(550, 200)
        f[1] = np.random.exponential(150)         # Большие паузы между кликами
        f[2] = np.random.normal(60, 25)
        f[3] = np.random.choice([6.0, 17.0])
        f[4] = np.random.choice([80, 443, 53, 8080])
        f[5] = 40.0
        f[6] = np.random.normal(1200, 250)
        f[7] = np.random.normal(15, 6)
        f[8] = 0.45
        f[9] = np.random.normal(400, 150)
        f[10] = 24.0                             # PSH, ACK
        f[11] = f[4] % 127
        f[12] = np.random.randint(1024, 65535) % 127
        f[13] = np.random.normal(2.5, 0.8)
        f[14] = np.random.normal(2, 1)
        f[15] = np.random.exponential(0.8)
        X.append(f)
        y.append(2)

    # Класс 3: Bulk / Background Downloads / Torrents
    # Признаки: максимальное заполнение канала, постоянные MTU 1500B, симметрия в P2P
    for _ in range(samples_per_class):
        f = np.zeros(16, dtype=np.float32)
        f[0] = np.random.normal(1460, 40)
        f[1] = np.random.normal(1.2, 0.5)         # Пакеты идут сплошным потоком
        f[2] = np.random.normal(10, 5)
        f[3] = np.random.choice([6.0, 17.0])
        f[4] = np.random.randint(10000, 60000)
        f[5] = 1200.0
        f[6] = 1514.0
        f[7] = np.random.normal(120, 25)          # Огромные burst
        f[8] = 0.3
        f[9] = 1420.0
        f[10] = 16.0
        f[11] = f[4] % 127
        f[12] = np.random.randint(1024, 65535) % 127
        f[13] = np.random.normal(4.5, 0.3)        # Максимальная зашифрованная энтропия
        f[14] = np.random.normal(80, 20)
        f[15] = np.random.exponential(3.0)
        X.append(f)
        y.append(3)

    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int64)

    # Нормализация в диапазон [-128, 127] для входа INT8
    mean = np.mean(X, axis=0)
    std = np.std(X, axis=0) + 1e-6
    X_norm = np.clip(((X - mean) / std) * 32.0, -128.0, 127.0)

    indices = np.arange(len(X_norm))
    np.random.shuffle(indices)
    return torch.tensor(X_norm[indices], dtype=torch.float32), torch.tensor(y[indices], dtype=torch.long)

# 2. Модель MLP 16 -> 32 -> 16 -> 4
class VexonMLP(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(16, 32)
        self.relu1 = nn.ReLU()
        self.fc2 = nn.Linear(32, 16)
        self.relu2 = nn.ReLU()
        self.fc3 = nn.Linear(16, 4)

    def forward(self, x):
        x = self.relu1(self.fc1(x))
        x = self.relu2(self.fc2(x))
        x = self.fc3(x)
        return x

def quantize_to_int8(tensor):
    max_val = torch.max(torch.abs(tensor)).item()
    if max_val == 0.0:
        return torch.zeros_like(tensor, dtype=torch.int8), 1.0
    scale = 127.0 / max_val
    quantized = torch.clamp(torch.round(tensor * scale), -128, 127).to(torch.int8)
    return quantized, float(1.0 / scale)

def quantize_bias_to_int32(bias_tensor, weight_scale, input_scale=1.0):
    scale = 1.0 / (weight_scale * input_scale)
    quantized = torch.clamp(torch.round(bias_tensor * scale), -2147483648, 2147483647).to(torch.int32)
    return quantized

def train_and_export():
    print("[1/4] Preparing traffic datasets (Gaming, Video, Web, Bulk)...")
    X, y = generate_traffic_dataset(samples_per_class=10000)

    split = int(0.85 * len(X))
    X_train, X_val = X[:split], X[split:]
    y_train, y_val = y[:split], y[split:]

    model = VexonMLP()
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.005, weight_decay=1e-4)

    print("[2/4] Training MLP model for high accuracy...")
    batch_size = 256
    dataset = torch.utils.data.TensorDataset(X_train, y_train)
    loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

    model.train()
    for epoch in range(12):
        total_loss = 0.0
        for b_x, b_y in loader:
            optimizer.zero_grad()
            out = model(b_x)
            loss = criterion(out, b_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

    model.eval()
    with torch.no_grad():
        val_preds = model(X_val).argmax(dim=1)
        acc = (val_preds == y_val).float().mean().item() * 100.0
        print(f"Validation Accuracy: {acc:.2f}%")

    print("[3/4] Quantizing model weights to INT8/INT32 (Symmetric)...")
    # Слой 1
    w1_q, scale1 = quantize_to_int8(model.fc1.weight.data)
    b1_q = quantize_bias_to_int32(model.fc1.bias.data, scale1)

    # Слой 2
    w2_q, scale2 = quantize_to_int8(model.fc2.weight.data)
    b2_q = quantize_bias_to_int32(model.fc2.bias.data, scale2)

    # Слой 3
    w3_q, scale3 = quantize_to_int8(model.fc3.weight.data)
    b3_q = quantize_bias_to_int32(model.fc3.bias.data, scale3)

    print("[4/4] Packing binary format (Little-Endian, exactly 1308 bytes)...")
    blob = bytearray()

    # Слой 1: W1 (32x16 = 512B) + B1 (32x4 = 128B) + scale (4B) = 644B
    blob.extend(w1_q.numpy().astype('<i1').tobytes())
    blob.extend(b1_q.numpy().astype('<i4').tobytes())
    blob.extend(struct.pack('<f', scale1))

    # Слой 2: W2 (16x32 = 512B) + B2 (16x4 = 64B) + scale (4B) = 580B
    blob.extend(w2_q.numpy().astype('<i1').tobytes())
    blob.extend(b2_q.numpy().astype('<i4').tobytes())
    blob.extend(struct.pack('<f', scale2))

    # Слой 3: W3 (4x16 = 64B) + B3 (4x4 = 16B) + scale (4B) = 84B
    blob.extend(w3_q.numpy().astype('<i1').tobytes())
    blob.extend(b3_q.numpy().astype('<i4').tobytes())
    blob.extend(struct.pack('<f', scale3))

    assert len(blob) == MODEL_SIZE_EXPECTED, f"Mismatch: got {len(blob)}, expected {MODEL_SIZE_EXPECTED}"

    with open("model.bin", "wb") as f:
        f.write(blob)

    sha256 = hashlib.sha256(blob).hexdigest()
    with open("model.sha256", "w") as f:
        f.write(f"{sha256}  model.bin\n")

    print(f"[SUCCESS] model.bin ({len(blob)} B) generated! SHA256: {sha256}")

if __name__ == "__main__":
    train_and_export()
