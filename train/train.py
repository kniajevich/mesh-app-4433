#!/usr/bin/env python3
"""
Экспорт параметров модели INT8 в бинарный файл model.bin.
Топология MLP: 16 -> 32 -> 16 -> 4.
Строгий размер файла: 1308 байт (Little-Endian).
"""
import struct
import hashlib
import numpy as np

def export_model():
    np.random.seed(42)

    # Принудительная сериализация в Little-Endian (<i1, <i4)
    w1 = np.random.randint(-20, 20, size=(32, 16)).astype('<i1')
    b1 = np.random.randint(-100, 100, size=32).astype('<i4')
    scale1 = 1.0

    w2 = np.random.randint(-20, 20, size=(16, 32)).astype('<i1')
    b2 = np.random.randint(-100, 100, size=16).astype('<i4')
    scale2 = 1.0

    w3 = np.random.randint(-20, 20, size=(4, 16)).astype('<i1')
    b3 = np.random.randint(-100, 100, size=4).astype('<i4')
    scale3 = 1.0

    blob = bytearray()

    # Слой 1: 32x16 (512B) + 32x4 (128B) + scale (4B) = 644B
    blob.extend(w1.tobytes())
    blob.extend(b1.tobytes())
    blob.extend(struct.pack('<f', scale1))

    # Слой 2: 16x32 (512B) + 16x4 (64B) + scale (4B) = 580B
    blob.extend(w2.tobytes())
    blob.extend(b2.tobytes())
    blob.extend(struct.pack('<f', scale2))

    # Слой 3: 4x16 (64B) + 4x4 (16B) + scale (4B) = 84B
    blob.extend(w3.tobytes())
    blob.extend(b3.tobytes())
    blob.extend(struct.pack('<f', scale3))

    assert len(blob) == 1308, f"Wrong binary size: {len(blob)} bytes (expected 1308)"

    with open("model.bin", "wb") as f:
        f.write(blob)

    sha256 = hashlib.sha256(blob).hexdigest()
    with open("model.sha256", "w") as f:
        f.write(f"{sha256}  model.bin\n")

    print(f"[OK] Generated model.bin ({len(blob)} bytes) | SHA256: {sha256}")

if __name__ == "__main__":
    export_model()
