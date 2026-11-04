#!/usr/bin/env python3
import struct
import hashlib
import numpy as np

# Топология: 16 -> 32 -> 16 -> 4
# Формат model.bin (ровно 1308 байт):
# W1: 32x16 = 512B
# B1: 32x4  = 128B
# Scale1:     4B
# W2: 16x32 = 512B
# B2: 16x4  = 64B
# Scale2:     4B
# W3: 4x16  = 64B
# B3: 4x4   = 16B
# Scale3:     4B
# Сумма = 1308B

def export_model():
    np.random.seed(42)

    # Веса в диапазоне INT8 [-127, 127]
    w1 = np.random.randint(-20, 20, size=(32, 16), dtype=np.int8)
    b1 = np.random.randint(-100, 100, size=32, dtype=np.int32)
    scale1 = 1.0

    w2 = np.random.randint(-20, 20, size=(16, 32), dtype=np.int8)
    b2 = np.random.randint(-100, 100, size=16, dtype=np.int32)
    scale2 = 1.0

    w3 = np.random.randint(-20, 20, size=(4, 16), dtype=np.int8)
    b3 = np.random.randint(-100, 100, size=4, dtype=np.int32)
    scale3 = 1.0

    blob = bytearray()

    # Слой 1
    blob.extend(w1.tobytes())
    blob.extend(b1.tobytes())
    blob.extend(struct.pack('<f', scale1))

    # Слой 2
    blob.extend(w2.tobytes())
    blob.extend(b2.tobytes())
    blob.extend(struct.pack('<f', scale2))

    # Слой 3
    blob.extend(w3.tobytes())
    blob.extend(b3.tobytes())
    blob.extend(struct.pack('<f', scale3))

    assert len(blob) == 1308, f"Wrong size: {len(blob)}"

    with open("model.bin", "wb") as f:
        f.write(blob)

    sha256 = hashlib.sha256(blob).hexdigest()
    with open("model.sha256", "w") as f:
        f.write(f"{sha256}  model.bin\n")

    print(f"Generated model.bin ({len(blob)} bytes), SHA256: {sha256}")

if __name__ == "__main__":
    export_model()
