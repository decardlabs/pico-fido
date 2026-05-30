#!/usr/bin/env python3
"""
Pico FIDO OTA Firmware Signing Tool

Usage:
    python3 tools/sign_firmware.py build/pico_fido.bin build/pico_fido_ota.bin

Generates:
    - build/pico_fido_ota.bin    : Signed firmware for OTA
    - src/fido/ota_pub_key.h       : Public key header (regenerate when key changes)
"""

import sys
import struct
import hashlib
from ecdsa import NIST256p, SigningKey
from ecdsa.util import sigencode_string
from ecdsa.curves import Curve

OTA_MAGIC = 0x4D524946  # "FIRM" little-endian
FW_VERSION = 0x0706     # matches PICO_FIDO_VERSION

def sign_firmware(fw_path, output_path, key_path="tools/ota_key.pem"):
    with open(fw_path, "rb") as f:
        fw_data = f.read()

    with open(key_path, "rb") as f:
        key = SigningKey.from_pem(f.read(), hashfunc=hashlib.sha256)

    # Sign the SHA-256 hash of the firmware
    fw_hash = hashlib.sha256(fw_data).digest()
    signature = key.sign_deterministic(fw_data, hashfunc=hashlib.sha256, sigencode=sigencode_string)

    assert len(signature) == 64, f"Signature length {len(signature)} != 64"

    # Format: [version:4][magic:4][sha256:32][signature:64][firmware_data...]
    with open(output_path, "wb") as f:
        f.write(struct.pack("<I", FW_VERSION))
        f.write(struct.pack("<I", OTA_MAGIC))
        f.write(fw_hash)
        f.write(signature)
        f.write(fw_data)

    pubkey = key.verifying_key
    print(f"Signed firmware: {output_path}")
    print(f"  Firmware size: {len(fw_data)} bytes")
    print(f"  OTA package size: {len(fw_data) + 104} bytes")
    print(f"  Version: {(FW_VERSION >> 8) & 0xff}.{FW_VERSION & 0xff}")
    print(f"  Signature: {signature.hex()[:32]}...")

def generate_pubkey_header(pubkey_path="tools/ota_pub.pem", output="src/fido/ota_pub_key.h"):
    from ecdsa import VerifyingKey
    from ecdsa.curves import NIST256p
    import base64

    with open(pubkey_path, "rb") as f:
        vk = VerifyingKey.from_pem(f.read(), hashfunc=hashlib.sha256)

    pub_bytes = vk.to_string()  # 64 bytes (X || Y) uncompressed
    assert len(pub_bytes) == 64

    header = f"""/*
 * Auto-generated OTA public key header. DO NOT EDIT MANUALLY.
 * Regenerate with: python3 tools/sign_firmware.py build/pico_fido.bin build/pico_fido_ota.bin
 */

#ifndef _OTA_PUB_KEY_H_
#define _OTA_PUB_KEY_H_

#include <stdint.h>

#define OTA_PUB_KEY_SIZE 64

static const uint8_t ota_pub_key[OTA_PUB_KEY_SIZE] = {{
"""
    for i in range(0, 64, 8):
        header += "    "
        header += ", ".join(f"0x{b:02x}" for b in pub_bytes[i:i+8])
        if i + 8 < 64:
            header += ","
        header += "\n"
    header += """};

#endif /* _OTA_PUB_KEY_H_ */
"""
    with open(output, "w") as f:
        f.write(header)
    print(f"Generated: {output}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 tools/sign_firmware.py <input.bin> <output_ota.bin>")
        sys.exit(1)
    sign_firmware(sys.argv[1], sys.argv[2])
    generate_pubkey_header()
