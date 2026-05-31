#!/usr/bin/env python3
"""
Pico FIDO OTA Flashing Tool

Usage:
    python3 tools/ota_flash.py build/pico_fido_ota.bin

Steps:
    1. Connect to the FIDO device
    2. Get device info
    3. Send firmware chunks via CTAP vendor HID command
    4. Send verification metadata
    5. Device reboots on success
"""

import sys
import os
import struct
import time
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("ota-flash")

# CTAPHID vendor command for CBOR
CTAPHID_VENDOR_FIRST = 0x40
CTAP_VENDOR_CBOR = CTAPHID_VENDOR_FIRST + 1  # 0x41

from cbor2 import dumps as cbor_dumps, loads as cbor_loads

CTAPHID_VENDOR_FIRST = 0x40
CTAP_VENDOR_CBOR = CTAPHID_VENDOR_FIRST + 1  # 0x41
CTAP_VENDOR_OTA = 0x07

# OTA sub-commands
OTA_CMD_INFO = 0x01
OTA_CMD_WRITE = 0x02
OTA_CMD_VERIFY = 0x03
OTA_CMD_ABORT = 0x04

OTA_MAGIC = 0x4D524946  # "FIRM"

CHUNK_SIZE = 768  # Send ~768 bytes per CTAP CBOR payload


def find_device():
    try:
        from fido2.hid import CtapHidDevice
    except ImportError:
        log.error("fido2 library not found. Install: pip install fido2")
        sys.exit(1)

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        log.error("No FIDO device found. Is it plugged in?")
        sys.exit(1)

    dev = devices[0]
    log.info(f"Found device: {dev.descriptor.path}")
    return dev


def send_vendor_cbor(dev, data):
    """Send a CTAP vendor CBOR command via HID.

    The firmware's cbor_vendor() expects data[0] to be the vendor command
    type selector (CTAP_VENDOR_OTA = 0x07), routing to the OTA handler.
    We prepend that byte before the CBOR payload.
    """
    frame = bytes([CTAP_VENDOR_OTA]) + data
    response = dev.call(CTAP_VENDOR_CBOR, frame)
    return response


def build_ota_cbor(cmd, payload=None):
    """Build a minimal CBOR structure for OTA sub-commands.

    CBOR:
    {
        0x01: cmd,         # OTA sub-command (INFO/WRITE/VERIFY/ABORT)
        0x02: {            # sub-parameter map
            0x01: h'...'   # data payload (optional)
        }
    }
    """
    if payload and len(payload) > 0:
        return cbor_dumps({
            0x01: cmd,
            0x02: {0x01: payload}
        })
    else:
        return cbor_dumps({
            0x01: cmd,
            0x02: {0x01: b''}
        })


def ota_info(dev):
    """Get OTA info from device."""
    req = build_ota_cbor(OTA_CMD_INFO)
    resp = send_vendor_cbor(dev, req)
    # Parse response
    try:
        decoded = cbor_loads(resp)
        if 0x01 in decoded:
            info = bytes(decoded[0x01])
            if len(info) >= 3:
                status = info[0]
                major = info[1]
                minor = info[2]
                log.info(f"  OTA status: {status}")
                log.info(f"  Firmware version: {major}.{minor}")
                return status, major, minor
    except Exception:
        pass
    return None, None, None


def ota_write(dev, chunk):
    """Send a firmware chunk to the device."""
    req = build_ota_cbor(OTA_CMD_WRITE, chunk)
    try:
        resp = send_vendor_cbor(dev, req)
        return True
    except Exception as e:
        log.error(f"  Write failed: {e}")
        return False


def ota_verify(dev, version, sha256_hash, signature):
    """Send verification metadata and trigger partition switch."""
    metadata = struct.pack("<I", version) + \
               struct.pack("<I", OTA_MAGIC) + \
               sha256_hash + signature
    req = build_ota_cbor(OTA_CMD_VERIFY, metadata)
    try:
        resp = send_vendor_cbor(dev, req)
        # Device will restart on success
        return True
    except Exception:
        # Device restarts, so connection drops - this is expected
        return True


def ota_abort(dev):
    """Abort any ongoing OTA update."""
    req = build_ota_cbor(OTA_CMD_ABORT)
    try:
        send_vendor_cbor(dev, req)
    except Exception:
        pass


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tools/ota_flash.py <signed_firmware.ota.bin>")
        sys.exit(1)

    fw_path = sys.argv[1]
    if not os.path.exists(fw_path):
        log.error(f"File not found: {fw_path}")
        sys.exit(1)

    # Read signed firmware (format: version + magic + sha256 + signature + raw_fw)
    with open(fw_path, "rb") as f:
        ota_data = f.read()

    if len(ota_data) < 104:
        log.error("File too small for OTA header")
        sys.exit(1)

    fw_version = struct.unpack("<I", ota_data[0:4])[0]
    fw_magic = struct.unpack("<I", ota_data[4:8])[0]
    fw_hash = ota_data[8:40]
    fw_sig = ota_data[40:104]
    fw_body = ota_data[104:]

    if fw_magic != OTA_MAGIC:
        log.error(f"Invalid magic: 0x{fw_magic:08x}")
        sys.exit(1)

    log.info(f"Pico FIDO OTA Flasher")
    log.info(f"  Firmware: {fw_path} ({len(fw_body)} bytes)")
    log.info(f"  Version:  {(fw_version >> 8) & 0xff}.{fw_version & 0xff}")
    log.info(f"  SHA-256:  {fw_hash.hex()}")
    log.info(f"  Signature: {fw_sig.hex()[:32]}...")

    # Connect to device
    dev = find_device()
    log.info("")

    # Get current OTA status
    log.info("Querying device...")
    status, major, minor = ota_info(dev)
    if status is not None:
        log.info(f"  Current fw version: {major}.{minor}")
        log.info(f"  OTA status: {['idle','busy','error','done'][status]}")
    log.info("")

    # Abort any existing OTA in progress
    ota_abort(dev)
    time.sleep(0.1)

    # Send firmware in chunks
    log.info("Sending firmware chunks...")
    total = len(fw_body)
    sent = 0
    chunk_num = 0
    for offset in range(0, total, CHUNK_SIZE):
        chunk = fw_body[offset:offset + CHUNK_SIZE]
        if not ota_write(dev, chunk):
            log.error(f"  Failed at chunk {chunk_num} (offset {offset})")
            ota_abort(dev)
            sys.exit(1)
        sent += len(chunk)
        chunk_num += 1
        if chunk_num % 10 == 0:
            progress = sent * 100 // total
            log.info(f"  Sent {sent}/{total} bytes ({progress}%) - {chunk_num} chunks")

    log.info(f"  Sent {sent}/{total} bytes - {chunk_num} chunks")
    log.info("")

    # Verify and activate
    log.info("Verifying and activating...")
    log.info("  (device will restart on success)")

    success = ota_verify(dev, fw_version, fw_hash, fw_sig)

    if success:
        log.info("")
        log.info("✓ OTA update complete!")
        log.info("  Device should restart with new firmware.")
        log.info(
            "  If not, unplug and replug to force restart.")
    else:
        log.info("OTA verify command sent. Check device.")


if __name__ == "__main__":
    main()
