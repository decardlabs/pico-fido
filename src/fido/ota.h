/*
 * Pico FIDO OTA Firmware Update
 *
 * Implements USB-based OTA firmware update using the CTAP vendor command
 * interface. Firmware chunks are written to the inactive OTA partition,
 * verified via ECDSA P-256 signature, and then activated on successful
 * validation.
 */

#ifndef _FIDO_OTA_H_
#define _FIDO_OTA_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define OTA_MAGIC           0x4D524946  /* "FIRM" */
#define OTA_SIG_SIZE        64
#define OTA_HASH_SIZE       32

/* OTA commands (vendorCmd values for CTAP_VENDOR_OTA) */
#define OTA_CMD_INFO        0x01
#define OTA_CMD_WRITE       0x02
#define OTA_CMD_VERIFY      0x03
#define OTA_CMD_ABORT       0x04

/* OTA status codes */
#define OTA_STATUS_IDLE     0x00
#define OTA_STATUS_BUSY     0x01
#define OTA_STATUS_ERROR    0x02
#define OTA_STATUS_DONE     0x03

/* OTA info response structure (CBOR encoded) */
int ota_get_info(uint8_t *resp_buf, size_t *resp_len);

/* Process an OTA command */
int ota_process_cmd(uint8_t cmd, const uint8_t *data, size_t len);

/* Write a firmware chunk to the OTA partition */
int ota_write_chunk(const uint8_t *data, size_t len);

/* Verify signature and activate the new firmware */
int ota_verify_and_activate(const uint8_t *metadata, size_t len);

/* Abort the current OTA operation */
void ota_abort(void);

/* Get current OTA status string for diagnostics */
const char *ota_status_str(int status);

#endif /* _FIDO_OTA_H_ */
