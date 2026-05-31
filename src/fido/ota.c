/*
 * Pico FIDO OTA Firmware Update - Implementation
 */
#include "ota.h"
#include "ota_pub_key.h"
#include "version.h"

#include <string.h>

#if defined(ESP_PLATFORM)
#include "esp_system.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"

static const char *TAG = "pico-fido-ota";

static esp_ota_handle_t ota_handle = 0;
static const esp_partition_t *ota_partition = NULL;
static bool ota_in_progress = false;
static int ota_error_code = 0;
static uint8_t ota_chunk_count = 0;

#define OTA_CHUNK_LOG_INTERVAL 50

int ota_get_info(uint8_t *resp_buf, size_t *resp_len)
{
    /* We don't use CBOR here, simple binary response */
    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
    esp_app_desc_t app_desc;

    /* Try to get application description from running partition */
    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, NULL);
    bool has_desc = false;
    while (part) {
        if (esp_ota_get_partition_description(part, &app_desc) == ESP_OK) {
            has_desc = true;
            break;
        }
        part = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                        ESP_PARTITION_SUBTYPE_ANY, NULL);
    }

    size_t off = 0;
    resp_buf[off++] = ota_in_progress ? OTA_STATUS_BUSY : OTA_STATUS_IDLE;
    resp_buf[off++] = PICO_FIDO_VERSION_MAJOR;
    resp_buf[off++] = PICO_FIDO_VERSION_MINOR;
    if (running) {
        resp_buf[off++] = (uint8_t)(running->address >> 24);
        resp_buf[off++] = (uint8_t)(running->address >> 16);
        resp_buf[off++] = (uint8_t)(running->address >> 8);
        resp_buf[off++] = (uint8_t)(running->address);
    }
    if (next) {
        resp_buf[off++] = (uint8_t)(next->size >> 24);
        resp_buf[off++] = (uint8_t)(next->size >> 16);
        resp_buf[off++] = (uint8_t)(next->size >> 8);
        resp_buf[off++] = (uint8_t)(next->size);
    }
    if (ota_error_code) {
        resp_buf[off++] = (uint8_t)ota_error_code;
    } else {
        resp_buf[off++] = 0;
    }
    *resp_len = off;
    return 0;
}

int ota_write_chunk(const uint8_t *data, size_t len)
{
    if (!ota_in_progress) {
        /* Start a new OTA session */
        ota_partition = esp_ota_get_next_update_partition(NULL);
        if (!ota_partition) {
            ESP_LOGE(TAG, "No OTA partition available");
            ota_error_code = 0x01;
            return -1;
        }

        esp_err_t err = esp_ota_begin(ota_partition, OTA_SIZE_UNKNOWN, &ota_handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
            ota_partition = NULL;
            ota_error_code = 0x02;
            return -1;
        }
        ota_in_progress = true;
        ota_chunk_count = 0;
        ota_error_code = 0;
        ESP_LOGI(TAG, "OTA started, partition at 0x%x size %d",
                 ota_partition->address, ota_partition->size);
    }

    if (len == 0) {
        return 0;  /* Skip empty chunks */
    }

    esp_err_t err = esp_ota_write(ota_handle, data, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
        ota_abort();
        ota_error_code = 0x03;
        return -1;
    }
    ota_chunk_count++;
    return 0;
}

int ota_verify_and_activate(const uint8_t *metadata, size_t len)
{
    if (!ota_in_progress || !ota_handle || !ota_partition) {
        ota_error_code = 0x04;
        return -1;
    }

    /* Parse metadata: [version:4][magic:4][sha256:32][signature:64] */
    if (len < 8 + OTA_HASH_SIZE + OTA_SIG_SIZE) {
        ESP_LOGE(TAG, "Metadata too short: %d", (int)len);
        ota_abort();
        ota_error_code = 0x05;
        return -1;
    }

    uint32_t fw_version = (uint32_t)metadata[0] | ((uint32_t)metadata[1] << 8) |
                          ((uint32_t)metadata[2] << 16) | ((uint32_t)metadata[3] << 24);
    uint32_t magic = (uint32_t)metadata[4] | ((uint32_t)metadata[5] << 8) |
                     ((uint32_t)metadata[6] << 16) | ((uint32_t)metadata[7] << 24);
    const uint8_t *expected_hash = metadata + 8;
    const uint8_t *signature = metadata + 8 + OTA_HASH_SIZE;

    if (magic != OTA_MAGIC) {
        ESP_LOGE(TAG, "Bad magic: 0x%08x", magic);
        ota_abort();
        ota_error_code = 0x06;
        return -1;
    }

    /* Compare version (reject downgrade if new version < current) */
    uint16_t new_ver = (uint16_t)fw_version;
    if (new_ver < PICO_FIDO_VERSION) {
        ESP_LOGE(TAG, "Downgrade attempt: new %d.%d < current %d.%d",
                 (new_ver >> 8) & 0xff, new_ver & 0xff,
                 PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR);
        ota_abort();
        ota_error_code = 0x07;
        return -1;
    }

    /* End the OTA write */
    esp_err_t err = esp_ota_end(ota_handle);
    ota_handle = 0;
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
        ota_abort();
        ota_error_code = 0x08;
        return -1;
    }

    /* Read back the written data for verification */
    size_t fw_size = ota_partition->size;
    uint8_t *fw_buf = malloc(fw_size);
    if (!fw_buf) {
        ESP_LOGE(TAG, "Failed to allocate %d bytes for verification", (int)fw_size);
        ota_abort();
        ota_error_code = 0x09;
        return -1;
    }

    err = esp_partition_read(ota_partition, 0, fw_buf, fw_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read back firmware");
        free(fw_buf);
        ota_abort();
        ota_error_code = 0x0A;
        return -1;
    }

    /* Compute SHA-256 of the written firmware */
    uint8_t computed_hash[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, fw_buf, fw_size);
    mbedtls_sha256_finish(&sha_ctx, computed_hash);
    mbedtls_sha256_free(&sha_ctx);

    /* Compare hash */
    if (memcmp(computed_hash, expected_hash, 32) != 0) {
        ESP_LOGE(TAG, "SHA-256 mismatch!");
        free(fw_buf);
        ota_abort();
        ota_error_code = 0x0B;
        return -1;
    }

    /* Verify ECDSA P-256 signature using mbedtls_pk API */
    /*
     * Build SubjectPublicKeyInfo DER for EC P-256:
     * SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BITSTRING <key> }
     */
    uint8_t pubkey_der[91];
    size_t der_off = 0;
    /* Outer SEQUENCE of 89 bytes content */
    pubkey_der[der_off++] = 0x30;
    pubkey_der[der_off++] = 0x59;
    /* Inner SEQUENCE of 19 bytes content */
    pubkey_der[der_off++] = 0x30;
    pubkey_der[der_off++] = 0x13;
    /* OID: ecPublicKey (1.2.840.10045.2.1) */
    memcpy(pubkey_der + der_off, "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01", 9);
    der_off += 9;
    /* OID: prime256v1 (1.2.840.10045.3.1.7) */
    memcpy(pubkey_der + der_off, "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", 10);
    der_off += 10;
    /* BIT STRING: 66 bytes (0 unused bits + 04 + X + Y) */
    pubkey_der[der_off++] = 0x03;
    pubkey_der[der_off++] = 0x42;
    pubkey_der[der_off++] = 0x00;
    pubkey_der[der_off++] = 0x04;
    memcpy(pubkey_der + der_off, ota_pub_key, 64);
    der_off += 64;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk, pubkey_der, der_off);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to parse public key DER: %d", ret);
        mbedtls_pk_free(&pk);
        free(fw_buf);
        ota_abort();
        ota_error_code = 0x0C;
        return -1;
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                            computed_hash, 32, signature, 64);
    mbedtls_pk_free(&pk);
    free(fw_buf);

    if (ret != 0) {
        ESP_LOGE(TAG, "Signature verification failed: %d", ret);
        ota_abort();
        ota_error_code = 0x0C;
        return -1;
    }

    ESP_LOGI(TAG, "Signature OK! Setting boot partition...");

    /* Set the new boot partition */
    err = esp_ota_set_boot_partition(ota_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set boot partition: %s", esp_err_to_name(err));
        ota_abort();
        ota_error_code = 0x0D;
        return -1;
    }

    ota_in_progress = false;
    ota_error_code = 0;

    ESP_LOGI(TAG, "OTA successful! Restarting...");
    esp_restart();

    return 0;  /* Never reached */
}

void ota_abort(void)
{
    if (ota_handle) {
        esp_ota_abort(ota_handle);
        ota_handle = 0;
    }
    ota_partition = NULL;
    ota_in_progress = false;
    ESP_LOGW(TAG, "OTA aborted");
}

int ota_process_cmd(uint8_t cmd, const uint8_t *data, size_t len)
{
    switch (cmd) {
        case OTA_CMD_INFO:
            return 0;  /* Handled by caller for CBOR encoding */
        case OTA_CMD_WRITE:
            return ota_write_chunk(data, len);
        case OTA_CMD_VERIFY:
            return ota_verify_and_activate(data, len);
        case OTA_CMD_ABORT:
            ota_abort();
            return 0;
        default:
            return -1;
    }
}

const char *ota_status_str(int status)
{
    switch (status) {
        case OTA_STATUS_IDLE:   return "idle";
        case OTA_STATUS_BUSY:   return "busy";
        case OTA_STATUS_ERROR:  return "error";
        case OTA_STATUS_DONE:   return "done";
        default:                return "unknown";
    }
}

#else /* !ESP_PLATFORM */

/* Stub for non-ESP32 builds (emulation) */
int ota_get_info(uint8_t *resp_buf, size_t *resp_len)
{
    if (resp_len) *resp_len = 0;
    return 0;
}

int ota_process_cmd(uint8_t cmd, const uint8_t *data, size_t len)
{
    (void)cmd; (void)data; (void)len;
    return -1;
}

int ota_write_chunk(const uint8_t *data, size_t len)
{
    (void)data; (void)len;
    return -1;
}

int ota_verify_and_activate(const uint8_t *metadata, size_t len)
{
    (void)metadata; (void)len;
    return -1;
}

void ota_abort(void) {}

const char *ota_status_str(int status)
{
    (void)status;
    return "unavailable";
}

#endif
