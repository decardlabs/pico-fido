# Pico FIDO 固件升级（OTA）

## 概述

Pico FIDO 支持通过 USB HID 通道进行固件升级（OTA），无需额外的烧录器或进入下载模式。

### 协议分层

```
USB HID 传输层 (CTAPHID)
  │  CMD = 0xC1 (CTAPHID_VENDOR_FIRST + 1 | TYPE_INIT)
  │
  ├── Vendor 类型选择 (1 字节)
  │    0x07 = CTAP_VENDOR_OTA
  │
  ├── CBOR 编码结构
  │    { 0x01: subcmd, 0x02: { 0x01: h'payload' } }
  │
  └── OTA 子命令
       0x01 = INFO    — 查询设备状态
       0x02 = WRITE   — 写入固件块
       0x03 = VERIFY  — 验签并切换分区
       0x04 = ABORT   — 取消升级
```

### 数据传输流程

```
OTA_WRITE →
  固件侧: esp_ota_begin(ota_partition) → esp_ota_write(chunk) × N

OTA_VERIFY →
  固件侧: esp_ota_end() → SHA256 校验 → ECDSA 验签 → esp_ota_set_boot_partition() → esp_restart()
```

### 分区布局

| 分区 | 偏移 | 大小 | 用途 |
|------|------|------|------|
| `nvs` | 0x9000 | 24K | NVS 存储 |
| `otadata` | 0xF000 | 8K | OTA 启动选择 |
| `phy_init` | 0x11000 | 4K | RF 初始化数据 |
| `ota_0` | 0x20000 | 1MB (0x100000) | 当前运行固件槽 |
| `ota_1` | 0x120000 | 1MB (0x100000) | OTA 备用固件槽 |
| `part0` | 0x220000 | 0x1E0000 (~1.88MB) | 数据分区（密钥、凭证） |

## 安全机制

### 签名验签

固件包使用 ECDSA P-256 + SHA-256 签名：

```
OTA 固件包格式:
  <-- 104 字节元数据 --><-- 固件二进制 -->
  ┌────────┬──────┬──────────┬──────────┬─────────────┐
  │Version │Magic │ SHA-256  │ ECDSA签  │ 固件数据    │
  │ 4B LE  │4B LE │ 32B      │ 名 64B   │             │
  └────────┴──────┴──────────┴──────────┴─────────────┘

  Version: PICO_FIDO_VERSION 匹配 src/fido/version.h
  Magic:   0x4D524946 ("FIRM")
```

验签流程:
1. 主机发送元数据 (Version + Magic + SHA-256 + 签名)
2. 固件读取写入到 `ota_1` 的数据，计算 SHA-256 → 比对
3. 使用内置公钥 (`ota_pub_key.h`) 验证 ECDSA 签名
4. 通过后调用 `esp_ota_set_boot_partition()` 切换

### 防回滚

固件版本号与 `PICO_FIDO_VERSION` 比对，拒绝低于当前版本的固件。

### OTA 状态码

| 代码 | 常量 | 说明 |
|------|------|------|
| 0x00 | `OTA_STATUS_IDLE` | 空闲，无进行中的 OTA |
| 0x01 | `OTA_STATUS_BUSY` | 正在接收固件数据 |
| 0x02 | `OTA_STATUS_ERROR` | 上次 OTA 失败 |
| 0x03 | `OTA_STATUS_DONE` | OTA 完成（待重启） |

### OTA_INFO 响应格式

| 偏移 | 大小 | 说明 |
|------|------|------|
| 0 | 1 | OTA 状态码 |
| 1 | 1 | 主版本号 (Major) |
| 2 | 1 | 次版本号 (Minor) |
| 3 | 4 | 当前运行分区地址 (big-endian，仅当 running≠NULL) |
| 7 | 4 | 备用分区大小 (big-endian，仅当 next≠NULL) |
| - | 1 | 错误码 (最后字节) |

## CTAP 协议参考

### Vendor 命令路由

USB HID 以 `CMD=0xC1` 发送到设备，数据格式：

```
[0x07][CBOR bytes...]
  ↑
  CTAP_VENDOR_OTA — 固件通过此字节路由到 OTA 处理函数
```

### CBOR 请求结构

```python
{
    0x01: int,          # OTA 子命令 (1-4)
    0x02: {             # 参数嵌套 Map
        0x01: b'...'    # 数据载荷 (可选)
    }
}
```

### CBOR 响应结构

**OTA_INFO:**
```python
{
    0x01: b'...',    # 二进制信息 (见上节格式)
    0x02: 0          # 0=成功
}
```

**其他命令:**
```python
{
    0x02: 0          # 0=成功
}
```

**错误响应:** `0xF1` 即 `CTAP2_ERR_VENDOR_FIRST + 0x01`

## 开发环境工具链

### 1. 生成签名密钥（一次性）

```bash
# 在项目根目录执行
openssl ecparam -genkey -name prime256v1 -out tools/ota_key.pem   # 私钥
openssl ec -in tools/ota_key.pem -pubout -out tools/ota_pub.pem   # 公钥

# 测试密钥文件已存在，用以下命令重新生成
rm tools/ota_key.pem tools/ota_pub.pem
# 再执行上面的 openssl 命令
```

### 2. 编译并签名固件

```bash
cd <project_root>

# 编译
idf.py build

# 签名 (版本号自动从 src/fido/version.h 读取)
python3 tools/sign_firmware.py build/pico_fido.bin build/pico_fido_ota.bin
```

输出:
- `build/pico_fido_ota.bin` — 带签名的 OTA 固件包
- `src/fido/ota_pub_key.h` — 自动生成的公钥头文件（编译前需重新生成）

### 3. 本地 CLI 升级

```bash
pip install fido2
python3 tools/ota_flash.py build/pico_fido_ota.bin
```

工作原理:
- 通过 fido2 库发现 FIDO HID 设备
- 按 `CHUNK_SIZE=768` 分块发送固件
- 每块以 `[0x07][CBOR...]` 格式通过 CTAP vendor command 发送
- 最后发送 OTA_VERIFY，设备验签后自动重启

### 4. Web 浏览器升级

打开 `tools/web/ota_flash.html`（需 HTTPS 或 localhost）:

1. 点击 **连接设备** → 浏览器弹出 HID 设备选择器
2. 点击选择固件文件 → 选 `build/pico_fido_ota.bin`
3. 点击 **开始 OTA 升级** → 实时显示进度

要求：Chrome/Edge 浏览器，支持 WebHID API

## 产品化注意事项

### 测试密钥替换

`tools/ota_key.pem` 是开发测试用密钥。量产前必须替换：

```bash
# 生成新的正式密钥
openssl ecparam -genkey -name prime256v1 -out production_ota_key.pem

# 私钥离线安全保管
# 公钥编入固件
python3 tools/sign_firmware.py build/pico_fido.bin build/pico_fido_ota.bin --key production_ota_key.pem
```

### 安全启动集成

在量产时可进一步锁定设备:

- 烧录 `SECURE_BOOT_EN` eFuse → 只运行签名固件
- 烧录 `FLASH_CRYPT_CNT` eFuse → Flash 全盘加密
- 烧录 `DIS_USB_SERIAL_JTAG` → 禁用 USB 下载模式（OTA 仍可用）
- **注意**: eFuse 不可逆，请先在开发板上验证生产流程

### 固件大小约束

每个 OTA 槽 1MB。当前固件约 556KB，预留约 40% 扩展空间。
若固件超过 1MB，需缩小 `part0` 分区或扩大 `ota` 分区。
