# Pico FIDO 固件升级（OTA）

## 概述

Pico FIDO 支持通过 USB HID 通道进行固件升级（OTA），无需额外的烧录器或进入下载模式。

### 工作原理

```
PC/浏览器 ──USB─→ FIDO HID ──→ CTAP Vendor Command (0x41)
                                   │
                          ┌────────┴────────┐
                          │ CBOR 解析       │
                          │ cbor_vendor()   │
                          └────────┬────────┘
                                   │
                          ┌────────┴────────┐
                          │ OTA 处理        │
                          │ ota.c           │
                          └────────┬────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
              OTA_INFO      OTA_WRITE      OTA_VERIFY
              查版本号       写入 ota_1     校验签名+切换
```

### 分区布局

| 分区 | 偏移 | 大小 | 用途 |
|------|------|------|------|
| `nvs` | 0x9000 | 24K | NVS 存储 |
| `otadata` | 0xF000 | 8K | OTA 启动选择 |
| `phy_init` | 0x11000 | 4K | RF 初始化数据 |
| `ota_0` | 0x20000 | 1MB | 当前运行固件 |
| `ota_1` | 0x120000 | 1MB | OTA 备用槽 |
| `part0` | 0x220000 | 1.75MB + 数据分区（密钥、凭证） |

## 安全机制

### 签名验签

每个固件包包含 ECDSA P-256 签名：

```
[固件包格式]
  4 字节:  版本号 (uint32 LE)
  4 字节:  Magic 0x4D524946 ("FIRM")
  32 字节: SHA-256 哈希
  64 字节: ECDSA P-256 签名 (R||S)
  固件二进制数据...
```

验签流程：
1. 计算已写入固件的 SHA-256 → 与声明值比对
2. 使用内置公钥验证 ECDSA 签名
3. 通过后调用 `esp_ota_set_boot_partition()` 切换

### 防回滚

固件包含版本号与 `PICO_FIDO_VERSION` 比对，拒绝低于当前版本的固件。

### CTAP 协议扩展

通过 CTAP vendor command (CMD: 0x41) 传输：

| 子命令 | 代码 | 说明 |
|--------|------|------|
| `OTA_CMD_INFO` | 0x01 | 查询固件版本、OTA 状态 |
| `OTA_CMD_WRITE` | 0x02 | 写入固件块（每块最大 ~768 字节） |
| `OTA_CMD_VERIFY` | 0x03 | 发送元数据，触发验签切换 |
| `OTA_CMD_ABORT` | 0x04 | 取消正在进行的升级 |

## 开发环境工具链

### 1. 生成签名密钥（一次性）

```bash
cd tools
openssl ecparam -genkey -name prime256v1 -out ota_key.pem        # 私钥
openssl ec -in ota_key.pem -pubout -out ota_pub.pem                # 公钥
```

### 2. 签名固件

```bash
# 编译后执行
python3 tools/sign_firmware.py build/pico_fido.bin build/pico_fido_ota.bin
```

这会生成：
- `build/pico_fido_ota.bin` — 带签名的 OTA 固件包
- `src/fido/ota_pub_key.h` — 嵌入式公钥头文件

### 3. 本地 CLI 工具升级

```bash
pip install fido2   # 安装依赖
python3 tools/ota_flash.py build/pico_fido_ota.bin
```

### 4. Web 浏览器升级（推荐给终端用户）

打开 `tools/web/ota_flash.html`:

1. 点击 **连接设备** → 浏览器弹出 HID 设备选择
2. 点击选择固件文件 → 选 `pico_fido_ota.bin`
3. 点击 **开始 OTA 升级** → 等待进度完成

要求：Chrome/Edge 浏览器
协议：WebHID（需要 HTTPS 或 localhost）

## 产品化注意事项

### 测试密钥替换

`tools/ota_key.pem` 是开发测试用密钥。量产前必须替换：

```bash
# 生成新的正式密钥
openssl ecparam -genkey -name prime256v1 -out production_ota_key.pem
# 私钥离线安全保管，公钥编入固件
python3 tools/sign_firmware.py build/pico_fido.bin build/pico_fido_ota.bin
```

### 安全启动集成

在量产时可进一步锁定设备：

- 烧录 `SECURE_BOOT_EN` eFuse → 只运行签名固件
- 烧录 `FLASH_CRYPT_CNT` eFuse → Flash 全盘加密
- 烧录 `DIS_USB_SERIAL_JTAG` → 禁用 USB 下载模式（此时 OTA 仍可用）
- **注意**：eFuse 不可逆，请先在开发板上验证生产流程

### 固件大小限制

当前固件 ~556KB，每个 OTA 槽 1MB，预留约 40% 扩展空间。
如果固件接近 1MB，需要扩大 OTA 分区或将 part0 分区缩小。
