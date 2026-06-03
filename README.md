# quick-test-apis

## 启动 HTTP 服务

```bash
uv run run.py
```

---

## 启动 mTLS HTTPS 服务

用于测试客户端证书（Mutual TLS）认证。

### 1. 生成测试证书

```bash
uv run scripts/generate_certs.py
```

证书生成到 `certs/` 目录（已加入 `.gitignore`）：

| 文件 | 说明 |
|------|------|
| `ca.crt` / `ca.key` | 受信 CA 根证书 |
| `server.crt` / `server.key` | 服务器证书（localhost） |
| `client.crt` / `client.key` | 受信客户端证书（PEM） |
| `client-encrypted.key` | 带 passphrase 的加密私钥（密码：`test-passphrase`） |
| `client.p12` | PFX/P12 格式 bundle（密码：`test-passphrase`） |
| `untrusted-ca.crt` | 不受信任的 CA |
| `untrusted-client.crt` / `untrusted-client.key` | 不受信任 CA 签发的客户端证书 |

### 2. 启动服务

```bash
uv run run_mtls.py
```

服务运行在 `https://localhost:10443`

### 3. mTLS 端点

| 端点 | 说明 |
|------|------|
| `GET /mtls/echo-cert` | 要求客户端证书，返回证书详情 |
| `GET /mtls/optional` | 可选客户端证书，有则返回详情，无则提示 |
| `GET /mtls/verify` | 验证证书并返回 TLS 版本、加密套件等 |
| `GET /mtls/headers` | 回传所有请求头 + 客户端证书信息 |

### 4. 使用 curl 测试

```bash
# 不带客户端证书（/mtls/optional 正常返回，/mtls/verify 返回 403）
curl -sk https://localhost:10443/mtls/optional
curl -sk https://localhost:10443/mtls/verify

# 带受信客户端证书
curl -sk \
  --cert certs/client.crt \
  --key certs/client.key \
  --cacert certs/ca.crt \
  https://localhost:10443/mtls/echo-cert

# 使用加密私钥（需指定 passphrase）
curl -sk \
  --cert certs/client.crt \
  --key certs/client-encrypted.key \
  --pass "test-passphrase" \
  --cacert certs/ca.crt \
  https://localhost:10443/mtls/echo-cert

# 使用不受信任的客户端证书（TLS 握手失败）
curl -sk \
  --cert certs/untrusted-client.crt \
  --key certs/untrusted-client.key \
  https://localhost:10443/mtls/optional
```

---

## 运行测试

```bash
uv run pytest -v tests/
```