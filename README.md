<<<<<<< HEAD
# poc_rpc_proxy
=======
PoC RPC Proxy — мінімальна реалізація проміжного сервісу між гаманцем і blockchain RPC-нoдами.
Поточний фокус: Tron FullNode + уніфікований JSON-RPC 2.0 API.

## Основні можливості
- JSON-RPC 2.0 поверх HTTPS
- Обов'язковий mTLS між клієнтом і сервісом
- Гібридні методи: базові без префікса + chain-specific з префіксом
- Відповіді: normalized + raw
- Паралельна обробка batch-запитів через goroutines
- Tron upstream через HTTP API

## Конфігурація
- `PROXY_ADDR` (default `:8080`)
- `TRON_RPC_URLS` (список upstream через кому, має пріоритет над `TRON_RPC_URL`)
- `TRON_RPC_URL` (default `http://127.0.0.1:8090`)
- `TRON_RPC_MAX_ATTEMPTS` (default `3`)
- `PROXY_TIMEOUT_MS` (default `8000`)
- `PROXY_TLS_CERT` (шлях до server cert PEM)
- `PROXY_TLS_KEY` (шлях до server key PEM)
- `PROXY_TLS_CLIENT_CA` (CA PEM для перевірки client cert)
- `PROXY_TLS_ALLOWED_FILE` (allowlist файл для CN/SAN, optional)
- `PROXY_TLS_REVOKED_FILE` (revocation файл для fingerprint, optional)

Якщо заданий `TRON_RPC_URLS`, проксі вибирає upstream випадково і робить до `TRON_RPC_MAX_ATTEMPTS` спроб.

## TLS/mTLS (приклад локальної генерації)
### 1) CA
```bash
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -subj "/CN=poc-rpc-ca" -out ca.pem
```

### 2) Server cert
```bash
openssl genrsa -out server.key 4096
openssl req -new -key server.key -subj "/CN=rpc-proxy" -out server.csr
cat > server.ext <<'EOT'
subjectAltName=DNS:localhost,IP:127.0.0.1
EOT
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365 -sha256 -extfile server.ext
```

### 3) Client cert (кожному клієнту окремий)
```bash
openssl genrsa -out client1.key 4096
openssl req -new -key client1.key -subj "/CN=client-1" -out client1.csr
openssl x509 -req -in client1.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client1.pem -days 365 -sha256
```

## Allowlist / Revocation
Allowlist файл задає, які CN/SAN допускаються. Якщо файл не заданий або порожній — допускаються всі сертифікати, підписані вашим CA (крім відкликаних).
Для `dns:` та `uri:` переконайтесь, що client cert містить відповідний SAN.

### Формат allowlist файла
```
cn:client-1
dns:client-1.example.com
uri:spiffe://myorg/client-1
uri_prefix:spiffe://myorg/clients/
```

### Формат revocation файла
```
<sha256 fingerprint hex без двокрапок>
```

## Методи
### Базові (через `params.chain`)
- `getBalance`
- `getTransaction`
- `sendRawTransaction`

### Chain-specific
- `tron_getAccountResource`

## Приклади
### getBalance
```bash
curl -s https://127.0.0.1:8443 \
  --cacert ca.pem --cert client1.pem --key client1.key \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getBalance","params":{"chain":"tron","address":"T..."}}'
```

```json
{"jsonrpc":"2.0","id":1,"result":{"chain":"tron","address":"T...","balance":"1234567","unit":"sun","decimals":6,"raw":{}}}
```

### getTransaction
```bash
curl -s https://127.0.0.1:8443 \
  --cacert ca.pem --cert client1.pem --key client1.key \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"getTransaction","params":{"chain":"tron","txid":"..."}}'
```

```json
{"jsonrpc":"2.0","id":2,"result":{"chain":"tron","txid":"...","raw":{}}}
```

### sendRawTransaction
```bash
curl -s https://127.0.0.1:8443 \
  --cacert ca.pem --cert client1.pem --key client1.key \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"sendRawTransaction","params":{"chain":"tron","tx":{"raw_data":{},"signature":["..."]}}}'
```

```json
{"jsonrpc":"2.0","id":3,"result":{"chain":"tron","txid":"...","success":true,"raw":{}}}
```

### tron_getAccountResource
```bash
curl -s https://127.0.0.1:8443 \
  --cacert ca.pem --cert client1.pem --key client1.key \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"tron_getAccountResource","params":{"address":"T..."}}'
```

```json
{"jsonrpc":"2.0","id":4,"result":{"chain":"tron","address":"T...","energy_limit":"0","energy_used":"0","net_limit":"0","net_used":"0","free_net_limit":"0","free_net_used":"0","raw":{}}}
```

## Запуск
```bash
export PROXY_ADDR=:8443
export TRON_RPC_URLS=https://tron-rpc.publicnode.com,https://api.trongrid.io
export TRON_RPC_MAX_ATTEMPTS=3
export PROXY_TIMEOUT_MS=8000
export PROXY_TLS_CERT=./server.pem
export PROXY_TLS_KEY=./server.key
export PROXY_TLS_CLIENT_CA=./ca.pem
export PROXY_TLS_ALLOWED_FILE=./allowlist.txt
export PROXY_TLS_REVOKED_FILE=./revoked.txt

go run ./cmd/proxy
```

## Нотатки
- Адреса приймається у base58 або hex форматі (`41...`).
- Batch-запити (масив JSON-RPC) обробляються паралельно через goroutines.
- Проксі не підписує транзакції; лише бродкастить підписані.
- Кожен клієнт має власний client cert, підписаний спільним CA.
- Fingerprint береться як SHA-256 від DER сертифіката (hex, без двокрапок).
>>>>>>> 4ce42c0 (Initial commit)
