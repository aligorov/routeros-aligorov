# A-ligament-relay

Периферийный edge-узел филиала **Ligament Relay** для экосистемы **Ligament 2FA**, адаптированный для запуска на MikroTik RouterOS (`/app`).

- Образ: `ghcr.io/aligorov/routeros-aligorov/ligament-relay:1` (`linux/arm64`).
- Порты:
  - `1812/udp` — локальный RADIUS-сервер (с проверкой `Message-Authenticator` против BlastRADIUS).
  - `8082/tcp` — локальный HTTP API (`/healthz`, `/api/v1/status`, `/api/v1/auth/verify`, `/api/v1/ws`).
- Тома (отдельные тома, ключ шифрования изолирован от БД согласно R-08):
  - `relay-config` → `/app/config` (`config.yaml`).
  - `relay-data` → `/app/data` (`relay.db` SQLite + WAL, права `0700`).
  - `relay-keys` → `/app/keys` (`relay.key` AES-GCM ключ + авто-токен `.api_token`, права `0700`).
  - `relay-certs` → `/app/certs` (опциональные PEM-сертификаты: `core-ca.pem`, `ad-ca.pem`, `relay-cert.pem`, `relay-key.pem`).

## Установка и настройка

1. В **Winbox → App → App** нажмите **Update** и включите **`A-ligament-relay`**.
2. В настройках приложения (**Environment**) укажите реальные параметры вашего филиала и перезапустите контейнер:
   - `RELAY_ID`, `RELAY_NAME` — идентификатор и имя филиала (как заведено в Core).
   - `CORE_URL`, `RELAY_CORE_PASSWORD` — адрес ядра Ligament 2FA (`https://...` или `wss://...`) и пароль филиала.
   - `RELAY_RADIUS_SECRET` — shared secret для NAS / MikroTik `/radius`.
   - `LDAP_URL`, `LDAP_BASE_DN`, `LDAP_BIND_DN`, `RELAY_LDAP_PASSWORD` — параметры локального AD/LDAP.
   - `RELAY_API_TOKEN` — оставьте `auto` (автогенерируется 32-символьный токен в `/app/keys/.api_token`) или задайте свой токен (минимум 16 символов).

## Работа с сертификатами (`/app/certs`)

По умолчанию том `relay-certs` пуст. Если положить туда файлы (через файл-менеджер RouterOS в каталог тома `relay-certs`), entrypoint автоматически подключит их в `config.yaml`:
- `core-ca.pem` → `core.ca_file` (доверенный CA для Core вместо `CORE_INSECURE_SKIP_VERIFY=true`)
- `ad-ca.pem` → `ldap.ca_file` (доверенный CA для LDAPS вместо `LDAP_INSECURE_SKIP_VERIFY=true`)
- `relay-cert.pem` + `relay-key.pem` → `http.tls.cert` / `http.tls.key` (TLS для локального HTTP API `:8082`)

Пути можно также явно переопределить переменными `CORE_CA_FILE`, `LDAP_CA_FILE`, `HTTP_TLS_CERT`, `HTTP_TLS_KEY`.

## Режимы конфигурации (`CONFIG_MODE`)

- `CONFIG_MODE=env` *(по умолчанию)* — при каждом старте генерирует `/app/config/config.yaml` из переменных окружения Winbox (секреты передаются как `${VAR}`, не записываясь в файл открытым текстом).
- `CONFIG_MODE=file` — не перезаписывает `/app/config/config.yaml`; используйте, если хотите редактировать YAML вручную на диске роутера.

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `CONFIG_MODE` | `env` (генерация из env) или `file` (ручной `config.yaml`) | `env` |
| `RELAY_ID` / `RELAY_NAME` | ID и отображаемое имя филиала | `branch-routeros` / `RouterOS Branch` |
| `RELAY_HOST_IP` | Локальный LAN IP хоста (`auto` = автоопределение) | `auto` |
| `RELAY_MAX_OFFLINE_TTL` | Окно автономной работы без связи с Core | `72h` |
| `CORE_URL` | URL центрального ядра Ligament 2FA (`https://` / `wss://`) | `https://2fa.example.com` |
| `RELAY_CORE_PASSWORD` | Пароль филиала для синхронизации с Core | `change-me-core-password` |
| `CORE_INSECURE_SKIP_VERIFY` / `CORE_ALLOW_INSECURE` | Отладочные флаги TLS/клиртекста для Core | `"false"` / `"false"` |
| `RADIUS_ENABLED` / `RELAY_RADIUS_SECRET` | Включение RADIUS и shared secret | `"true"` / `change-me-radius-secret` |
| `RADIUS_TRUST_DAYS` | Окно доверия устройства (дней, рек. `<= 7`) | `"7"` |
| `RADIUS_REQUIRE_MSG_AUTH` / `RADIUS_VERIFY_NAS_IP` | Защита BlastRADIUS / проверка `NAS-IP-Address` | `"true"` / `"false"` |
| `LDAP_ENABLED` / `LDAP_URL` | Подключение к AD (`ldaps://...`) | `"true"` / `ldaps://dc01.example.local:636` |
| `LDAP_BASE_DN` / `LDAP_BIND_DN` / `RELAY_LDAP_PASSWORD` | Параметры поиска и bind-учётка LDAP | `DC=example,DC=local` / ... |
| `LDAP_USER_FILTER` / `LDAP_INSECURE_SKIP_VERIFY` | Фильтр пользователя / пропуск проверки TLS LDAPS | `(sAMAccountName=%s)` / `"false"` |
| `RELAY_API_TOKEN` | Токен локального API (`auto` или строка >= 16 символов) | `auto` |
| `DISCOVERY_ENABLED` / `DISCOVERY_PORT` | mDNS `_ligament-relay._tcp.local` | `"true"` / `"8082"` |
| `BASTION_ALLOW_CIDRS` | Разрешённые подсети бастиона (через запятую) | `192.168.0.0/16,10.0.0.0/8` |
| `TZ` | Часовой пояс | `UTC` |
