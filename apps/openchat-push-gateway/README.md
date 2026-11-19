# A-openchat-push-gateway

Автономный шлюз слепых push-уведомлений **OpenChat Blind Push Gateway** (`push-gateway`) для RouterOS `/app`: выдаёт обезличенные токены `PushCapability` (XChaCha20-Poly1305) и доставляет пустые wakeup-уведомления через Apple APNs HTTP/2 и FCM без знания публичных ключей, ID очередей и графа контактов.

- Образ: `ghcr.io/aligorov/routeros-aligorov/openchat-push-gateway:1` (`linux/arm64`, `linux/amd64`).
- Порт: `8088/tcp` (`/health`, `/api/v1/push/issue`, `/api/v1/push/capability`, `/api/v1/push/dispatch`).
- Тома:
  - `push-data` → `/var/lib/openchat-push` (хранит автосгенерированный 32-байтный ключ `.push_cap_key`).
  - `push-keys` → `/app/keys` (опциональные ключи провайдеров: `apns.p8` или `*.p8`, `fcm-service-account.json`).

## Установка и настройка

1. В **Winbox → App → App** нажмите **Update** (обновить каталог) и включите **`A-openchat-push-gateway`**.
2. Для доставки реальных Apple VoIP/Push уведомлений положите ключ Apple `.p8` в каталог тома `push-keys` (как `apns.p8`) и задайте в **Environment**:
   - `APNS_KEY_ID` — ID ключа Apple APNs;
   - `APNS_TEAM_ID` — Apple Developer Team ID;
   - `APNS_BUNDLE_ID` — Bundle ID приложения (по умолчанию `org.openchat.ios`).
3. Для Android FCM положите `fcm-service-account.json` в каталог тома `push-keys`.
4. В настройках **`A-openchat-node-server`** укажите `OPENCHAT_PUSH_GATEWAY_URL=http://<IP-роутера-или-контейнера>:8088` (для публичных клиентов рекомендуется проксировать шлюз через HTTPS).

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `PUSH_GATEWAY_PORT` | TCP-порт HTTP API шлюза | `"8088"` |
| `PUSH_CAP_KEY` | 64-символьный hex-ключ XChaCha20-Poly1305 (`auto` — генерация и сохранение в `/var/lib/openchat-push/.push_cap_key`) | `auto` |
| `APNS_KEY_PATH` | Путь к `.p8` ключу Apple (`auto` — ищет `/app/keys/apns.p8` или `*.p8`, `none` — отключить) | `auto` |
| `APNS_KEY_ID` / `APNS_TEAM_ID` | Key ID и Team ID в Apple Developer (`none` — не задано) | `none` |
| `APNS_BUNDLE_ID` | Bundle ID iOS-приложения (`ios-voip` добавляет суффикс `.voip`) | `org.openchat.ios` |
| `APNS_SANDBOX` | Использовать `api.sandbox.push.apple.com` (`"true"` / `"false"`) | `"false"` |
| `FCM_KEY_PATH` | Путь к `fcm-service-account.json` (`auto` — ищет в `/app/keys/`, `none` — отключить) | `auto` |
| `TZ` | Часовой пояс | `UTC` |

## Проверка

- `GET http://<ip-роутера>:8088/health` → `{"has_apns":...,"has_fcm":...,"service":"openchat-blind-push-gateway","status":"healthy",...}`
- В логах контейнера должна быть строка `Starting OpenChat Blind Push Gateway on :8088...`.
