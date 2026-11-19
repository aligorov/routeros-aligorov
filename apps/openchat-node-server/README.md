# A-openchat-node-server

Автономный узел **OpenChat Sovereign Mesh Node** (`openchat-node`) для RouterOS `/app`: STUN Rendezvous, Blind Mailbox (per-contact очереди), No-Exit Guardian Relay, MediaRelay и маскировочный TCP-туннель **ShadowTLS v3 / REALITY**.

- Образ: `ghcr.io/aligorov/routeros-aligorov/openchat-node-server:1` (`linux/arm64`, `linux/amd64`).
- Порты:
  - `4433/udp` — входящий UDP (Rendezvous / STUN / Blind Mailbox / Relay / MediaRelay).
  - `8443/tcp` — ShadowTLS v3 TCP fallback (для обхода блокировки UDP). Порт `8443` выбран по умолчанию, чтобы не конфликтовать в каталоге с `A-ligament-ice` (`443/tcp`); при свободном `443/tcp` на роутере можно переназначить проброс на `443:8443/tcp`.
- Том: `openchat-data` → `/var/lib/openchat` (`openchat.db`, `.node_pin`, `node_identity.mnemonic`).

## Установка

1. В **Winbox → App → App** нажмите **Update** (обновить каталог).
2. Выберите **`A-openchat-node-server`** и нажмите **Enable**.
3. Убедитесь, что на WAN-интерфейсе роутера открыты входящие порты `4433/udp` и `8443/tcp` (или `443/tcp` при пробросе `443:8443/tcp`).
4. В клиенте OpenChat (iOS / Android / macOS) в **Настройки → Точка встречи** укажите `<публичный-IP-или-домен>:4433`.

## Подключение Push Gateway (`A-openchat-push-gateway`)

Чтобы нода отправляла слепые push-уведомления через собственный **`A-openchat-push-gateway`**, задайте `OPENCHAT_PUSH_GATEWAY_URL` (например, `http://<IP-роутера>:8088` или ваш внешний `https://...` URL за обратным прокси) и перезапустите контейнер.

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `OPENCHAT_PORT` | UDP-порт сервера Rendezvous / STUN / Blind Mailbox / Relay (`0` = отключить) | `"4433"` |
| `OPENCHAT_TLS_PORT` | TCP-порт ShadowTLS v3 / REALITY прокси (`0` = отключить) | `"8443"` |
| `OPENCHAT_SNI_DONOR` | Домен-донор для маскировки ShadowTLS v3 и отклонения активного зондирования | `yastatic.net` |
| `OPENCHAT_STRICT_NOISE` | Строгая аутентификация Noise IK по ключу узла (`"true"` / `"false"`) | `"true"` |
| `OPENCHAT_PIN` | ПИН-код шифрования локальной БД ноды (`auto` = генерируется и сохраняется в `/var/lib/openchat/.node_pin`) | `auto` |
| `OPENCHAT_ENABLE_TG` | Включить встроенный локальный модуль TG-шлюза (`"true"` / `"false"`) | `"false"` |
| `OPENCHAT_SPONSOR` | Спонсорский канал для Telegram-шлюза | `@openchat_freedom` |
| `OPENCHAT_PUSH_GATEWAY_URL` | URL шлюза слепых Push-уведомлений (`none` = отключено) | `none` |
| `TZ` | Часовой пояс (`UTC`, `MSK-3` и т.п.) | `UTC` |

## Проверка

После запуска проверьте логи контейнера в Winbox (**App → A-openchat-node-server → Logs** или `/container print`): в выводе должны появиться строки:
- `Сервер «Точка встречи» (Rendezvous + Blind Mailbox) запущен на UDP :4433`
- `NodePubkey (Noise IK): ... (strict=true)`
- `ТСПУ маскировка: ShadowTLS v3 на [::]:8443 -> донор yastatic.net:443`
