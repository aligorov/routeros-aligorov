# A-openchat-node-server

Автономный узел **OpenChat Sovereign Mesh Node** (`node-server`) для RouterOS `/app`: STUN Rendezvous, Blind Mailbox, No-Exit Guardian Relay и MediaRelay.

- Образ: `ghcr.io/aligorov/routeros-aligorov/openchat-node-server:1` (`linux/arm64`).
- Порт: `4433/udp` (входящий UDP для клиентов OpenChat).
- Том: `openchat-data` → `/var/lib/openchat` (`openchat.db`, `.node_pin`).

## Установка

1. В **Winbox → App → App** нажмите **Update** (обновить каталог).
2. Выберите **`A-openchat-node-server`** и нажмите **Enable**.
3. Убедитесь, что на WAN-интерфейсе роутера открыт входящий порт `4433/udp` (RouterOS `/app` автоматически пробрасывает его в контейнер, но в `input`/`forward` firewall не должен его резать).
4. В клиенте OpenChat (iOS / Android) в **Настройки → Точка встречи** укажите `<публичный-IP-или-домен>:4433`.

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `OPENCHAT_PORT` | UDP-порт сервера Rendezvous / STUN / Blind Mailbox / Relay (`0` = отключить) | `"4433"` |
| `OPENCHAT_PIN` | ПИН-код шифрования локальной БД ноды (`auto` = генерируется и сохраняется в `/var/lib/openchat/.node_pin`) | `auto` |
| `OPENCHAT_ENABLE_TG` | Включить встроенный локальный модуль TG-шлюза (`"true"` / `"false"`) | `"false"` |
| `OPENCHAT_SPONSOR` | Спонсорский канал для Telegram-шлюза | `@openchat_freedom` |
| `OPENCHAT_PUSH_GATEWAY_URL` | URL шлюза слепых Push-уведомлений (`none` = отключено) | `none` |
| `TZ` | Часовой пояс (`UTC`, `MSK-3` и т.п.) | `UTC` |

## Проверка

После запуска проверьте логи контейнера в Winbox (**App → A-openchat-node-server → Logs** или `/container print`): в выводе должна появиться строка `Сервер «Точка встречи» (Rendezvous + Blind Mailbox) запущен на UDP :4433`.
