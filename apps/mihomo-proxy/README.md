# mihomo-proxy

[mihomo (Clash.Meta)](https://github.com/Medium1992/mihomo-proxy-ros) — прокси с WebUI,
заточенный под RouterOS (TPROXY/Redirect+TUN, fake-ip DNS, встроенная генерация
команд для терминала MikroTik).

## Важно: интеграция с маршрутизацией

Установка из app-store запускает **контейнер** (WebUI, панель mihomo, подгрузка
подписки), но НЕ настраивает перехват трафика на роутере. Полная интеграция
(mangle-правила, TPROXY, таблицы маршрутизации) выполняется скриптами автора:
`script.rsc` (RouterOS 7.20) / `script21.rsc` (7.21+) из
[репозитория проекта](https://github.com/Medium1992/mihomo-proxy-ros) —
либо сгенерируйте команды через встроенный WebUI.

Альтернатива: поставить целиком их штатным скриптом — тогда контейнер из стора
не нужен (дублей быть не должно).

## Что открывается

| Порт | Что |
|---|---|
| `http://<ip-роутера>:8090` | WebUI (basic auth: admin / пароль по умолчанию, меняется ENV) |
| `http://<ip-роутера>:9090` | панель mihomo (external controller, секрет = `ui-secret`) |

## Переменные (основные)

- `UI_SECRET` — секрет панели (вводится при установке, плейсхолдер `[secret:ui-secret]`)
- `BASIC_AUTH_USER` — логин WebUI (по умолчанию admin)
- `TPROXY=true|false`, `DNS_MODE=fake-ip`, `SNIFFER=true` — режимы
  (полный список — в README проекта)

Том `mihomo-config:/root/.config/mihomo` — конфиги/подписки переживают перезапуск.

Требования: RouterOS 7.20+, пакет container, arm64. При установке введите
значение секрета `ui-secret`.
