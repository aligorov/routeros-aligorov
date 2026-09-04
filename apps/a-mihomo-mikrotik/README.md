# A-mihomo-mikrotik

[wiktorbgu/mihomo-mikrotik](https://github.com/wiktorbgu/mihomo-mikrotik) — mihomo
(форк Clash) как tunnel-gateway + mixed-прокси, адаптированный под RouterOS.

- Образ: `docker.io/wiktorbgu/mihomo-mikrotik:latest` (arm64, ~22 МБ сжато)
- `:1080` — mixed-прокси (SOCKS5 + HTTP/HTTPS)
- `http://<ip-роутера>:9091/ui` — панель (zashboard/Yacd, ставится из `EXTERNAL_UI_URL`)

## Envs (основные)

| Переменная | Что |
|---|---|
| `SUB1`, `SUB2`… | ссылки на подписки — **секрет**: значения вводятся при установке, в репо не попадают |
| `SRV1`, `SRV2`… | прямые URI прокси (`vless://`, `ss://`…) — тоже лучше как секреты |
| `UI_SECRET` | секрет API/панели (плейсхолдер `[secret:ui-secret]`) |
| `EXTERNAL_UI_URL` | ZIP панели: zashboard `dist.zip` / Yacd-meta |
| `LOG_LEVEL` | уровень логов (`error`) |

## Mounts

Том `mihomo-config` → `/etc/mihomo`: свои шаблоны в `/template`, скрипты в
`/user_sh`; `default_config.yaml` не редактировать (восстанавливается).
Для WireGuard/AmneziaWG — дополнительный маунт `/etc/mihomo/awg`, конфиги `.conf`
с LF-концами строк (CRLF не работают).

Правка на роутере: Winbox → App → приложение → Environment / Mounts → перезапуск.

## Маршрутизация

Контейнер поднимается как mixed-прокси на `:1080` — направлять трафик на него
можно NAT/mangle-правилами или указывая прокси клиентам вручную. Готового
TPROXY-визарда, как в `A-mihomo-proxy`, здесь нет.

## Третий mihomo в сторе?!

В сторе уже есть `A-mihomo-proxy` (визард + TPROXY), `A-mihomo-ros`
(ручной YAML-редактор) и этот (простой mixed-прокси). Оставьте один нужный,
остальные уберу: `npm run cli -- remove a-mihomo-proxy --commit` (или в боте
`/remove имя`).
