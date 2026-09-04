# A-mihomo-ros

[medium1992/mihomo-ros](https://github.com/Medium1992/mihomo-ros) — ядро mihomo
(Clash.Meta) + веб-панель на busybox httpd для **ручного** написания config.yaml
(YAML/ssh-редактор, без визарда). В отличие от `A-mihomo-proxy` (там визард с
генерацией команд для MikroTik), здесь конфиг пишете сами.

- Образ: `docker.io/medium1992/mihomo-ros:latest` (arm64, ~24 МБ сжато)
- Панель: `http://<ip-роутера>:8091` — basic auth `admin/admin` (менять!)
- Порт API (external-controller) и прокси-порты задаются в `config.yaml`

## Mounts и Envs

| Что | Где |
|---|---|
| Том `mihomo-config` → `/etc/mihomo` | здесь живёт `config.yaml`, `scripts/`, `proxy-providers/` — переживает перезапуск/переустановку |
| `BASIC_AUTH_USER` (env) | логин панели, по умолчанию `admin` |
| `BASIC_AUTH_HASH` (env) | md5crypt-хеш пароля; пусто = дефолт `admin` |
| `BASIC_AUTH=off` (env) | отключить авторизацию панели |

Посмотреть/поменять на роутере: **Winbox → App → приложение → вкладки
Environment / Mounts** (после правки — перезапустить приложение).

## Интеграция с маршрутизацией

Перехват LAN-трафика (mangle/маршруты) настраивается отдельно — hook-скрипты в
том же `/etc/mihomo` (`scripts/`, `scripts-post/`) плюс правила на роутере
(README проекта, RouterOS 7.21+). Их `docker run` пример с `--network host` и
`cap_add` под /app-механизмом не нужен — veth создаётся автоматически.
