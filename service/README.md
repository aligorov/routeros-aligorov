# store-combine — комбайн app-store

Сервис добавления контейнеров в стор `routeros-aligorov` тремя способами:
**Telegram-бот**, **MCP-инструменты** (для ИИ-агента) и **CLI**.

Что делает: проверяет образ (arm64! размер, порты, env) → генерирует
`apps/<имя>/app.yaml` по официальной схеме RouterOS → placeholder-иконка →
валидация → пересборка `store.yaml` → коммит+push → стор обновляется на GitHub Pages.

Образ в Docker Hub: `aligorov/store-combine:latest` (arm64+amd64).

## Быстрый старт (CLI, без токенов)

```sh
cd service
npm install
npm run cli -- check docker.io/library/nginx:1.27-alpine   # проверка образа
npm run cli -- add docker.io/library/redis:7-alpine        # dry-run (показ YAML)
npm run cli -- add docker.io/library/redis:7-alpine --commit --name redis --port 6379:6379
npm run cli -- import /путь/docker-compose.yml [--name имя] [--commit]   # импорт compose (M2)
npm run cli -- import https://example.com/docker-compose.yml             # compose по URL
```

## Telegram-бот

1. В `@BotFather` → `/newbot` → получить токен.
2. В `@userinfobot` узнать свой ID.
3. `cp .env.example .env`, заполнить `TELEGRAM_BOT_TOKEN` и `TELEGRAM_ALLOWED_IDS`.
4. Запуск: `npm run bot` (читает `.env`? — нет, экспортируйте: `set -a; source .env; set +a; npm run bot`).

Команды бота:

- `/add docker.io/library/redis:7-alpine redis` → бот пришлёт YAML и кнопки
  «✅ Опубликовать / Отмена»
- `/import <URL docker-compose.yml>` или просто прислать файл `.yml/.yaml`
  документом 📎 → импорт compose с отчётом о предупреждениях
- `/check <образ>` — проверка без добавления
- `/list`, `/remove <имя>`

Чужим пользователям бот не отвечает (белый список ID).

## Запуск в Docker

```sh
docker run -d --name store-combine \
  -v /путь/к/routeros-aligorov:/repo \
  -e REPO_DIR=/repo \
  -e STORE_BASE_URL=https://aligorov.github.io/routeros-aligorov \
  -e TELEGRAM_BOT_TOKEN=... -e TELEGRAM_ALLOWED_IDS=... \
  aligorov/store-combine:latest
```

Для `git push` из контейнера нужен доступ к GitHub: смонтируйте
настроенный клон (ssh-remotes + ключ) или переключитесь на
GitHub-API-publisher (M4, план `docs/plan-store-combine.md`).

## MCP (для агента)

```sh
npm run mcp   # stdio-сервер: check_image, add_docker_image, publish_app, list_apps, remove_app, store_status
```

Регистрация в проекте (`.mcp.json`):

```json
{
  "mcpServers": {
    "store-combine": { "command": "npm", "args": ["run", "--prefix", "/Users/aleksey/Documents/routeros-aligorov/service", "mcp"] }
  }
}
```

## Запуск бота как сервис (macOS, launchd)

`~/Library/LaunchAgents/app.aligorov.store-combine.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>app.aligorov.store-combine</string>
  <key>WorkingDirectory</key><string>/Users/aleksey/Documents/routeros-aligorov/service</string>
  <key>EnvironmentVariables</key><dict>
    <key>TELEGRAM_BOT_TOKEN</key><string>ВАШ_ТОКЕН</string>
    <key>TELEGRAM_ALLOWED_IDS</key><string>ВАШ_ID</string>
  </dict></dict>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/npm</string><string>run</string><string>bot</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/store-combine.log</string>
  <key>StandardErrorPath</key><string>/tmp/store-combine.err</string>
</dict></plist>
```

`launchctl load ~/Library/LaunchAgents/app.aligorov.store-combine.plist`
(путь к npm: `which npm`; Homebrew на arm — `/opt/homebrew/bin/npm`).

## Безопасность

- Репозиторий публичный: перед коммитом — авто-скан на токены/ключи/пароли/приватные IP.
- Ключи env вида `*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*KEY*` превращаются в
  `secrets:` + `[secret:имя]` — значения не попадают в репо.
- Бот отвечает только ID из `TELEGRAM_ALLOWED_IDS`.
- Коммит из CLI/MCP — только с явным `--commit` / `commit: true`.

## Конфигурация

См. `.env.example`: `REPO_DIR`, `STORE_BASE_URL`, `TELEGRAM_*`, `ALLOW_COMMIT`.
