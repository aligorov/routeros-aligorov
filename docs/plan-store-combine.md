# План: `store-combine` — сервис-«комбайн» для app-store (MCP server + API)

> Статус: план (2026-09-03). Реализация — по этапам ниже.
> Сценарий: «добавь в стор vaultwarden» → агент вызывает MCP-инструмент →
> сервис проверяет образ (arm64, размер, метаданные), конвертирует docker-образ
> или docker-compose в манифест RouterOS, публикует в репо → GitHub Pages
> обновляется → приложение доступно в App Store на роутере.

---

## 1. Что строим

Сервис **store-combine** внутри этого репозитория (`service/`):

- **MCP server** — инструменты для ИИ-агента (ZCode/Claude и др.)
- **HTTP API** (streamable HTTP транспорт MCP + REST-эндпоинты health/status)
- **Комбайн конвертации**: Docker-образ / docker-compose.yml → манифест `/app` (tikapp YAML)
- **Публикатор**: коммит в этот репо → стор обновляется автоматически (Pages)

Работает как сервис (launchd на Mac / systemd / docker-compose на VPS),
но те же инструменты доступны и локально через stdio.

## 2. Архитектура

```
┌─────────────┐   MCP (stdio или HTTP+Bearer)   ┌──────────────────────────┐
│ ИИ-агент /  │ ───────────────────────────────▶ │        store-combine     │
│ REST-клиент │ ◀─────────────────────────────── │  (Node 22 + TypeScript)  │
└─────────────┘                                  └──────────┬───────────────┘
                                                            │
                    ┌───────────────┬───────────────┬───────┴────────┬──────────────┐
                    ▼               ▼               ▼                ▼              ▼
             registry-client   converter       validator        publisher      icon-gen
             (docker.io/ghcr:  (compose/img →  (ajv по         (LocalGit /     (placeholder
              arm64, env,      app.yaml,       schemas/…       GitHubApi)      PNG 128×128)
              ports, size)     секреты-маск.)  .schema.json)
```

**Стек**: TypeScript (ESM), `@modelcontextprotocol/server` (v2 line) +
`@modelcontextprotocol/express` для HTTP; `yaml`, `ajv`, `zod/v4`.
Альтернатива на Python/FastMCP отвергнута: хотим одну экосистему с VPN-проектом
(Next.js) и строгие типы на границах схем.

**Два entrypoint'а, один набор инструментов** (рекомендация SDK):
- `src/index.ts` — stdio (агент запускает сам)
- `src/http.ts` — streamable HTTP на `/mcp`, bearer-токен, для сервиса

## 3. MCP-инструменты (полный список)

### 3.1 `check_image` — проверка образа
Вход: `image` (например `docker.io/library/nginx:1.27-alpine`).
Выход: registry; есть ли `linux/arm64` (+digest); сжатый размер слоёв;
`Env`, `ExposedPorts`, `Cmd`, `Entrypoint`, `Labels`, `User`, `Volumes` из
config-блоба; предупреждения (нет arm64 / большой размер против RAM роутера /
`latest`-тег нестабилен).
Кэш метаданных на диск (TTL 24 ч) — анонимный Docker Hub лимитирован (~100 pull/6ч/IP).

### 3.2 `add_docker_image` — образ → приложение в сторе
Вход: `image`, опционально `name`, `descr`, `category`, `ports`, `env`, `volumes`, `ram-hint`.
Логика:
1. `check_image` (без arm64 — отказ, override флагом `allow_noarm64`)
2. Генерация `apps/<name>/app.yaml`:
   - `ExposedPorts` образа → порты `хост:контейнер/tcp`; первый TCP-порт получает метку `web` (кнопка UI в Winbox); host-номера подбираются свободными (начиная с 8080, шаг 10)
   - `Env` образа → черновик `environment` (системные PATH/LANG/HOME отфильтровываются), помечен «проверить руками»
   - `restart: unless-stopped`, `auto-update: false`
3. Placeholder-иконка `icon.png` (128×128) + `README.md`
4. По умолчанию — **dry-run**: возвращает сгенерированные файлы, не коммитит. Публикация — отдельным вызовом `publish`.

### 3.3 `import_compose` — docker-compose.yml → приложение
Вход: путь к файлу или URL.
Конвертация (см. §4): все сервисы compose → одно RouterOS-приложение (один veth,
сервисы видят друг друга через localhost). Секреты маскируются (§5).
Выход: файлы приложения + отчёт «что не переносится».

### 3.4 `list_apps` — содержимое стора
Из репо (локально или GitHub API): приложения, версии (теги образов), даты, URL стора.

### 3.5 `validate_app` — проверка манифеста по официальной схеме
Тот же ajv-валидатор, что в CI. Возвращает человекочитаемые ошибки.

### 3.6 `publish` — публикация в стор
Вход: `app` (имя) или `all`. Действия:
1. валидация всех манифестов
2. пересборка `store.yaml` / `default.yaml` / `index.html` (порт логики `scripts/build.sh` в TS)
3. атомарный коммит через **Git Data API** (blobs → tree → commit → ref): нет состояния гонки между файлами; Pages при push в `main` перестраивается сам
4. возврат: commit SHA, URL стора, URL страницы приложения

### 3.7 `remove_app` — удалить приложение
Удаление `apps/<name>/` + пересборка + коммит (одним атомарным коммитом).

### 3.8 `store_status` — состояние стора
Последние коммиты, статус CI, ответ `store.yaml` (HTTP-код, число приложений).

## 4. Правила конвертации Docker → RouterOS

| Docker / compose | RouterOS app YAML | Примечание |
|---|---|---|
| `image` | `services.<svc>.image` | только с registry (docker.io/ghcr.io) |
| `ports: "8080:80"` | `"8080:80/tcp"` | метка `web` первому TCP-порту; UDP → `/udp` |
| `environment` / `env_file` | `environment` | ключи, похожие на секрет (PASSWORD/SECRET/TOKEN/KEY/CERT) → `secrets:` + `[secret:имя]` |
| named volume, bind mount | именованный том в корневом `volumes:` | bind-пути становятся именованными томами |
| небольшой конфиг-файл | корневое `configs:` (inline `content`) + `configs` сервиса | только файлы < 32 КБ из репозитория |
| `depends_on` | `depends_on` | как есть |
| `healthcheck` | `healthcheck` | поддерживается схемой |
| `restart` | `restart` | дефолт `unless-stopped` |
| `command` / `entrypoint` | `command` / `entrypoint` | как есть |
| `build:` | — | отказ: нужен готовый образ (или сначала `ghcr-push`) |
| `privileged`, `cap_add`, `network_mode: host`, `pid/ipc`, внешние сети | — | warning: не поддерживается / требует ручной настройки на роутере |
| `deploy.resources.limits.memory` | — | warning против `ram-hint` роутера |

Всегда: `auto-update: false`; тег образа pinned (не `latest` — предупреждение).

## 5. Безопасность

- **Репо публичный** → до коммита regex-аудит диффа: пароли/токены/приватные IP (RFC1918) → блок.
- **Секреты из compose/env_file не коммитятся**: значения заменяются на `[secret:имя]`,
  оригиналы складываются в локальный `service/.secrets/<app>.json` (gitignored) —
  вводятся при установке приложения на роутере.
- **MCP HTTP**: статический bearer (`Authorization: Bearer …`, 401 + `WWW-Authenticate`).
- **GitHub PAT** fine-grained: только этот репо, Contents: RW; лежит в env сервиса, не в репо.
- Registry-клиент: только анонимные pull-токены, ничего не пишет в registry.

## 6. Конфигурация и запуск как сервис

`service/.env` (пример, gitignored):
```
GITHUB_REPO=aligorov/routeros-aligorov
GITHUB_TOKEN=github_pat_...        # fine-grained, Contents RW на этот репо
MCP_TOKEN=...                      # bearer для HTTP /mcp
PORT=8765
STORE_BASE_URL=https://aligorov.github.io/routeros-aligorov
```

Запуск:
- локально агентом: `.mcp.json` в проекте → `{"store-combine": {"type":"stdio","command":"node","args":["service/dist/index.js"]}}`
- как сервис на Mac: launchd plist (`~/Library/LaunchAgents/app.aligorov.store-combine.plist`, `KeepAlive`), или systemd/docker-compose на VPS (docker-образ сервиса — опционально, M4)
- удалённо агентом: `{"type":"http","url":"https://<host>:8765/mcp","headers":{"Authorization":"Bearer …"}}`

## 7. Структура кода

```
service/
├── package.json / tsconfig.json
├── src/
│   ├── index.ts               # stdio entrypoint
│   ├── http.ts                # HTTP entrypoint (/mcp, bearer; /healthz)
│   ├── tools/                 # check-image.ts, add-image.ts, import-compose.ts,
│   │                          # list.ts, validate.ts, publish.ts, remove.ts, status.ts
│   └── core/
│       ├── registry.ts        # docker.io/ghcr.io: токены, манифесты, arm64, config blob
│       ├── converter.ts       # compose/образ → app.yaml
│       ├── validate.ts        # ajv + ../schemas/routeros-app-yaml.schema.json
│       ├── build-store.ts     # пересборка store.yaml/default.yaml/index.html (порт build.sh)
│       ├── publisher/
│       │   ├── github-api.ts  # Git Data API, атомарный коммит
│       │   └── local-git.ts   # режим локального клона (MVP, вызывает git)
│       ├── icons.ts           # placeholder PNG
│       └── secrets.ts         # маскирование, service/.secrets/
└── test/                      # vitest: converter, arm64-фильтр, секреты-маскировка
```

## 8. Этапы реализации

| Этап | Содержание | Критерий готовности |
|---|---|---|
| **M1** (ядро) | registry.ts, converter, validate, icons, `check_image` + `add_docker_image` + `publish` (local-git), stdio | «добавь nginx в стор» одной командой агента; demo-nginx воспроизводится автоматически |
| **M2** (compose) | `import_compose`, маскирование секретов, warnings-отчёт | реальный compose с 2–3 сервисами → валидное приложение в сторе; секрет не попадает в коммит (тест) |
| **M3** (сервис) | http.ts + bearer, launchd, `.mcp.json`, `store_status` | сервис живёт между перезагрузками, агент подключается по HTTP |
| **M4** (API-режим) | publisher/github-api (без клона), `remove_app`, кэш registry, CI сервиса | сервис работает на чистой VPS без локального клона |

## 9. Проверенные технические детали (из исследования 2026-09-03)

**Docker Registry API (живые проверки):**
- docker.io токен: `https://auth.docker.io/token?service=registry.docker.io&scope=repository:<ns>/<repo>:pull`; registry: `registry-1.docker.io`, официальный образы под `library/`
- arm64: манифест запрашивать с `Accept: application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json`; выбирать `platform.os==linux && architecture==arm64`; записи `unknown/unknown` — attestation, пропускать; одно-арх образ вернёт plain manifest → смотреть `architecture` в config-блобе
- config-блоб (`application/vnd.docker.container.image.v1+json`): `.config.{Env,ExposedPorts,Labels,Cmd,Entrypoint,User,Volumes,StopSignal}`; блобы редиректят на CDN — следовать 307
- GHCR тоже требует анонимный токен: `https://ghcr.io/token?scope=repository:<owner>/<image>:pull&service=ghcr.io`
- размер (сжатый) = сумма `.layers[].size` манифеста конкретной архитектуры

**GitHub API:**
- атомарный мультifайл-коммит: `GET git/ref/heads/main` → `POST git/blobs` (для каждого файла, base64) → `POST git/trees` (`base_tree` + список; удаление = `"sha": null`) → `POST git/commits` → `PATCH git/refs/heads/main`
- Pages (deploy from branch) перестраивается автоматически при push в main
- fine-grained PAT: Metadata:R + Contents:RW; 409 на устаревшем sha → перечитать и повторить

**MCP SDK (TS, v2 line):**
- пакеты `@modelcontextprotocol/server` + `@modelcontextprotocol/express`; инструменты: `server.registerTool(name, {description, inputSchema: z.object(...)}, handler)`; zod из `zod/v4`
- транспорта: stdio (локально) и streamable HTTP (`/mcp`) — отдельные entrypoint'ы; SSE устарел
- auth для личного сервера: статический bearer в middleware, 401 + `WWW-Authenticate: Bearer`
