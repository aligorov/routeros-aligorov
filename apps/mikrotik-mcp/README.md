# A-mikrotik-mcp

Полнофункциональный мульти-роутерный **MCP-шлюз (`mikrotik-mcp-server`)** для **MikroTik RouterOS 7.24+** по протоколам **REST API** (`/rest`) и **Binary API** (`8728`/`8729`), без использования SSH.

- Образ: `ghcr.io/aligorov/routeros-aligorov/mikrotik-mcp-server:1.1.0` (`linux/arm64`, `linux/amd64`; также публикуются теги каналов `:1.1` и `:1`).
- Порт: `3000/tcp` (Streamable HTTP MCP endpoint `/mcp` и проверка живости `/healthz`).
- Тома:
  - `mcp-config` → `/app/config` (опциональные `routers.yaml` для управления парком роутеров и `ca.pem` для TLS-верификации).
  - `mcp-data` → `/app/data` (хранит автосгенерированный Bearer-токен `.bearer_token`).

## Подготовка RouterOS перед запуском

На целевом MikroTik создайте пользователя с правами `rest-api` и `api` и включите сервисы:

```rsc
/user/group/add name=mcp policy=read,write,test,ftp,api,rest-api,!local,!telnet,!ssh,!winbox
/user/add name=mcp group=mcp password="STRONG_PASSWORD"
/ip/service/set www-ssl disabled=no
/ip/service/set api-ssl disabled=no
```

Убедитесь также, что в firewall (`input`) разрешены подключения от подсети контейнеров (veth) к портам `443/tcp` и `8729/tcp` роутера.

## Установка и настройка

1. В **Winbox → App → App** нажмите **Update** (обновить каталог) и включите **`A-mikrotik-mcp`**.
2. В настройках приложения (**Environment**) укажите как минимум:
   - `MIKROTIK_USERNAME` и `MIKROTIK_PASSWORD` (должны совпадать с созданным пользователем в RouterOS);
   - `MIKROTIK_HOST` — оставьте `auto` (контейнер сам определит шлюз хоста RouterOS) или укажите явный IP роутера;
   - `MCP_BEARER_TOKEN` — задайте свой длинный секретный токен или оставьте `auto` (случайный 48-символьный токен сгенерируется при первом старте и сохранится в `/app/data/.bearer_token`).
3. Для управления **несколькими роутерами** положите файл `routers.yaml` (и при желании `ca.pem`) в каталог тома `mcp-config` на диске роутера и перезапустите контейнер.

## Подключение MCP-клиента

- URL: `http://<ip-роутера>:3000/mcp` (рекомендуется закрыть обратным прокси с TLS или подключаться внутри VPN/LAN)
- Заголовок: `Authorization: Bearer <ваш_MCP_BEARER_TOKEN>`
- Проверка статуса: `GET http://<ip-роутера>:3000/healthz`

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `MCP_BEARER_TOKEN` | Bearer-токен авторизации (`auto` — генерация в `/app/data/.bearer_token`) | `auto` |
| `MIKROTIK_HOST` | IP/домен роутера (`auto` — автоопределение шлюза хоста) | `auto` |
| `MIKROTIK_ROUTER_ID` | Идентификатор профиля роутера в шлюзе | `local-router` |
| `MIKROTIK_USERNAME` / `MIKROTIK_PASSWORD` | Учётные данные пользователя RouterOS (`api,rest-api`) | `mcp` / `change-me-router-password` |
| `MIKROTIK_TRANSPORT_PREF` | Приоритет транспорта: `auto` \| `rest` \| `api` | `auto` |
| `MIKROTIK_REST_PROTOCOL` / `MIKROTIK_REST_PORT` | Протокол (`https`/`http`) и порт REST API | `https` / `443` |
| `MIKROTIK_API_TLS` / `MIKROTIK_API_PORT` | TLS (`true`/`false`) и порт Binary API | `true` / `8729` |
| `MIKROTIK_TLS_VERIFY` | Проверять TLS-сертификат роутера (при `ca.pem` можно `true`) | `false` |
| `MCP_PORT` / `MCP_PATH` | Порт и URL-путь HTTP MCP endpoint | `3000` / `/mcp` |
| `MCP_AUDIT_LOG_PATH` | Файл JSONL-аудита вызовов MCP внутри тома `mcp-data` | `/app/data/mcp-audit.jsonl` |
| `MIKROTIK_ROUTER_AUDIT_LOG` | Автоматически создавать на роутере отдельный лог `mcpdisk` + правила `[MCP-LOG]` в `/system/logging` | `true` |
| `MIKROTIK_ROUTER_LOG_MARKERS` | Писать `[MCP]`-метки через `/log/info` / `/log/warning` при мутациях | `true` |
| `TZ` | Часовой пояс | `UTC` |
