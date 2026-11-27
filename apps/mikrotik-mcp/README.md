# A-mikrotik-mcp

Полнофункциональный мульти-роутерный **MCP-шлюз нового поколения (`mikrotik-mcp-server` v2.0.5)** для **MikroTik RouterOS 7.24+** по протоколам **REST API** (`/rest`) и **Binary API** (`8728`/`8729`), без использования SSH.

- Образ: `ghcr.io/aligorov/routeros-aligorov/mikrotik-mcp-server:2.0.5` (`linux/arm64`, `linux/amd64`, `linux/386`, `linux/arm/v7`; теги каналов `:2.0`, `:2` и `:latest`).
- Порт: `3000/tcp` (веб-дашборд `/dashboard`, Streamable HTTP MCP endpoint `/mcp` и проверка живости `/healthz`).
- Тома:
  - `mcp-config` → `/app/config` (опциональные `routers.yaml` для первичного импорта парка роутеров и `ca.pem` для TLS-верификации).
  - `mcp-data` → `/app/data` (хранит SQLite-БД `gateway.db` — единый источник настроек/профилей/политик, токен `.bearer_token`, снапшоты `/app/data/snapshots` и JSONL-аудит).

## Новые возможности версии 2.0.5 и 2.0.x:
1. **49 MCP-инструментов**:
   - `mikrotik_diagnose_route` (+ read-only `routing_route`): диагностика маршрутов `/routing/route` по IP/CIDR-префиксу и VRF/таблице (активные, ECMP, `immediate-gw`, отфильтрованные, недостижимые).
   - `mikrotik_analyze_firmware_changelog` и `include_changelog` в `mikrotik_fleet_updates`: анализ официальных changelog MikroTik (что уже исправлено vs ещё не исправлено на текущей прошивке, CVE и RouterBOOT BIOS).
   - `mikrotik_diagnostics`: добавлены роли STP (`stp_status`), состояние LACP-партнёров (`lacp_status`), а в `mikrotik_monitor_traffic` поддержан одиночный замер `once` через REST.
   - `mikrotik_manage_gateway_policy`: управление SQLite-настройками шлюза и SHA-256 Bearer-политиками доступа.
   - `mikrotik_security_audit`: Автоматический аудит безопасности с расчётом оценки защищённости 0–100 по 10+ критическим векторам и генерацией готовых команд устранения.
   - `mikrotik_discover_routers`: Автообнаружение роутеров сети через MNDP, LLDP, WireGuard, OSPF, BGP и DHCP-аренды с безопасным пробингом и авторегистрацией.
   - `mikrotik_config_snapshots`: Машина времени конфигураций `.rsc` с детекцией неполного экспорта (`truncated`, `#error exporting`), unified diffing и обязательным паролем для бинарных `.backup`.
   - `mikrotik_fleet_execute`: Canary/Safe Mode с проверками (`verify_after`/`verify_ping`) строго до `/safe-mode/release`, явным `commit_status` (`committed`/`rolled_back`/`unknown`), fail-closed валидацией (`highlight` + `import verbose=yes dry-run`) и прерыванием при неполном пре-снимке.
   - `mikrotik_topology_map` & `mikrotik_fleet_incidents`: Интерактивная карта топологии и проактивный мониторинг с реальными флагами VRRP (`master`/`backup`/`failure`/`invalid`) и сохранением инцидентов при сбое чтения логов.
   - `mikrotik_manage_cloud_and_zerotier`: Управление MikroTik Cloud DDNS, Back-To-Home VPN и ZeroTier.
   - Аппаратная диагностика: SFP DDM оптика, управление PoE-out, профилирование CPU (`/tool/profile`), топ-соединения conntrack.
2. **Встроенный Web Dashboard (`/dashboard`)**:
   - Графическая визуализация топологии, карточки аудита безопасности, просмотр снапшотов с diffing и панель инцидентов прямо в браузере.
3. **Надёжность, SQLite SSOT и RBAC**:
   - SQLite-БД (`/app/data/gateway.db`, `MCP_DB_PATH`) как единый источник настроек шлюза, профилей и SHA-256 политик доступа (мигрирует ENV/YAML при первом старте, затем восстанавливается из БД даже без ENV).
   - Разделение учётных записей чтения и записи (`MIKROTIK_READ_USERNAME` / `MIKROTIK_READ_PASSWORD` с политикой `read,api,rest-api`), очередь REST `1` запрос на пару `(устройство, учётка)`, учёт 60 с лимита REST и сверка состояния после таймаута записи.
   - Ограничение доступа к веб-интерфейсу по белому списку IP (`MCP_DASHBOARD_ALLOWED_IPS`, например `192.168.200.0/24,10.0.0.5`).
   - Поддержка Read-Only токенов (`MCP_READONLY_TOKENS`) для мониторинга без риска случайных изменений.
   - Блокировка команд перезагрузки и выключения (`MCP_DENY_POWER_ACTIONS=true`).

## Подготовка RouterOS перед запуском

На целевом MikroTik создайте пользователя с правами `rest-api` и `api` (и при желании отдельного read-only пользователя) и включите сервисы:

```rsc
/user/group/add name=mcp policy=read,write,test,ftp,api,rest-api,!local,!telnet,!ssh,!winbox
/user/add name=mcp group=mcp password="STRONG_PASSWORD"
# Опционально — отдельная учётка только для чтения (MIKROTIK_READ_USERNAME):
/user/group/add name=mcp-read policy=read,api,rest-api,!write,!local,!telnet,!ssh,!winbox
/user/add name=mcp-read group=mcp-read password="READONLY_PASSWORD"
/ip/service/set www-ssl disabled=no
/ip/service/set api-ssl disabled=no
```

Убедитесь также, что в firewall (`input`) разрешены подключения от подсети контейнеров (veth) к портам `443/tcp` и `8729/tcp` роутера.

## Установка и настройка

1. В **Winbox → App → App** нажмите **Update** (обновить каталог) и включите **`A-mikrotik-mcp`**.
2. В настройках приложения (**Environment**) укажите как минимум:
   - `MIKROTIK_USERNAME` и `MIKROTIK_PASSWORD` (должны совпадать с созданным пользователем в RouterOS);
   - `MIKROTIK_HOST` — оставьте `auto` (локальный роутер) или перечислите **несколько роутеров через запятую** с общим пользователем, например: `auto,10.10.20.1,192.168.88.1` или с именами `core=auto,branch1=10.10.20.1,office=https://192.168.88.1:443`;
   - `MCP_BEARER_TOKEN` — задайте свой длинный секретный токен или оставьте `auto` (случайный 48-символьный токен сгенерируется при первом старте и сохранится в `/app/data/.bearer_token`).
3. Для управления **несколькими роутерами с разными учётками/CA** положите файл `routers.yaml` (и при желании `ca.pem`) в каталог тома `mcp-config` на диске роутера (или добавьте профили через `mikrotik_manage_router_profile` с `persist=true` — они сохранятся в `/app/config/routers.yaml`).

## Подключение MCP-клиента

- URL: `http://<ip-роутера>:3000/mcp` (рекомендуется закрыть обратным прокси с TLS или подключаться внутри VPN/LAN)
- Заголовок: `Authorization: Bearer <ваш_MCP_BEARER_TOKEN>`
- Проверка статуса: `GET http://<ip-роутера>:3000/healthz`

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `MCP_BEARER_TOKEN` | Bearer-токен авторизации (`auto` — генерация в `/app/data/.bearer_token`) | `auto` |
| `MIKROTIK_HOST` | IP/домен роутера (`auto`) или список через запятую (`auto,10.10.20.1`, `core=auto,branch=https://10.10.20.1:443`) | `auto` |
| `MIKROTIK_ROUTER_ID` | Идентификатор профиля роутера в шлюзе | `local-router` |
| `MIKROTIK_USERNAME` / `MIKROTIK_PASSWORD` | Учётные данные пользователя RouterOS (`api,rest-api`) | `mcp` / `change-me-router-password` |
| `MIKROTIK_READ_USERNAME` / `MIKROTIK_READ_PASSWORD` | Опциональная раздельная учётка чтения (`read,api,rest-api`) | `""` |
| `MCP_DB_PATH` | SQLite-БД настроек, профилей и SHA-256 политик доступа | `/app/data/gateway.db` |
| `MIKROTIK_TRANSPORT_PREF` | Приоритет транспорта: `auto` \| `rest` \| `api` | `auto` |
| `MIKROTIK_REST_PROTOCOL` / `MIKROTIK_REST_PORT` | Протокол (`https`/`http`) и порт REST API | `https` / `443` |
| `MIKROTIK_API_TLS` / `MIKROTIK_API_PORT` | TLS (`true`/`false`) и порт Binary API | `true` / `8729` |
| `MIKROTIK_TLS_VERIFY` | Проверять TLS-сертификат роутера (при `ca.pem` можно `true`) | `false` |
| `MCP_PORT` / `MCP_PATH` | Порт и URL-путь HTTP MCP endpoint | `3000` / `/mcp` |
| `MCP_ALLOWED_HOSTS` | Разрешённые HTTP `Host` (`*`, `*.routingthecloud.com`, или конкретные домены/IP; `127.0.0.1` и `localhost` разрешены всегда) | `*` |
| `MCP_DASHBOARD_ALLOWED_IPS` | Белый список IP/CIDR для `/dashboard` и `/api/dashboard/*` | `""` |
| `MCP_TRUSTED_PROXIES` | Доверенные IP/CIDR обратного прокси для `X-Forwarded-For` / `X-Real-IP` | `""` |
| `MCP_READONLY_TOKENS` | Read-Only Bearer-токены (`mikrotik:read`, без мутаций и выгрузки секретов) | `""` |
| `MCP_DENY_POWER_ACTIONS` | Запретить `reboot`, `shutdown` и `reset-configuration` во всех инструментах | `"false"` |
| `MCP_AUDIT_LOG_PATH` | Файл JSONL-аудита вызовов MCP внутри тома `mcp-data` | `/app/data/mcp-audit.jsonl` |
| `MIKROTIK_ROUTER_AUDIT_LOG` | Автоматически создавать на роутере отдельный лог `mcpdisk` + правила `[MCP-LOG]` в `/system/logging` | `true` |
| `MIKROTIK_ROUTER_LOG_MARKERS` | Писать `[MCP]`-метки через `/log/info` / `/log/warning` при мутациях | `true` |
| `TZ` | Часовой пояс | `UTC` |
