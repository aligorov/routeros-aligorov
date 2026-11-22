# A-mikrotik-mcp

Полнофункциональный мульти-роутерный **MCP-шлюз нового поколения (`mikrotik-mcp-server` v2.0.3)** для **MikroTik RouterOS 7.24+** по протоколам **REST API** (`/rest`) и **Binary API** (`8728`/`8729`), без использования SSH.

- Образ: `ghcr.io/aligorov/routeros-aligorov/mikrotik-mcp-server:2.0.3` (`linux/arm64`, `linux/amd64`; теги каналов `:2.0`, `:2` и `:latest`).
- Порт: `3000/tcp` (веб-дашборд `/dashboard`, Streamable HTTP MCP endpoint `/mcp` и проверка живости `/healthz`).
- Тома:
  - `mcp-config` → `/app/config` (опциональные `routers.yaml` для управления парком роутеров и `ca.pem` для TLS-верификации).
  - `mcp-data` → `/app/data` (хранит автосгенерированный Bearer-токен `.bearer_token`, снапшоты конфигураций в `/app/data/snapshots` и JSONL-аудит).

## Новые возможности версии 2.0.0:
1. **46 MCP-инструментов**:
   - `mikrotik_security_audit`: Автоматический аудит безопасности с расчётом оценки защищённости 0–100 по 10+ критическим векторам и генерацией готовых команд устранения.
   - `mikrotik_discover_routers`: Автообнаружение роутеров сети через MNDP, LLDP, WireGuard, OSPF, BGP и DHCP-аренды с безопасным пробингом и авторегистрацией.
   - `mikrotik_config_snapshots`: Машина времени конфигураций `.rsc` с очисткой динамических баннеров, unified diffing и мгновенным откатом.
   - `mikrotik_fleet_diff` & `mikrotik_fleet_updates`: N-way сравнение дрейфа конфигураций парка с эталонным роутером и матрица обновлений RouterOS / RouterBOOT.
   - `mikrotik_topology_map`: Интерактивная карта топологии сети (Mermaid + JSON) с корреляцией L2/L3/WireGuard/VRRP/BGP/OSPF.
   - `mikrotik_fleet_incidents`: Проактивный мониторинг инцидентов (недоступность, BGP/VRRP флапы, устаревшие WG-хэндшейки, NAND износ).
   - `mikrotik_manage_cloud_and_zerotier`: Управление MikroTik Cloud DDNS, Back-To-Home VPN и ZeroTier.
   - Расширенная аппаратная диагностика: SFP DDM оптика, управление PoE-out, профилирование CPU (`/tool/profile`), топ-соединения conntrack.
2. **Встроенный Web Dashboard (`/dashboard`)**:
   - Графическая визуализация топологии, карточки аудита безопасности, просмотр снапшотов с diffing и панель инцидентов прямо в браузере.
3. **Безопасность и RBAC**:
   - Ограничение доступа к веб-интерфейсу по белому списку IP (`MCP_DASHBOARD_ALLOWED_IPS`, например `192.168.200.0/24,10.0.0.5`).
   - Поддержка Read-Only токенов (`MCP_READONLY_TOKENS`) для мониторинга без риска случайных изменений.
   - Блокировка команд перезагрузки и выключения (`MCP_DENY_POWER_ACTIONS=true`).

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
| `MIKROTIK_TRANSPORT_PREF` | Приоритет транспорта: `auto` \| `rest` \| `api` | `auto` |
| `MIKROTIK_REST_PROTOCOL` / `MIKROTIK_REST_PORT` | Протокол (`https`/`http`) и порт REST API | `https` / `443` |
| `MIKROTIK_API_TLS` / `MIKROTIK_API_PORT` | TLS (`true`/`false`) и порт Binary API | `true` / `8729` |
| `MIKROTIK_TLS_VERIFY` | Проверять TLS-сертификат роутера (при `ca.pem` можно `true`) | `false` |
| `MCP_PORT` / `MCP_PATH` | Порт и URL-путь HTTP MCP endpoint | `3000` / `/mcp` |
| `MCP_ALLOWED_HOSTS` | Разрешённые HTTP `Host` (`*`, `*.routingthecloud.com`, или конкретные домены/IP; `127.0.0.1` и `localhost` разрешены всегда) | `*` |
| `MCP_AUDIT_LOG_PATH` | Файл JSONL-аудита вызовов MCP внутри тома `mcp-data` | `/app/data/mcp-audit.jsonl` |
| `MIKROTIK_ROUTER_AUDIT_LOG` | Автоматически создавать на роутере отдельный лог `mcpdisk` + правила `[MCP-LOG]` в `/system/logging` | `true` |
| `MIKROTIK_ROUTER_LOG_MARKERS` | Писать `[MCP]`-метки через `/log/info` / `/log/warning` при мутациях | `true` |
| `TZ` | Часовой пояс | `UTC` |
