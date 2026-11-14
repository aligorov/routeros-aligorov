# A-amneziawg-mikrotik

Клиент и сервер **AmneziaWG 3.1** (`amneziawg-go` `v3.1.20260828` + `awg-quick` `v3.1.20260812`) для RouterOS со встроенным **WebUI (`:8092`)**, **мульти-профилями (`.conf`)**, **GeoSite / GeoIP + правилами `PROXY / DIRECT / DROP`**, вкладкой **Настройки**, **QR-генератором**, **DNS-форвардером (`:53`)**, **health-зондом (`:8081`)** для `/tool/netwatch` и **REST-синхронизацией RouterOS**.

- Образ: `ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:1` (`1.3.1`, `arm64`, `amd64`, `arm/v7`).
- WebUI: `http://<ip-роутера>:8092` (кнопка **Open WebUI** в Winbox).
- Сеть: RouterOS `/app` создаёт выделенный `veth` автоматически (без предварительного создания сети).
- Том: `awg-config` → `/etc/amnezia/amneziawg` (`*.conf`, `.active`, `settings.json`, `rules.conf`, `geo/`, `domains.txt`).

## Установка и обновление

**Шаг 1 — приложение из App Store:**
1. В **Winbox → App → App** нажмите **Update** (обновить каталог).
2. Выберите **`A-amneziawg-mikrotik`** (в описании должно быть `AmneziaWG 3.1 (v1.3.1)...`) и нажмите **Enable**.
   > Если ранее стояла старая версия под тем же тегом `:1`, выполните в терминале RouterOS `/app/disable A-amneziawg-mikrotik; /app/remove A-amneziawg-mikrotik; /app/cleanup; /app/enable A-amneziawg-mikrotik`, чтобы RouterOS скачал свежий образ.
3. Откройте **Open WebUI** (`http://<ip-роутера>:8092`):
   - **Конфиги (.conf)** — управление профилями (радио-переключатель активного конфига + `+ Новый профиль` + **QR-код**).
   - **Правила / Geo** — подгрузка баз `geosite.dat` / `geoip.dat` (по умолчанию из `Loyalsoldier/v2ray-rules-dat`), выбор режима по умолчанию (**PROXY** / **DIRECT**), быстрые пресеты (`Реклама → DROP`, `РФ → DIRECT`, `YouTube/Telegram → PROXY`) и тест правил.
   - **Настройки** — DNS (Proxy/Direct), `Auto-Route`, `Kill-Switch`, `Multi-Tunnel`, URL баз Geo и параметры RouterOS REST API.
   - Альтернатива без UI: переменная `AWG_CONF_B64` (base64-конфиг) в **Environment** или файлы `*.conf` в томе `awg-config`.

**Шаг 2 (опционально) — policy routing, Netwatch и DNS-форвардинг:**
В комплекте есть опциональный скрипт [`router-setup.rsc`](router-setup.rsc) для выборочной маршрутизации по `address-list=AmneziaWGRoS`, Netwatch-пробы и DNS-заглушек Apple Private Relay:

```routeros
/tool fetch url="https://aligorov.github.io/routeros-aligorov/apps/a-amneziawg-mikrotik/router-setup.rsc" dst-path=awg-setup.rsc
/import awg-setup.rsc
```

> Так как `app.yaml` не привязан к внешнему `veth AmneziaWGRoS` (чтобы приложение ставилось в один клик без подготовки), `/app` выделит контейнеру свой IP (посмотрите в `/container/print` или **Winbox → Interfaces → VETH**). После установки подставьте этот IP в `gateway=` маршрута `AmneziaWGRoS_default`, `host=` Netwatch `AWG_Health` и `forward-to=` DNS-записей (вместо заготовки `192.168.253.2`), либо используйте собственный gateway из `/app`.

Скрипт идемпотентный. Он создаёт:
- заготовку `veth` `AmneziaWGRoS` (`192.168.253.2/30`, gw `192.168.253.1`) и список `InAccept`;
- таблицу маршрутизации `AmneziaWGRoS` (`0.0.0.0/0 -> 192.168.253.2` + `blackhole` fallback);
- `mangle` для выборочной маршрутизации по `/ip/firewall/address-list` (`list=AmneziaWGRoS`) и правку `fasttrack`;
- `NXDOMAIN` для Apple Private Relay (`mask.icloud.com`, `doh.dns.apple.com`);
- заготовки `AWG_Server_DSTNAT` и Netwatch-пробы `AWG_Health` (`:8081`, обе отключены по умолчанию).

Если списки `LAN`/`WAN` только что создались — добавьте в них интерфейсы (**Interfaces → Interface List**).

## Максимальная интеграция с RouterOS

### 1. Авто-синхронизация маршрутов (`AllowedIPs`) и доменов через REST API
Укажите в **Winbox → App → A-amneziawg-mikrotik → Environment**:
- `ROS_URL`: `https://192.168.253.1` (или `http://192.168.253.1`, если включён `www`)
- `ROS_USER` / `ROS_PASS`: сервисный пользователь RouterOS (группа `write` + `api`/`rest`)

После этого контроллер `awg-ctl` автоматически:
- **Site-to-Site:** все не-дефолтные подсети из `AllowedIPs` (например `10.10.0.0/16`, `192.168.50.0/24`) прописывает в `/ip/route` с `gateway=192.168.253.2` и комментарием `awg-ctl:<iface>`;
- **Домены из WebUI:** список во вкладке **Домены / RouterOS** синхронизируется в `/ip/dns/static` как `type=FWD` → `192.168.253.2` (`address-list=AmneziaWGRoS`, `match-subdomain=yes`).

### 2. DNS без утечек
Встроенный DNS-форвардер слушает `192.168.253.2:53` (UDP+TCP) и отправляет запросы на `DNS = ...` из активного `.conf` (или `DNS_UPSTREAM`) строго через туннель. Для ручного форвардинга домена на роутере:
```routeros
/ip/dns/static/add name=ifconfig.me type=FWD forward-to=192.168.253.2 match-subdomain=yes address-list=AmneziaWGRoS
```

### 3. Failover через Netwatch
После первого успешного запуска туннеля можно включить автопереключение при падении handshake/интерфейса:
- При желании задайте `AWG_HEALTH_MAX_HANDSHAKE_SEC=180` (для client-режима).
- Включите пробу на роутере:
  ```routeros
  /tool/netwatch/enable [find comment="AWG_Health"]
  ```
  При недоступности `192.168.253.2:8081` роутер отключит маршрут `AmneziaWGRoS_default` (сработает `blackhole`), а при восстановлении — включит обратно.

### 4. Server Mode / Вся подсеть
- Включить входящий порт `51821/udp` для сервера: `/ip/firewall/nat/enable [find comment="AWG_Server_DSTNAT"]`
- Завернуть конкретное устройство или подсеть целиком: `/routing/rule/add src-address=192.168.88.50/32 action=lookup table=AmneziaWGRoS`

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `AWG_AUTO_ROUTE` | Авто-инъекция `MASQUERADE`, `TCPMSS`, `Table = awg`, `ip rule` (`on`/`off`) | `"on"` |
| `AWG_KILLSWITCH` | Включить `blackhole` и запрет утечек мимо туннеля (`on`/`off`) | `"on"` |
| `AWG_CONF_B64` | Base64-содержимое `.conf` для быстрого старта без UI/файлов | `""` |
| `DNS_ENABLE` / `DNS_UPSTREAM` | DNS-форвардер внутри туннеля (`:53`) и fallback-серверы | `"on"` / `1.1.1.1:53,8.8.8.8:53` |
| `UI_USER` / `UI_PASSWORD` | Basic Auth для WebUI (если пароль пустой — без авторизации) | `admin` / `""` |
| `ROS_URL` / `ROS_USER` / `ROS_PASS` | RouterOS REST API для авто-синка `AllowedIPs` и доменов | `""` |
| `AWG_HEALTH_MAX_HANDSHAKE_SEC` | Макс. возраст handshake (сек) для `/health` (`0` = не проверять) | `"0"` |
| `LOG_LEVEL` | Уровень логирования `amneziawg-go` (`verbose`, `error`, `silent`) | `error` |
| `TZ` | Часовой пояс (POSIX-строки: `UTC`, `MSK-3`) | `UTC` |

## Пересборка мульти-арх образа (`arm64`, `amd64`, `arm/v7`)

```bash
docker buildx build --builder multiarch \
  --platform linux/arm64,linux/amd64,linux/arm/v7 \
  -t ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:1.3.1 \
  -t ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:1 \
  -t ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:latest \
  --push apps/a-amneziawg-mikrotik/image
```
