# A-amneziawg-mikrotik

Клиент и сервер **AmneziaWG 3.1** (`amneziawg-go` `v3.1.20260828` + `awg-quick` `v3.1.20260812`) для RouterOS со встроенным **WebUI (`:8092`)**, **QR-генератором**, **DNS-форвардером (`192.168.253.2:53`)**, **health-зондом (`:8081`)** для `/tool/netwatch` и **авто-синхронизацией маршрутов/доменов через REST API RouterOS**.

- Образ: `ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:1.1.0` (`arm64`, `amd64`, `arm/v7`).
- WebUI: `http://<ip-роутера>:8092` (кнопка **Open WebUI** в Winbox) или `http://192.168.253.2:8080`.
- Выделенный `veth`: `AmneziaWGRoS` (`192.168.253.2/30`, шлюз роутера `192.168.253.1`).
- Том: `awg-config` → `/etc/amnezia/amneziawg` (`*.conf` и `domains.txt`).

## Установка (2 шага)

**Шаг 1 — подготовка роутера** (Winbox → New Terminal, по одной строке):

```routeros
/tool fetch url="https://aligorov.github.io/routeros-aligorov/apps/a-amneziawg-mikrotik/router-setup.rsc" dst-path=awg-setup.rsc
/import awg-setup.rsc
```

Скрипт идемпотентный. Он создаёт:
- `veth` `AmneziaWGRoS` (`192.168.253.2/30`, gw `192.168.253.1`) и список `InAccept`;
- таблицу маршрутизации `AmneziaWGRoS` (`0.0.0.0/0 -> 192.168.253.2` + `blackhole` fallback);
- `mangle` для выборочной маршрутизации по `/ip/firewall/address-list` (`list=AmneziaWGRoS`) и правку `fasttrack`;
- `NXDOMAIN` для Apple Private Relay (`mask.icloud.com`, `doh.dns.apple.com`);
- заготовки `AWG_Server_DSTNAT` и Netwatch-пробы `AWG_Health` (`192.168.253.2:8081`, обе отключены по умолчанию).

Если списки `LAN`/`WAN` только что создались — добавьте в них интерфейсы (**Interfaces → Interface List**).

**Шаг 2 — приложение и конфиг:**
1. **Winbox → App → `A-amneziawg-mikrotik` → Install**.
2. Откройте **Open WebUI** (`http://<ip-роутера>:8092`) → вкладка **Конфиги (.conf)** или **Генератор / QR** → вставьте стандартный `.conf` из AmneziaVPN (ничего дописывать не нужно, CRLF исправится автоматически) и нажмите **Сохранить и применить**.
   - Альтернатива без UI: передайте base64-конфиг в `AWG_CONF_B64` или положите `*.conf` в том `awg-config`.

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
  -t ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:1.1.0 \
  --push apps/a-amneziawg-mikrotik/image
```
