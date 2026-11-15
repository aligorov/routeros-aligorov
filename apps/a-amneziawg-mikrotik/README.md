# A-amneziawg-mikrotik

Клиент и сервер **AmneziaWG 3.1** (`amneziawg-go v3.1.20260828` + `awg-quick v3.1.20260812`) для **MikroTik RouterOS (`/app`)** с современным **WebUI (`:8092`)**, одновременной работой нескольких туннелей (**Multi-Tunnel**), автоматическим переключением (**Auto-Failover**), маршрутизацией по **GeoSite / GeoIP**, встроенным **DoH DNS-форвардером (`:53`)**, **Telegram-уведомлениями** и синхронизацией с **RouterOS REST API**.

- **Образ:** `ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:1` (`v1.4.1`, `linux/arm64`)
- **WebUI:** `http://<ip-роутера>:8092` (кнопка **Open WebUI** в Winbox)
- **Сеть:** `/app` автоматически создаёт выделенный `veth` (без ручной подготовки интерфейсов)
- **Том:** `awg-config` → `/etc/amnezia/amneziawg` (`*.conf`, `.active`, `settings.json`, `rules.conf`, `geo/`, `domains.txt`)
- **Порты:** `8092:8080/tcp` (WebUI), `51821:51820/udp` (AWG Server), внутри контейнера также `:53/udp+tcp` (DNS) и `:8081/tcp` (health-зонд туннеля)

---

## Возможности (v1.4.1)

- **Multi-Tunnel и приоритеты профилей** — загрузка любого числа `.conf` (drag-and-drop в браузере), порядок приоритетов (`#1` — Primary), одновременный подъём нескольких туннелей в отдельных таблицах (`awg`, `202+`, `210`), проверка конфликтов подсетей `Address` и переключение Primary в один клик.
- **Auto-Failover (`Cold Switch` и `Hot Standby`)** — контроль здоровья каждого профиля по `Hybrid` (`Handshake + TCP-probe`), только `Handshake` или только `TCP-probe`; настройка интервала, порога ошибок, cooldown и авто-возврата (**Failback**) на приоритет `#1`.
- **Правила маршрутизации и GeoSite / GeoIP** — поддержка баз `geosite.dat` и `geoip.dat` (по умолчанию из `Loyalsoldier/v2ray-rules-dat`) с автообновлением по расписанию; политика по умолчанию (`PROXY` / `DIRECT`), правила `PROXY` (основной или конкретный туннель `PROXY:<iface>`), `DIRECT`, `DROP`, готовые пресеты (Реклама → `DROP`, РФ → `DIRECT`, YouTube/Telegram → `PROXY`) и проверка маршрута для любого домена или IP.
- **DNS-форвардер + DoH (RFC 8484)** — локальный DNS на `:53` (UDP/TCP), раздельные **Proxy DNS** (строго через туннель с `fwmark`) и **Direct DNS**, плюс встроенный каталог из **179 DoH-серверов** (`dns.quic.best`, включая `w.quic.best`) с поддержкой fallback-цепочек.
- **Telegram-уведомления** — отправка алертов о старте, failover-переключениях, падениях и ежедневной сводки в ЛС, группу или топик форума (`message_thread_id`, с отдельным топиком для критических алертов); маршрут доставки до `api.telegram.org` (`Auto` / напрямую / через туннель) и поддержка зеркала Bot API.
- **Генератор / QR, Web-терминал и Логи** — генерация ключей и параметров обфускации AWG 3.1 (`Jc`, `S1`, `S2`), экспорт клиентских конфигов и QR-кодов, встроенный shell-терминал (`awg show`, `ip route`, диагностика) и полноэкранный просмотр логов с фильтром.
- **Интеграция с RouterOS** — health-эндпоинт `:8081` для `/tool/netwatch`, авто-синхронизация маршрутов `AllowedIPs` и DNS-доменов через RouterOS REST API.

---

## Интерфейс

### Статус туннелей, Multi-Tunnel и Failover
![Статус и Multi-Tunnel Failover](screenshots/status.png)

### Правила маршрутизации и GeoSite / GeoIP
![Правила и Geo-базы](screenshots/rules.png)

### Настройки DNS (DoH), Failover и Telegram-уведомлений
![Настройки DNS, Failover и Telegram](screenshots/settings.png)

---

## Установка и обновление

1. В **Winbox → App → App** нажмите **Update** (обновить каталог стора).
2. Выберите **`A-amneziawg-mikrotik`** и нажмите **Enable**.
   > Для принудительного обновления уже установленного контейнера под тем же тегом `:1`:
   > ```routeros
   > /app/disable A-amneziawg-mikrotik; /app/remove A-amneziawg-mikrotik; /app/cleanup; /app/enable A-amneziawg-mikrotik
   > ```
3. Откройте **Open WebUI** (`http://<ip-роутера>:8092`):
   - **Конфиги (.conf)** — загрузите или вставьте один или несколько `.conf`, задайте приоритет.
   - **Правила / Geo** — загрузите Geo-базы и при необходимости выберите пресеты (`РФ → DIRECT`, `Реклама → DROP` и др.).
   - **Настройки** — укажите Proxy/Direct DNS (или выберите из каталога DoH), настройте `Multi-Tunnel`, `Failover`, `Telegram` и `ROS_URL`.
   - *Без WebUI:* передайте конфиг в переменной `AWG_CONF_B64` (base64) или поместите `*.conf` в том `awg-config`.

---

## Выборочная маршрутизация в RouterOS (опционально)

Чтобы заворачивать в контейнер только нужные подсети/списки устройств с роутера, можно импортировать скрипт [`router-setup.rsc`](router-setup.rsc):

```routeros
/tool fetch url="https://aligorov.github.io/routeros-aligorov/apps/a-amneziawg-mikrotik/router-setup.rsc" dst-path=awg-setup.rsc
/import awg-setup.rsc
```

> RouterOS `/app` назначает контейнеру свой `veth` и IP автоматически (узнать актуальный IP можно в `/container/print` или **Winbox → Interfaces → VETH**). После импорта скрипта подставьте этот IP в `gateway=` маршрута `AmneziaWGRoS_default`, `host=` пробы Netwatch `AWG_Health` и `forward-to=` DNS-записей (вместо шаблонного `192.168.253.2`).

Что создаёт [`router-setup.rsc`](router-setup.rsc):
- таблицу маршрутизации `AmneziaWGRoS` (`0.0.0.0/0 → <ip-контейнера>` + `blackhole` fallback);
- правила `mangle` для маршрутизации трафика из `/ip/firewall/address-list` (`list=AmneziaWGRoS`);
- блокировку `NXDOMAIN` для Apple Private Relay (`mask.icloud.com`, `doh.dns.apple.com`);
- заготовки `AWG_Server_DSTNAT` (`51821/udp`) и Netwatch-пробы `AWG_Health` (`:8081`, выключены по умолчанию).

---

## Интеграция с RouterOS

- **REST API синк (маршруты и домены):** задайте `ROS_URL` (`https://<ip-шлюза>`, по умолчанию при установке через `/app` это `https://172.18.0.1`), `ROS_USER` и `ROS_PASS` в **Настройках** WebUI или в **Environment** Winbox. IP контейнера (`ROS_CONTAINER_IP`) определяется автоматически; в RouterOS у пользователя должна быть группа с политикой `read,write,api,rest-api` и разрешён сервис `www-ssl` (либо `rest-plain=yes` для `http://`) с подсети контейнера. Контроллер пропишет не-дефолтные подсети из `AllowedIPs` в `/ip/route` и домены в `/ip/dns/static`.
- **DNS без утечек:** форвардер `:53` контейнера отправляет Proxy-запросы строго через туннель (с `fwmark`, если включён `Proxy DNS строго через туннель`). Для перенаправления отдельных доменов с MikroTik:
  ```routeros
  /ip/dns/static/add name=ifconfig.me type=FWD forward-to=<ip-контейнера> match-subdomain=yes address-list=AmneziaWGRoS
  ```
- **Netwatch-проба (`:8081`):** при включении `/tool/netwatch/enable [find comment="AWG_Health"]` роутер отключит маршрут `AmneziaWGRoS_default` в случае падения туннеля и вернёт его при восстановлении (не путать с `:8080/health`, который отвечает за готовность самого WebUI).
- **Вся подсеть или Server Mode:**
  - входящий порт сервера: `/ip/firewall/nat/enable [find comment="AWG_Server_DSTNAT"]`;
  - завернуть конкретное устройство/подсеть через контейнер: `/routing/rule/add src-address=192.168.88.50/32 action=lookup table=AmneziaWGRoS`.

---

## Переменные окружения

Настройки также удобно редактировать прямо в WebUI (хранятся в `settings.json` тома `awg-config`), а переменные окружения задают начальные значения по умолчанию:

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `AWG_DEFAULT_POLICY` | Политика по умолчанию (`proxy` / `direct`) | `"proxy"` |
| `AWG_AUTO_ROUTE` | Авто-инъекция `MASQUERADE`, `TCPMSS`, `Table = awg`, `ip rule` (`on`/`off`) | `"on"` |
| `AWG_KILLSWITCH` | Включить `blackhole` при падении VPN (`on`/`off`) | `"on"` |
| `AWG_MULTI_TUNNEL` | Поднимать все включённые `.conf` одновременно (`on`/`off`) | `"off"` |
| `AWG_FAILOVER_MODE` | Авто-переключение (`off` / `switch` / `standby`) | `"off"` |
| `AWG_FAILOVER_TRIGGER` | Триггер failover (`hybrid` / `handshake` / `probe`) | `"hybrid"` |
| `AWG_CONF_B64` | Base64-содержимое `.conf` для старта без UI и файлов | `""` |
| `DNS_ENABLE` / `DNS_UPSTREAM` | DNS-форвардер (`on`/`off`) и базовые upstream-серверы | `"on"` / `"1.1.1.1:53,8.8.8.8:53"` |
| `UI_USER` / `UI_PASSWORD` | Basic Auth для WebUI (при пустом пароле — без авторизации) | `"admin"` / `""` |
| `ROS_URL` / `ROS_USER` / `ROS_PASS` | RouterOS REST API (`https://...`) для синка `AllowedIPs` и доменов | `""` |
| `ROS_CONTAINER_IP` / `ROS_ROUTE_TABLE` | IP контейнера для маршрутов/DNS и целевая таблица маршрутизации | авто / `main` |
| `TG_ENABLE` / `TG_BOT_TOKEN` / `TG_CHAT_ID` | Telegram-уведомления (можно настроить целиком из WebUI) | `""` |
| `TG_THREAD_ID` / `TG_ALERT_THREAD_ID` | ID топика форума Telegram (`0` — общий чат) | `"0"` |
| `AWG_HEALTH_MAX_HANDSHAKE_SEC` | Макс. возраст handshake для пробы `:8081` (`0` = не проверять) | `"0"` |
| `LOG_LEVEL` | Уровень логирования `amneziawg-go` (`verbose`, `error`, `silent`) | `"error"` |
| `TZ` | Часовой пояс (POSIX: `UTC`, `MSK-3`) | `"UTC"` |

---

## Сборка и публикация образа

```bash
# arm64 (роутеры MikroTik ARM64)
./scripts/ghcr-push.sh apps/a-amneziawg-mikrotik/image amneziawg-mikrotik 1

# мульти-арх сборка (arm64, amd64, arm/v7)
docker buildx build --builder multiarch \
  --platform linux/arm64,linux/amd64,linux/arm/v7 \
  -t ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:1.4.1 \
  -t ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:1 \
  --push apps/a-amneziawg-mikrotik/image
```
