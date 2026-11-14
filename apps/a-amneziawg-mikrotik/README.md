# A-amneziawg-mikrotik

Клиент и сервер **AmneziaWG 3.1** (`amneziawg-go` `v3.1.20260828` + `awg-quick` `v3.1.20260812`) для RouterOS `arm64`, собранный на базе Alpine 3.21 без OpenRC (вместо форка `wiktorbgu/amneziawg-mikrotik`).

- Образ: `ghcr.io/aligorov/routeros-aligorov/amneziawg-mikrotik:1.0.0` (`arm64`, ~8.1 МБ несжато).
- Выделенный `veth`: `AmneziaWGRoS` (`192.168.253.2/30`, шлюз роутера `192.168.253.1`).
- Том: `awg-config` → `/etc/amnezia/amneziawg`.

> **Что улучшено по сравнению с оригинальным образом:**
> - **Без OpenRC и `/sbin/init`** — логи `awg-quick` и `amneziawg-go` идут напрямую в `RouterOS → Container → Logs`, при остановке интерфейсы корректно гасятся по `SIGTERM`.
> - **Работает обычный `.conf` из AmneziaVPN** — не нужно вручную вписывать `PostUp`/`PostDown`, `Table = awg`, угадывать имя veth (`eth0` vs `AmneziaWGRoS`) или переводить CRLF в LF.
> - **Авто-маршрутизация и kill-switch** — контейнер сам определяет свой `veth`, поднимает `MASQUERADE`, `TCPMSS`, `ip rule priority 300 ... lookup awg` и `blackhole default metric 254` (управляются через `AWG_AUTO_ROUTE` / `AWG_KILLSWITCH`).
> - **Запуск без загрузки файлов** — конфиг можно передать прямо в `Environment` через `AWG_CONF_B64` (base64).

> Для роутеров на `arm/v5` или если нужен только прокси для штатного WireGuard RouterOS — используйте `A-awg-proxy` (~0.1 МБ).

## Установка (2 шага)

**Шаг 1 — подготовка роутера** (Winbox → New Terminal, по одной строке):

```routeros
/tool fetch url="https://aligorov.github.io/routeros-aligorov/apps/a-amneziawg-mikrotik/router-setup.rsc" dst-path=awg-setup.rsc
/import awg-setup.rsc
```

Скрипт идемпотентный (повторный запуск безопасен). Он создаёт:
- `veth` `AmneziaWGRoS` (`192.168.253.2/30`, gw `192.168.253.1`) и список `InAccept` (чтобы ответный трафик контейнера не уходил в петлю mangle);
- таблицу маршрутизации `AmneziaWGRoS` (`0.0.0.0/0 -> 192.168.253.2` + `blackhole` fallback);
- `mangle`-правила для выборочной маршрутизации по `/ip/firewall/address-list` (`list=AmneziaWGRoS`) и правку `fasttrack` (`connection-mark=no-mark`);
- заготовку `dst-nat` для Server Mode (`AWG_Server_DSTNAT`, по умолчанию выключена).

Если списки `LAN`/`WAN` только что создались — добавьте в них ваши интерфейсы (**Interfaces → Interface List**).

**Шаг 2 — приложение и конфиг:**
1. **Winbox → App → `A-amneziawg-mikrotik` → Install**. Контейнер автоматически подключится к `veth` `AmneziaWGRoS`.
2. Передайте ваш стандартный `.conf` (из AmneziaVPN / генератора) любым из двух способов:
   - **Без файлов (быстрее всего):** закодируйте `.conf` в base64 (`base64 -w0 awg.conf` на Linux или `base64 -i awg.conf | tr -d '\n'` на macOS) и вставьте строку в `Environment → AWG_CONF_B64`, затем перезапустите контейнер.
   - **Через том:** положите `*.conf` (LF или CRLF — не важно) в смонтированный том `awg-config` (`/etc/amnezia/amneziawg/awg0.conf`) и перезапустите контейнер.

## Куда направлять трафик (на RouterOS)

- **Выборочно по доменам/IP** (уже готово после `router-setup.rsc`):
  ```routeros
  /ip/firewall/address-list/add list=AmneziaWGRoS address=ifconfig.me
  ```
- **Вся подсеть / конкретный клиент через VPN** (в обход `address-list`):
  ```routeros
  /routing/rule/add src-address=192.168.88.50/32 action=lookup table=AmneziaWGRoS
  ```
- **Server Mode** (входящие подключения к серверу AmneziaWG снаружи на порт `51821/udp`):
  ```routeros
  /ip/firewall/nat/enable [find comment="AWG_Server_DSTNAT"]
  ```

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `AWG_AUTO_ROUTE` | Автоматически добавлять `MASQUERADE`, `TCPMSS`, `Table = awg`, `ip rule` (`on`/`off`) | `"on"` |
| `AWG_KILLSWITCH` | Добавлять `blackhole` и запрет утечек мимо туннеля (`on`/`off`) | `"on"` |
| `AWG_CONF_B64` | Base64-содержимое `.conf` (если не монтируете файл в `awg-config`) | `""` |
| `AWG_IFACE` | Имя интерфейса при запуске из `AWG_CONF_B64` / `AWG_CONF` | `awg0` |
| `AWG_LAN_IFACE` | Явное имя veth-интерфейса (по умолчанию определяется автоматически) | авто |
| `LOG_LEVEL` | Уровень логирования `amneziawg-go` (`verbose`, `error`, `silent`) | `error` |
| `WG_QUICK_USERSPACE_IMPLEMENTATION` | Userspace-реализация AmneziaWG | `amneziawg-go` |
| `TZ` | Часовой пояс (без `tzdata` работают POSIX-строки, например `UTC`, `MSK-3`) | `UTC` |

*(Если в вашем `.conf` уже прописаны собственные `PostUp` или `Table`, авто-инъекция не вмешивается и использует ваши правила как есть.)*

## Проверка состояния

```routeros
/container print where running
/container shell 0
```

Внутри контейнера:
- `awg` — активный интерфейс, параметры обфускации и `latest handshake`;
- `/usr/local/bin/healthcheck.sh` — проверка поднятых интерфейсов (код возврата `0` при успехе).

## Пересборка образа

Исходники образа лежат в [`image/`](image/):
```bash
./scripts/ghcr-push.sh apps/a-amneziawg-mikrotik/image amneziawg-mikrotik 1.0.0
```
