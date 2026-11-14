# A-amneziawg-mikrotik

[wiktorbgu/amneziawg-mikrotik](https://hub.docker.com/r/wiktorbgu/amneziawg-mikrotik) — полноценный клиент и сервер **AmneziaWG (включая AWG 3.1)** на базе Alpine + OpenRC + `amneziawg-go` + `awg-quick` внутри контейнера RouterOS.

- Образ: `docker.io/wiktorbgu/amneziawg-mikrotik:latest` (`arm64`, `arm/v7`, `arm/v5`, `amd64`; ~10.1 МБ сжато).
- Порт: `51821:51820/udp` (используется в серверном режиме или для входящего проброса).
- Healthcheck: `/bin/bash /data/healthcheck.sh` (проверяет вывод `/usr/bin/awg`).

> В отличие от `A-awg-proxy` (который лишь обфусцирует трафик штатного WireGuard роутера), этот контейнер поднимает сам интерфейс `amneziawg-go` и маршрутизацию/NAT через `awg-quick` внутри контейнера — подходит для двусторонних туннелей, client- и server-режима.

## Том и конфигурационные файлы

- Том `awg-config` → `/etc/amnezia/amneziawg`.
- При старте OpenRC-сервис `/etc/init.d/wg-quick` автоматически запускает `awg-quick up` для каждого `*.conf` с секцией `[Interface]` в `/etc/amnezia/amneziawg/`.
- При запуске `/data/pre_up.sh` автоматически создаёт `/dev/net/tun` и исправляет заголовок `/etc/resolv.conf` для `resolvconf`, а `/entrypoint.sh` очищает конфликтующие `ip rule` для RouterOS 7.22+.

> **ВАЖНО:** файлы `*.conf` **обязательно должны иметь Unix-концы строк (LF)**! Файлы с CRLF (Windows) не запустятся.

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `LOG_LEVEL` | Уровень логирования | `error` |
| `WG_QUICK_USERSPACE_IMPLEMENTATION` | Userspace-реализация AmneziaWG | `amneziawg-go` |
| `TZ` | Часовой пояс внутри контейнера | `UTC` |

## Пример конфига: клиент (Client Mode)

Положите файл `awg.conf` (в формате LF) в смонтированный том `awg-config` (`/etc/amnezia/amneziawg/awg.conf`). Имя интерфейса в `PostUp`/`PostDown` (например, `eth0` или имя veth контейнера — проверьте внутри через `ip a`) должно соответствовать veth-интерфейсу контейнера:

```ini
[Interface]
PrivateKey = ВАШ_PRIVATE_KEY
Address = 10.10.10.2/24
MTU = 1420
Jc = 6
Jmin = 50
Jmax = 1000
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

PostUp = iptables -t nat -A POSTROUTING -o %i -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE
PostUp = iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

Table = awg
PostUp = ip rule add priority 300 from all iif eth0 lookup awg || true
PostDown = ip rule del from all iif eth0 lookup awg || true

[Peer]
PublicKey = SERVER_PUBLIC_KEY
PresharedKey = PRESHARED_KEY
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
Endpoint = SERVER_IP_OR_DNS:PORT
```

*(Если используете оригинальный AWG-сервер, значения `S1`, `S2`, `H1`–`H4` должны в точности совпадать с серверными. Для RouterOS 7.20+ имя интерфейса внутри контейнера может совпадать с именем veth вместо `eth0` — уточните командой `ip link` в shell контейнера.)*

## Пример конфига: сервер (Server Mode)

Положите `awg0.conf` в `/etc/amnezia/amneziawg/awg0.conf`:

```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = SERVER_PRIVATE_KEY
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 146
S2 = 42
H1 = 532916466
H2 = 2096090865
H3 = 406337014
H4 = 57583056

PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PostUp = iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

Table = awg
PostUp = ip rule add priority 300 from all iif eth0 lookup awg || true
PostDown = ip rule del from all iif eth0 lookup awg || true

[Peer]
PublicKey = CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
```

Входящий порт пробрасывается стором (`51821:51820/udp`) или правилом dst-nat на роутере.

## Проверка состояния

```routeros
/container print where running
/container shell 0
```
Внутри контейнера выполните `awg` — отобразятся активный интерфейс, параметры обфускации и `latest handshake`.
