# A-awg-proxy

[timbrs/amneziawg-mikrotik-c](https://github.com/timbrs/amneziawg-mikrotik-c) (`awg-proxy`) — компактный UDP-прокси на C11 (~100 КБ, без зависимостей), который «переодевает» пакеты штатного WireGuard-интерфейса RouterOS в формат **AmneziaWG 1.0 / 1.5 / 2.0 / 3.0 / 3.1**.

```
Устройства в сети ──> MikroTik WireGuard ──UDP :51820──> [awg-proxy] ──AWG/UDP──> сервер AmneziaWG
                      (шифрует трафик)                   (маскирует)
```

- Образ: `ghcr.io/timbrs/awg-proxy:latest` (`arm64`, `arm`, `amd64`, ~0.1 МБ).
  > Для роутеров с ARMv5 (**hEX refresh E50UG, hEX S 2025 E60iUGS, hAP ax S E62iUGS**) укажите тег `ghcr.io/timbrs/awg-proxy:latest-armv5`!
- Порт прослушивания: `51820/udp` (`AWG_LISTEN=:51820`).
- Веб-конфигуратор команд RouterOS (генерация из `.conf` AmneziaVPN или WARP):
  https://timbrs.github.io/amneziawg-mikrotik-c/conf3.0.html

## Быстрая настройка после установки из App Store

1. Установите `A-awg-proxy` через **Winbox → App** (или `/app`).
2. Откройте настройки приложения → **Environment** и заполните параметры из вашего `.conf`-файла:
   - `AWG_REMOTE` — адрес и порт (или диапазон/список портов) сервера: `1.2.3.4:51820` или `host:20150-20299`
   - `AWG_SERVER_PUB` — `PublicKey` из секции `[Peer]`
   - `AWG_CLIENT_PUB` — публичный ключ вашего штатного WireGuard-интерфейса на MikroTik:
     `/interface/wireguard/get [find name=wg-awg] public-key`
   - `AWG_JC`, `AWG_JMIN`, `AWG_JMAX`, `AWG_S1`, `AWG_S2`, `AWG_H1`–`AWG_H4` — значения обфускации из `[Interface]`
   - при необходимости (AWG 1.5 / 2.0 / 3.0 / 3.1): `AWG_S3`, `AWG_S4`, `AWG_I1`–`AWG_I5`, `AWG_HEADER_PROTECTION_KEY`, `AWG_RANDOM_TRAILERS`, `AWG_DISABLE_COOKIES`
3. Создайте штатный WireGuard-интерфейс на роутере и направьте peer на контейнер (`<ip-контейнера>` или IP veth-интерфейса приложения, порт `51820`):
   ```routeros
   /interface/wireguard/add name=wg-awg private-key="ВАШ_PRIVATE_KEY" listen-port=12429
   /interface/wireguard/peers/add interface=wg-awg public-key="AWG_SERVER_PUB" \
       preshared-key="PRESHARED_KEY_ЕСЛИ_ЕСТЬ" endpoint-address=<ip-контейнера> endpoint-port=51820 \
       allowed-address=0.0.0.0/0 persistent-keepalive=25
   /ip/address/add address=<ВАШ_TUNNEL_IP> interface=wg-awg
   /ip/firewall/nat/add chain=srcnat action=masquerade out-interface=wg-awg
   ```
   *(Узнать IP, выданный `/app` контейнеру, можно в `/container print` / `/interface/veth/print`.)*

## Переменные окружения (`AWG_*`)

| Переменная | Назначение | Дефолт в манифесте |
|---|---|---|
| `AWG_MODE` | Режим: `normal` (клиент), `reverse` (1:1), `server` (хаб 1:N) | `normal` |
| `AWG_LISTEN` | Адрес и порт приёма UDP | `:51820` |
| `AWG_REMOTE` | Адрес(а) и порт(ы) сервера | `engage.cloudflareclient.com:2408,500,1701,4500` |
| `AWG_SERVER_PUB` | PublicKey сервера (44 симв. base64) | ключ Cloudflare WARP |
| `AWG_CLIENT_PUB` | PublicKey локального WireGuard-интерфейса (или fallback в `server`) | заглушка `AAA...=` |
| `AWG_JC`, `AWG_JMIN`, `AWG_JMAX` | Число и размер мусорных пакетов (`Jc`, `Jmin`, `Jmax`) | `4`, `40`, `70` |
| `AWG_S1`–`AWG_S4` | Паддинг init/response/cookie/transport (`S3`/`S4` для v2) | `0` |
| `AWG_H1`–`AWG_H4` | Подмена типов пакетов (число или диапазон `min-max` для v2) | `1`, `2`, `3`, `4` |
| `AWG_I1`–`AWG_I5` | CPS-шаблоны (v1.5/v2/v3), опц. | — |
| `AWG_HEADER_PROTECTION_KEY` | Ключ шифрования заголовков v3 (44 base64 или 64 hex), опц. | — |
| `AWG_RANDOM_TRAILERS`, `AWG_DISABLE_COOKIES` | Флаги AmneziaWG 3.1 (`on`/`off`) | `"off"` |
| `AWG_CLIENT_PUBS`, `AWG_CLIENT_PUBS_FILE` | Список ключей direct-клиентов в режиме `server` (например `/etc/awg-proxy/client-pubs.txt`) | — |
| `AWG_STATE_FILE` | Файл сохранённого состояния IPv4/IPv6 и рабочего endpoint WARP | `/etc/awg-proxy/awg-proxy.state` |
| `AWG_SRC_PORT`, `AWG_TIMEOUT`, `AWG_DNS_REFRESH` | Исходящий порт, таймаут handshake (с), рефреш DNS (с) | `random`, `60`, `60` |
| `AWG_PORT_ROTATE`, `AWG_PORT_ROTATE_SOFT`, `AWG_HE_DELAY` | Ротация портов по времени и фора IPv4 (мс) | `30m-2h`, `auto`, `250` |
| `AWG_LOG_LEVEL`, `AWG_STATS` | Логирование (`none`/`error`/`info`/`debug`) и период статистики (с) | `info`, `0` |
| `AWG_NO_GRO`, `AWG_NO_GSO`, `AWG_NO_DF`, `AWG_AUTO_CPU` | Управление UDP GRO/GSO, битом DF и авто-привязкой к CPU | `0`, `0`, `0`, `"on"` |

Подробная справка по всем переменным (включая `AWG_FB_*` для цепочки отката и `AWG_RT`/`AWG_RPS` при `privileged=yes`): [docs/env.md](https://github.com/timbrs/amneziawg-mikrotik-c/blob/main/docs/env.md).

## Том (`awg-state`)

Том `awg-state` монтируется в `/etc/awg-proxy`:
- хранит файл состояния `awg-proxy.state` (выбранный рабочий endpoint для Cloudflare WARP и предпочтение IPv4/IPv6 переживают перезапуск контейнера);
- в режиме `server` сюда можно положить `client-pubs.txt` и указать `AWG_CLIENT_PUBS_FILE=/etc/awg-proxy/client-pubs.txt`.

## Проверка

- Логи контейнера: **Winbox → App → A-awg-proxy → Logs** (должно быть `listening on :51820` и `connected to ...`).
- На роутере: `/interface/wireguard/peers/print` — у пира должен появиться `last-handshake` и счётчики `rx`/`tx`.
