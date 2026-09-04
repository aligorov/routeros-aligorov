# A-mihomo-proxy — через стор, с полной маршрутизацией

[mihomo-proxy-ros](https://github.com/Medium1992/mihomo-proxy-ros) как приложение
App Store. Контейнер ставится из стора, маршрутизация (TPROXY/mangle) —
скриптом подготовки роутера, выполните его **один раз**.

## Установка (2 шага)

**Шаг 1 — подготовка роутера** (Winbox → New Terminal, по одной строке):

```
/tool fetch url="https://aligorov.github.io/routeros-aligorov/apps/a-mihomo-proxy/router-setup.rsc" dst-path=router-setup.rsc
/import router-setup.rsc
```

Скрипт идемпотентный (повтор — безопасен). Он создаёт: NAT-фиксы GitHub, veth
`MihomoProxyRoS` (192.168.255.2/30), таблицу маршрутизации, mangle-правила,
DNS-исключения, address-list YouTube/NTC. Если списки `LAN`/`WAN` только что
создались — добавьте в них интерфейсы (Interfaces → Interface List Members).

> Если ранее ставили скриптом автора: его контейнер удалите
> (`/container remove [find comment="MihomoProxyRoS"]`), остальное
> (veth/правила) совпадает и остаётся — шаг 1 можно пропустить.

**Шаг 2 — приложение:** Winbox → App → `A-mihomo-proxy` → Install → ввести
секрет `ui-secret`. Контейнер подключится к готовому veth `MihomoProxyRoS`.

## После установки

| Что | Где |
|---|---|
| Веб-панель (визард) | `http://<ip-роутера>:8090` или `http://192.168.255.2:80` — вход `admin`/`admin`, сменить пароль сразу |
| Дашборд mihomo | `http://<ip-роутера>:9090/ui/` — секрет = `ui-secret` |
| Прокси-сервер (LINK1/SUB_LINK1) | Winbox → App → A-mihomo-proxy → **Environment** → добавить `LINK1=vless://...` (или `SUB_LINK1=https://подписка`) → перезапустить приложение |
| Что гонять через прокси | `/ip firewall address-list` список `MihomoProxyRoS` (добавить домены/IP); предустановлены YouTube, NTC, Twitch (DNS FWD) |

Переменные `LINK1`/`SUB_LINK1` в манифест не вшиты специально: ссылки на
прокси — секреты, вводятся на роутере.

## Требования

RouterOS 7.21+ (arm64), пакет `container`, `device-mode container=yes`,
свободно ≥80 МБ диска. Проверено: образ arm64 ✅, ~28 МБ.
