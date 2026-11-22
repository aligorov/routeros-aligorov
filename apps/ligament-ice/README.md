# A-ligament-ice

WebRTC STUN / TURN / TURNS TLS сервер (`coturn` + автоматический выпуск и продление сертификатов Let's Encrypt через `certbot`) для экосистемы **Ligament 2FA**, адаптированный под RouterOS `/app`.

- Образы (`linux/arm64`, `linux/amd64` для CHR):
  - `ghcr.io/aligorov/routeros-aligorov/ligament-ice-certbot:1` (`certbot`)
  - `ghcr.io/aligorov/routeros-aligorov/ligament-ice:1` (`coturn` + встроенный `turnserver.conf`)
- Порты:
  - `80/tcp` — HTTP-01 валидация Let's Encrypt (`certbot`)
  - `443/tcp`, `443/udp` — основной TURNS TLS / TURN UDP
  - `3478/tcp`, `3478/udp` — резервный STUN / TURN
  - `5349/tcp`, `5349/udp` — альтернативный TURNS TLS
- Тома:
  - `certs` → `/etc/letsencrypt` (в `certbot`) и `/etc/coturn/certs` (в `ice`)
  - `ice-config` → `/etc/coturn` (`turnserver.conf` копируется при первом старте и сохраняется между обновлениями)

## Установка и настройка

1. Создайте A-запись в DNS, указывающую на публичный IPv4 роутера (например `edge.example.com`).
2. **Освободите порт `80/tcp` и `443/tcp` на самом роутере** (если на них висят `/ip/service` `www`/`www-ssl` — перенесите их на другие порты или отключите).
3. В **Winbox → App → App** включите **`A-ligament-ice`**.
4. Отредактируйте переменные окружения **в обоих сервисах (`certbot` и `ice`)** и перезапустите приложение:
   - `REALM`: ваш реальный домен (одинаковый в `certbot` и `ice`!). Пока стоит `turn.example.com`, `certbot` пропускает запросы к Let's Encrypt, а `ice` стартует в обычном plain STUN/TURN режиме.
   - `ACME_EMAIL` (в `certbot`): email для уведомлений Let's Encrypt.
   - `TURN_PASSWORD` (в `ice`): замените `change-me` на надёжный пароль!
   - `EXTERNAL_IP` (в `ice`): `auto` (определяется автоматически через DNS) или явный публичный IPv4.

## Проброс диапазона UDP-портов релея (`49152-49250`)

Схема RouterOS `/app` не поддерживает диапазоны портов в `ports:`. Для входящего UDP-трафика WebRTC-релея (если пиры не пробивают исходящую conntrack-сессию) добавьте dst-nat правило на MikroTik (подставив IP `veth`-интерфейса контейнера из `/container print`):

```routeros
/ip/firewall/nat/add chain=dstnat in-interface-list=WAN protocol=udp dst-port=49152-49250 action=dst-nat to-addresses=<IP_КОНТЕЙНЕРА> comment="ligament-ice media relay"
```

## Переменные окружения

| Сервис | Переменная | Назначение | По умолчанию |
|---|---|---|---|
| `certbot`, `ice` | `REALM` | Доменное имя TURN-сервера (совпадает с DNS A-записью) | `turn.example.com` |
| `certbot` | `ACME_EMAIL` | Email для регистрации Let's Encrypt | `admin@example.com` |
| `ice` | `EXTERNAL_IP` | Внешний IPv4 (`auto` = автоопределение через `detect-external-ip`) | `auto` |
| `ice` | `TURN_USER` | Логин TURN | `ligament` |
| `ice` | `TURN_PASSWORD` | Пароль TURN (обязательно сменить!) | `change-me` |
| `ice` | `TURN_MIN_PORT` / `TURN_MAX_PORT` | Диапазон UDP-портов медиа-релея | `"49152"` / `"49250"` |
| `certbot`, `ice` | `TZ` | Часовой пояс | `UTC` |
