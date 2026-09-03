# routeros-aligorov — личный app-store для MikroTik RouterOS

Собственный каталог контейнерных приложений в формате RouterOS 7.21+ (раздел **App** в Winbox).
Репозиторий публичный, каталог публикуется на GitHub Pages:

```
https://aligorov.github.io/routeros-aligorov/store.yaml
```

## Подключение стора на роутере

Требования: RouterOS 7.21+ (лучше 7.22+), установленный пакет `container`, у роутера есть
интернет и рабочий DNS (нужны доступ к `github.io` — стор, и к registry образов — `docker.io` / `ghcr.io`).
Тома контейнеров пишутся на диск: на роутерах без USB это NAND — рекомендуется USB-накопитель.

**Winbox:** App → Settings → поле **App Store Urls** → добавить
`https://aligorov.github.io/routeros-aligorov/store.yaml` → OK. Список приложений обновится.

**CLI:** `/app/settings print` — посмотреть текущие настройки, затем
`/app/settings set app-store-urls="https://aligorov.github.io/routeros-aligorov/store.yaml"`
(имя поля сверяйте по `print` в вашей версии RouterOS).

## Как добавить свой контейнер

1. Создать заготовку:
   ```sh
   ./scripts/new-app.sh my-app "Моё приложение"
   ```
2. Отредактировать `apps/my-app/app.yaml` — внутри подробные комментарии по всем полям
   (порты, переменные окружения, тома, inline-конфиги, секреты).
3. Положить `apps/my-app/icon.png` (квадратная, от 128×128; плейсхолдер уже там).
4. Пересобрать каталог и проверить:
   ```sh
   ./scripts/build.sh      # пересобирает store.yaml / default.yaml / index.html
   ./scripts/validate.sh   # проверка по официальной JSON-схеме RouterOS
   ```
5. Закоммитить и запушить:
   ```sh
   git add -A && git commit -m "add my-app" && git push
   ```
   Через ~1 минуту GitHub Pages обновится — приложение появится в App Store на роутере.

## Свои образы (GHCR)

Стор ссылается на образы в registry. Для своих контейнеров используйте GHCR:

1. Разово войти в registry (токен с правом `write:packages`:
   https://github.com/settings/tokens):
   ```sh
   echo <GHCR_TOKEN> | docker login ghcr.io -u aligorov --password-stdin
   ```
2. Собрать и запушить (нативная arm64-сборка для роутера):
   ```sh
   ./scripts/ghcr-push.sh /путь/к/исходникам my-app 1.0.0
   # -> ghcr.io/aligorov/routeros-aligorov/my-app:1.0.0
   ```
3. Указать образ в `apps/my-app/app.yaml`:
   ```yaml
   image: ghcr.io/aligorov/routeros-aligorov/my-app:1.0.0
   ```

Образы публично скачиваемы — собирайте Dockerfile так, чтобы внутрь не попадали
`.env`, ключи и дампы.

## Безопасность

- Репозиторий **публичный**: никаких паролей, ключей, внутренних IP и доменов
  в `app.yaml`, README и иконках.
- Пароли по умолчанию — только заглушки (`changeme`), менять после установки
  (env меняется через `/app` → приложение → редактирование, затем перезапуск).
- Для настоящих секретов — механизм `secrets:` и плейсхолдеры `[secret:name]`
  (значение вводится при установке, в репозитории не хранится). Пример — в шаблоне.
- `auto-update: false` — обновления контролируемо, тегом образа.

## Структура

```
store.yaml                 # СГЕНЕРИРОВАН build.sh — каталог для RouterOS (не редактировать)
apps/<имя>/app.yaml        # манифест приложения (источник истины)
apps/<имя>/icon.png        # иконка в каталоге Winbox
apps/<имя>/README.md       # заметки по приложению
apps/_template/            # шаблон нового приложения (в стор не попадает)
schemas/…schema.json       # официальная JSON-схема манифеста RouterOS-приложения
scripts/build.sh           # сборка store.yaml + default.yaml + index.html из apps/*/
scripts/validate.sh        # валидация всех манифестов по схеме
scripts/new-app.sh         # создать новое приложение из шаблона
scripts/ghcr-push.sh       # сборка arm64-образа и пуш в GHCR
```

## Что уже есть в сторе

| Приложение | Что это | Проверка |
|---|---|---|
| `vpn-manager` | VPN-менеджер: админка + PostgreSQL + FreeRADIUS, синк с AD, провижининг WG/OpenVPN/VLESS на MikroTik, портал пользователей | после установки открыть `http://<ip-роутера>:3000`, вход admin + секрет `admin-password` |
| `demo-nginx` | nginx — проверка работоспособности стора end-to-end | после установки открыть `http://<ip-роутера>:8080` |

## Полезное

- Схема манифеста: `schemas/routeros-app-yaml.schema.json` (взята с
  https://tikoci.github.io/restraml/routeros-app-yaml-schema.latest.json)
- Пример чужого стора: https://routeros.horza.org
- Человекочитаемый вид своего стора: https://aligorov.github.io/routeros-aligorov/
