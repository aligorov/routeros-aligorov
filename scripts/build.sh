#!/usr/bin/env bash
# Сборка каталога стора из apps/*/app.yaml:
#   store.yaml   — каталог для RouterOS (YAML-массив приложений)
#   default.yaml — копия (совместимость с путями стора вида /default.yaml)
#   index.html   — человекочитаемый вид для браузера
set -euo pipefail
cd "$(dirname "$0")/.."
BASE_URL="${BASE_URL:-https://aligorov.github.io/routeros-aligorov}"

# используем .venv из validate.sh (нужен только pyyaml); создаём при отсутствии
if [ ! -x .venv/bin/python3 ]; then
    python3 -m venv .venv
    .venv/bin/pip install --quiet --upgrade pip
    .venv/bin/pip install --quiet pyyaml
fi

.venv/bin/python3 - "$BASE_URL" <<'PY'
import html
import os
import shutil
import sys
import glob

import yaml

base_url = sys.argv[1]
apps = []

for path in sorted(glob.glob("apps/*/app.yaml")):
    app_name = os.path.basename(os.path.dirname(path))
    if app_name.startswith("_"):
        continue  # шаблон в стор не попадает
    with open(path) as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict) or "services" not in doc:
        sys.exit(f"ERROR: {path}: нет обязательного ключа services")
    # относительный icon -> абсолютный URL (RouterOS грузит иконку по сети)
    icon = doc.get("icon")
    if icon and not str(icon).startswith(("http://", "https://")):
        if not os.path.exists(os.path.join("apps", app_name, str(icon))):
            sys.exit(f"ERROR: {path}: не найден файл иконки apps/{app_name}/{icon}")
        doc["icon"] = f"{base_url}/apps/{app_name}/{icon}"
    apps.append((app_name, doc))

if not apps:
    sys.exit("ERROR: не найдено ни одного apps/*/app.yaml (кроме _template)")

header = (
    "# =============================================================\n"
    "#  СГЕНЕРИРОВАН scripts/build.sh — НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ\n"
    "#  Источники приложений: apps/*/app.yaml\n"
    "# =============================================================\n"
)
with open("store.yaml", "w") as f:
    f.write(header)
    yaml.safe_dump([doc for _, doc in apps], f,
                   allow_unicode=True, sort_keys=False, default_flow_style=False)
shutil.copyfile("store.yaml", "default.yaml")

# человекочитаемый вид для браузера
cards = []
for app_name, doc in apps:
    icon = doc.get("icon", "")
    icon_img = f'<img src="{html.escape(icon)}" width="64" height="64">' if icon else ""
    cards.append(
        f'<div class="card"><div class="ico">{icon_img}</div>'
        f'<div><h3>{html.escape(str(doc.get("name", app_name)))}</h3>'
        f'<p class="cat">{html.escape(str(doc.get("category", "")))}</p>'
        f'<p>{html.escape(str(doc.get("descr", "")))}</p></div></div>'
    )
index = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<title>routeros-aligorov app-store</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{{font-family:-apple-system,system-ui,sans-serif;background:#111418;color:#e5e7eb;margin:40px auto;max-width:720px}}
 h1{{font-size:1.4em}} .sub{{color:#9ca3af;margin-bottom:28px}}
 .card{{display:flex;gap:16px;background:#1b2027;border:1px solid #2a303a;border-radius:10px;padding:16px;margin-bottom:12px;align-items:center}}
 .card h3{{margin:0 0 4px}} .cat{{color:#60a5fa;font-size:.8em;margin:0 0 6px;text-transform:uppercase}}
 .ico img{{border-radius:10px}}
 code{{background:#1b2027;padding:2px 6px;border-radius:5px}}
</style></head><body>
<h1>routeros-aligorov — app-store</h1>
<p class="sub">Каталог контейнеров для MikroTik RouterOS. Подключение:
<code>{base_url}/store.yaml</code></p>
{''.join(cards)}
</body></html>
"""
with open("index.html", "w") as f:
    f.write(index)

print(f"OK: {len(apps)} прил. -> store.yaml, default.yaml, index.html")
PY
