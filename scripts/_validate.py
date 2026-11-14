#!/usr/bin/env python3
"""Валидация манифестов apps/*/app.yaml и store.yaml по схеме RouterOS."""
import glob
import json
import os
import re
import sys

import yaml
from jsonschema.validators import validator_for

SCHEMA_PATH = "schemas/routeros-app-yaml.schema.json"

PORT_RE = re.compile(
    r"^(?:(\d+\.\d+\.\d+\.\d+|\[[a-zA-Z0-9]+\]):)?"
    r"(\d+|\[[a-zA-Z0-9]+\]):(\d+|\[[a-zA-Z0-9]+\])"
    r"(?:\/(tcp|udp))?(?::[^:\n\r]+)?(?::(tcp|udp))?$"
)


def load_validator():
    with open(SCHEMA_PATH) as f:
        schema = json.load(f)
    cls = validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def extract_host_ports(doc):
    """Возвращает список (ip, host_port, proto) для опубликованных портов приложения."""
    out = []
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return out
    for svc in services.values():
        if not isinstance(svc, dict):
            continue
        for item in svc.get("ports") or []:
            if isinstance(item, dict):
                pub = item.get("published")
                proto = item.get("protocol", "tcp")
                if pub is not None:
                    out.append(("0.0.0.0", str(pub), str(proto)))
            elif isinstance(item, str):
                m = PORT_RE.match(item.strip())
                if m:
                    ip, host, _cont, p1, p2 = m.groups()
                    proto = p1 or p2 or "tcp"
                    out.append((ip or "0.0.0.0", host, proto))
    return out


def check_manifest(validator, path, doc):
    """Возвращает список ошибок одного документа."""
    errors = [f"{err.message} (в {list(err.absolute_path) or 'корне'})"
              for err in validator.iter_errors(doc)]
    app = os.path.basename(os.path.dirname(path))
    icon = doc.get("icon") if isinstance(doc, dict) else None
    if icon and not str(icon).startswith(("http://", "https://")):
        if not os.path.exists(os.path.join("apps", app, str(icon))):
            errors.append(f"не найден файл иконки apps/{app}/{icon}")

    services = doc.get("services") if isinstance(doc, dict) else None
    if isinstance(services, dict):
        for svc_name, svc in services.items():
            env = svc.get("environment") if isinstance(svc, dict) else None
            if isinstance(env, dict):
                for k, v in env.items():
                    if isinstance(v, bool):
                        errors.append(
                            f"environment.{k} в сервисе '{svc_name}' имеет тип bool ({v}) — "
                            "оберните значение в кавычки (например, \"off\" / \"on\" / \"true\")"
                        )
    return errors


def main() -> int:
    validator = load_validator()
    total = 0

    manifests = sorted(glob.glob("apps/*/app.yaml"))
    if not manifests:
        print("FAIL: нет ни одного apps/*/app.yaml")
        return 1

    seen_names = {}
    seen_ports = {}

    for path in manifests:
        if os.path.basename(os.path.dirname(path)).startswith("_"):
            print(f"SKIP {path} (шаблон)")
            continue
        with open(path) as f:
            doc = yaml.safe_load(f)
        doc_dict = doc if isinstance(doc, dict) else {}
        errors = check_manifest(validator, path, doc_dict)

        app_name = doc_dict.get("name")
        if isinstance(app_name, str):
            key = app_name.lower()
            if key in seen_names:
                errors.append(f"дублирующееся имя приложения '{app_name}' (уже в {seen_names[key]})")
            else:
                seen_names[key] = path

        for ip, host, proto in extract_host_ports(doc_dict):
            pkey = (ip, host, proto)
            if pkey in seen_ports and seen_ports[pkey] != path:
                errors.append(
                    f"конфликт порта {ip}:{host}/{proto} (уже используется в {seen_ports[pkey]})"
                )
            else:
                seen_ports[pkey] = path

        for e in errors:
            print(f"FAIL {path}: {e}")
        total += len(errors)
        if not errors:
            print(f"OK   {path}")

    if os.path.exists("store.yaml"):
        with open("store.yaml", "rb") as f:
            store_bytes = f.read()
        store = yaml.safe_load(store_bytes.decode("utf-8"))
        if not isinstance(store, list):
            print("FAIL store.yaml: не YAML-массив")
            total += 1
        else:
            for item in store:
                name = item.get("name", "?") if isinstance(item, dict) else "?"
                for e in check_manifest(validator, f"store.yaml[{name}]", item):
                    print(f"FAIL store.yaml[{name}]: {e}")
                    total += 1
            print(f"OK   store.yaml ({len(store)} прил.)")

        if not os.path.exists("default.yaml"):
            print("FAIL default.yaml: файл отсутствует")
            total += 1
        else:
            with open("default.yaml", "rb") as f:
                if f.read() != store_bytes:
                    print("FAIL default.yaml: не совпадает со store.yaml")
                    total += 1
                else:
                    print("OK   default.yaml (совпадает со store.yaml)")

    if total:
        print(f"\nИТОГО ошибок: {total}")
    else:
        print("\nВсё валидно.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
