#!/usr/bin/env python3
"""Валидация манифестов apps/*/app.yaml и store.yaml по схеме RouterOS."""
import glob
import json
import os
import sys

import yaml
from jsonschema.validators import validator_for

SCHEMA_PATH = "schemas/routeros-app-yaml.schema.json"


def load_validator():
    with open(SCHEMA_PATH) as f:
        schema = json.load(f)
    cls = validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def check_manifest(validator, path, doc):
    """Возвращает список ошибок одного документа."""
    errors = [f"{err.message} (в {list(err.absolute_path) or 'корне'})"
              for err in validator.iter_errors(doc)]
    app = os.path.basename(os.path.dirname(path))
    icon = doc.get("icon") if isinstance(doc, dict) else None
    if icon and not str(icon).startswith(("http://", "https://")):
        if not os.path.exists(os.path.join("apps", app, str(icon))):
            errors.append(f"не найден файл иконки apps/{app}/{icon}")
    return errors


def main() -> int:
    validator = load_validator()
    total = 0

    manifests = sorted(glob.glob("apps/*/app.yaml"))
    if not manifests:
        print("FAIL: нет ни одного apps/*/app.yaml")
        return 1

    for path in manifests:
        if os.path.basename(os.path.dirname(path)).startswith("_"):
            print(f"SKIP {path} (шаблон)")
            continue
        with open(path) as f:
            doc = yaml.safe_load(f)
        errors = check_manifest(validator, path, doc if isinstance(doc, dict) else {})
        for e in errors:
            print(f"FAIL {path}: {e}")
        total += len(errors)
        if not errors:
            print(f"OK   {path}")

    if os.path.exists("store.yaml"):
        with open("store.yaml") as f:
            store = yaml.safe_load(f)
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

    if total:
        print(f"\nИТОГО ошибок: {total}")
    else:
        print("\nВсё валидно.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
