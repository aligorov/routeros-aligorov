// Порт scripts/build.sh: пересборка store.yaml / default.yaml / index.html из apps/*/app.yaml
import { readdirSync, readFileSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { config } from "../config.js";

export interface AppEntry {
  dir: string; // имя папки приложения
  manifest: any;
}

export function readApps(repoDir = config.repoDir): AppEntry[] {
  const appsDir = path.join(repoDir, "apps");
  const out: AppEntry[] = [];
  for (const entry of readdirSync(appsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith("_") || entry.name.startsWith(".")) continue;
    const f = path.join(appsDir, entry.name, "app.yaml");
    if (!existsSync(f)) continue;
    const manifest = YAML.parse(readFileSync(f, "utf8"));
    if (!manifest || typeof manifest !== "object" || !manifest.services) {
      throw new Error(`${f}: нет обязательного ключа services`);
    }
    out.push({ dir: entry.name, manifest });
  }
  return out.sort((a, b) => a.dir.localeCompare(b.dir));
}

export interface GeneratedStore {
  "store.yaml": string;
  "default.yaml": string;
  "index.html": string;
}

/** Сборка содержимого store.yaml/default.yaml/index.html из списка приложений (fs-независимо). */
export function buildStoreFiles(
  apps: AppEntry[],
  baseUrl: string,
  iconExists: (dir: string, icon: string) => boolean = () => true,
): GeneratedStore {
  if (!apps.length) throw new Error("В apps/ нет ни одного приложения");

  const items = apps.map(({ dir, manifest }) => {
    const doc = structuredClone(manifest);
    const icon = doc.icon;
    if (icon && !String(icon).startsWith("http")) {
      if (!iconExists(dir, String(icon))) {
        throw new Error(`apps/${dir}: не найдена иконка ${icon}`);
      }
      doc.icon = `${baseUrl}/apps/${dir}/${icon}`;
    }
    return doc;
  });

  const header =
    "# =============================================================\n" +
    "#  СГЕНЕРИРОВАН (scripts/build.sh | service) — НЕ РЕДАКТИРОВАТЬ\n" +
    "#  Источники приложений: apps/*/app.yaml\n" +
    "# =============================================================\n";
  const storeYaml = header + YAML.stringify(items, { lineWidth: 0 });

  const esc = (s: any) =>
    String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const cards = apps
    .map(({ dir, manifest }) => {
      const icon = manifest.icon
        ? String(manifest.icon).startsWith("http")
          ? manifest.icon
          : `${baseUrl}/apps/${dir}/${manifest.icon}`
        : "";
      return (
        `<div class="card"><div class="ico">${icon ? `<img src="${esc(icon)}" width="64" height="64">` : ""}</div>` +
        `<div><h3>${esc(manifest.name ?? dir)}</h3><p class="cat">${esc(manifest.category ?? "")}</p>` +
        `<p>${esc(manifest.descr ?? "")}</p></div></div>`
      );
    })
    .join("\n");
  const indexHtml = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<title>routeros-aligorov app-store</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{font-family:-apple-system,system-ui,sans-serif;background:#111418;color:#e5e7eb;margin:40px auto;max-width:720px}
 h1{font-size:1.4em} .sub{color:#9ca3af;margin-bottom:28px}
 .card{display:flex;gap:16px;background:#1b2027;border:1px solid #2a303a;border-radius:10px;padding:16px;margin-bottom:12px;align-items:center}
 .card h3{margin:0 0 4px} .cat{color:#60a5fa;font-size:.8em;margin:0 0 6px;text-transform:uppercase}
 .ico img{border-radius:10px}
 code{background:#1b2027;padding:2px 6px;border-radius:5px}
</style></head><body>
<h1>routeros-aligorov — app-store</h1>
<p class="sub">Каталог контейнеров для MikroTik RouterOS. Подключение:
<code>${esc(baseUrl)}/store.yaml</code></p>
${cards}
</body></html>
`;
  return { "store.yaml": storeYaml, "default.yaml": storeYaml, "index.html": indexHtml };
}

export function rebuildStore(repoDir = config.repoDir, baseUrl = config.storeBaseUrl): number {
  const exists = (dir: string, icon: string) =>
    existsSync(path.join(repoDir, "apps", dir, icon));
  const generated = buildStoreFiles(readApps(repoDir), baseUrl, exists);
  writeFileSync(path.join(repoDir, "store.yaml"), generated["store.yaml"]);
  writeFileSync(path.join(repoDir, "default.yaml"), generated["default.yaml"]);
  writeFileSync(path.join(repoDir, "index.html"), generated["index.html"]);
  return readApps(repoDir).length;
}
