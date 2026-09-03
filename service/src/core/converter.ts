import YAML from "yaml";
import { checkImage, type ImageInfo } from "./registry.js";
import { assertValid } from "./validate.js";

export interface AddOptions {
  name?: string;
  descr?: string;
  category?: string;
  env?: Record<string, string>;
  /** Готовые записи портов: "8080:80/tcp:web" или "8080:80" */
  ports?: string[];
  ramHintMB?: number;
}

const SECRET_KEY_RE = /(PASS|SECRET|TOKEN|KEY|CERT|CRED)/i;
const NOISY_ENV_RE = /^(PATH|LANG|[\w.]*LC_[\w.]*|HOME|HOSTNAME|TERM|PWD|SHLVL|_|GDAL|JAVA_|PYTHON_VERSION)$/;

const CATEGORIES = new Set([
  "productivity", "storage", "networking", "development", "communication",
  "file-management", "search", "video", "media", "media-management",
  "home-automation", "monitoring", "database", "automation", "ai", "messaging",
  "radio", "security", "business",
]);

function slugFromImage(info: ImageInfo): string {
  const base = info.name.split("/").pop() ?? info.name;
  return base.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "app";
}

/** Занятые host-порты во всех приложениях стора. */
export function takenHostPorts(appsDirFiles: { manifest: any }[]): number[] {
  const taken: number[] = [];
  for (const { manifest } of appsDirFiles) {
    for (const svc of Object.values<any>(manifest.services ?? {})) {
      for (const p of svc.ports ?? []) {
        const host = String(p).split(":")[0];
        if (/^\d+$/.test(host)) taken.push(Number(host));
      }
    }
  }
  return taken;
}

function allocHost(taken: number[], start = 8080, step = 10): number {
  let p = start;
  while (taken.includes(p)) p += step;
  taken.push(p);
  return p;
}

/**
 * Полный цикл: проверка образа -> генерация файлов приложения (dry-run, без записи).
 * Возвращает манифест + файлы (app.yaml, README.md, icon.png).
 */
export async function buildAppFiles(
  image: string,
  opts: AddOptions,
  existing: { manifest: any }[] = [],
): Promise<{ name: string; manifest: any; files: Record<string, Buffer | string>; info: ImageInfo }> {
  const info = await checkImage(image);
  if (!info.arm64) {
    throw new Error(
      `Образ ${image} не имеет linux/arm64 — на MikroTik (arm) не запустится. Добавление прервано.`,
    );
  }
  if (opts.ramHintMB && info.sizeCompressed > opts.ramHintMB * 1024 * 1024 * 2) {
    // мягкое предупреждение — не блокируем
  }

  const name = (opts.name ?? slugFromImage(info)).toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]*$/.test(name)) {
    throw new Error(`Недопустимое имя приложения: '${name}' (нужно [a-z0-9-])`);
  }
  const category = opts.category ?? guessCategory(info);
  if (!CATEGORIES.has(category)) {
    throw new Error(`category '${category}' не из списка enum (см. schemas)`);
  }

  const taken = takenHostPorts(existing);

  // порты: явные из opts, иначе из ExposedPorts образа
  const portEntries: string[] = [];
  if (opts.ports?.length) {
    for (const raw of opts.ports) {
      const parts = String(raw).split(":");
      if (parts.length < 2 || !/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])) {
        throw new Error(`Порт '${raw}' — ожидается вид 8080:80[/tcp|/udp][:метка]`);
      }
      let proto = "tcp";
      let label = "";
      for (const extra of parts.slice(2)) {
        if (extra === "tcp" || extra === "udp") proto = extra;
        else if (extra) label = extra;
      }
      taken.push(Number(parts[0]));
      portEntries.push(`${parts[0]}:${parts[1]}/${proto}${label ? ":" + label : ""}`);
    }
  } else {
    const exposed = [...info.exposedPorts].sort((a, b) =>
      a.endsWith("/tcp") ? -1 : b.endsWith("/tcp") ? 1 : a.localeCompare(b),
    );
    let webAssigned = false;
    for (const ex of exposed.slice(0, 5)) {
      const [cport, proto = "tcp"] = ex.split("/");
      const host = allocHost(taken);
      const label = proto === "tcp" && !webAssigned ? ((webAssigned = true), ":web") : "";
      portEntries.push(`${host}:${cport}/${proto}${label}`);
    }
  }

  // env: пользовательские + полезные из образа; секретоподобные -> secrets
  const env: Record<string, string> = {};
  const secrets: Record<string, null> = {};
  const maskSecret = (key: string, value: string) => {
    const slug = key.toLowerCase().replace(/[^a-z0-9]+/g, "-");
    secrets[slug] = null;
    env[key] = `[secret:${slug}]`;
    return value; // оригинал вызывающий должен сохранить ЛОКАЛЬНО, не в репо
  };

  const secretOriginals: Record<string, string> = {};
  for (const [k, v] of Object.entries(opts.env ?? {})) {
    if (!/^[A-Z_][A-Z0-9_]*$/.test(k)) {
      throw new Error(`Ключ env '${k}' должен соответствовать [A-Z_][A-Z0-9_]*`);
    }
    if (SECRET_KEY_RE.test(k)) secretOriginals[maskSecret(k, String(v))] = String(v);
    else env[k] = String(v);
  }
  for (const e of info.env) {
    const i = e.indexOf("=");
    if (i < 0) continue;
    const k = e.slice(0, i);
    const v = e.slice(i + 1);
    if (k in env || NOISY_ENV_RE.test(k)) continue;
    if (SECRET_KEY_RE.test(k) && v && v !== "*" && v !== "changeme") {
      maskSecret(k, v); // значение из образа не сохраняем — только плейсхолдер
    } else {
      env[k] = v;
    }
  }

  const svcName = name.slice(0, 30);
  const manifest: any = {
    name,
    descr: opts.descr ?? `${info.name} из Docker Hub (авто-конвертация store-combine)`,
    category,
    icon: "icon.png",
    "auto-update": false,
    services: {
      [svcName]: {
        image: `${info.registry}/${info.name}:${info.tag}`,
        ...(portEntries.length ? { ports: portEntries } : {}),
        ...(Object.keys(env).length ? { environment: env } : {}),
        restart: "unless-stopped",
      },
    },
  };
  if (Object.keys(secrets).length) manifest.secrets = secrets;

  assertValid(manifest, `apps/${name}/app.yaml`);

  const appYaml = YAML.stringify(manifest, { lineWidth: 0 });
  const readme = [
    `# ${name}`,
    "",
    `Автоматически сгенерировано store-combine из образа \`${info.registry}/${info.name}:${info.tag}\`.`,
    "",
    `- arm64: да (digest ${info.digest?.slice(0, 19) ?? "n/a"}…)`,
    `- Размер (сжато): ${(info.sizeCompressed / 1024 / 1024).toFixed(1)} МБ`,
    portEntries.length ? `- Порты: ${portEntries.join(", ")}` : "- Порты наружу не публикуются",
    Object.keys(secrets).length
      ? `- Секреты (вводятся при установке): ${Object.keys(secrets).join(", ")}`
      : "",
    "",
    "Отредактируйте вручную при необходимости: `apps/" + name + "/app.yaml`.",
  ]
    .filter(Boolean)
    .join("\n") + "\n";

  // icon.ts нельзя импортировать циклично — импорт ниже
  const { placeholderIcon } = await import("./icons.js");
  return {
    name,
    manifest,
    files: {
      "app.yaml": appYaml,
      "README.md": readme,
      "icon.png": placeholderIcon(name),
    },
    info,
  };
}

export function guessCategory(info: { name: string; labels?: Record<string, string> }): string {
  const s = `${info.name} ${Object.keys(info.labels ?? {}).join(" ")}`.toLowerCase();
  if (/(postgres|mysql|mariadb|redis|mongo|database|influxdb)/.test(s)) return "database";
  if (/(wireguard|vpn|nginx|dns|proxy|network|tailscale|netbird)/.test(s)) return "networking";
  if (/(prometheus|grafana|zabbix|uptime|monitor)/.test(s)) return "monitoring";
  if (/(chat|matrix|telegram|messenger)/.test(s)) return "messaging";
  if (/(torrent|download|sonarr|file|samba|nextcloud)/.test(s)) return "file-management";
  return "development";
}
