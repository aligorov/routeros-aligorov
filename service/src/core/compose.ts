// M2: импорт docker-compose.yml -> одно приложение RouterOS (/app).
// Правила конвертации — docs/plan-store-combine.md §4.
import YAML from "yaml";
import { readFileSync } from "node:fs";
import path from "node:path";
import { checkImage, type ImageInfo } from "./registry.js";
import { assertValid } from "./validate.js";
import { guessCategory } from "./converter.js";
import { placeholderIcon } from "./icons.js";

const SECRET_KEY_RE = /(PASS|SECRET|TOKEN|KEY|CERT|CRED)/i;

export interface ComposeImportOptions {
  name?: string;
  checkArm64?: boolean; // default: true
  /** Читатель env_file (путь относительно compose-файла). По умолчанию fs. */
  readEnvFile?: (p: string) => string;
}

export interface ComposeResult {
  name: string;
  manifest: any;
  warnings: string[];
  /** Локальные значения секретов (НЕ в репо!): "имя=значение" */
  secretLocalEnv: string[];
  files: Record<string, Buffer | string>;
}

function svcName(s: string): string {
  return s.replace(/[^a-zA-Z0-9_-]/g, "-");
}

function slug(p: string): string {
  return (
    p
      .replace(/^[.~/]+/, "")
      .replace(/[^a-zA-Z0-9-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .toLowerCase()
      .slice(0, 30) || "vol"
  );
}

export async function importCompose(
  content: string,
  opts: ComposeImportOptions = {},
): Promise<ComposeResult> {
  const warnings: string[] = [];
  const secretLocalEnv: string[] = [];
  const doc = YAML.parse(content);
  if (!doc || typeof doc !== "object" || !doc.services) {
    throw new Error("В compose нет ключа services");
  }
  const readEnvFile =
    opts.readEnvFile ?? ((p: string) => readFileSync(p, "utf8"));

  const name = (
    opts.name ??
    doc.name ??
    "compose-app"
  )
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!/^[a-z0-9][a-z0-9-]*$/.test(name)) {
    throw new Error(`Не получилось имя приложения: '${name}'`);
  }

  const services: Record<string, any> = {};
  const volumes: Record<string, null> = {};
  const appEnvSecrets: Record<string, null> = {};
  let webAssigned = false;

  const total = Object.keys(doc.services).length;
  if (total > 8) warnings.push(`Сервисов много (${total}) — проверьте RAM роутера`);

  for (const [rawSvc, raw] of Object.entries<any>(doc.services)) {
    const svc = svcName(rawSvc);

    // build-only сервисы не переносим
    if (!raw?.image) {
      if (raw?.build) {
        warnings.push(
          `Сервис '${rawSvc}': только build: (без image) — пропущен; соберите образ (ghcr-push) и добавьте позже`,
        );
      } else {
        warnings.push(`Сервис '${rawSvc}': нет image — пропущен`);
      }
      continue;
    }
    if (raw.build) warnings.push(`Сервис '${rawSvc}': build: проигнорирован, использую image`);

    // arm64
    if (opts.checkArm64 !== false) {
      let info: ImageInfo;
      try {
        info = await checkImage(raw.image);
      } catch (e: any) {
        const firstSeg = String(raw.image).split("/")[0];
        const noRegistry = !firstSeg.includes(".");
        warnings.push(
          `Сервис '${rawSvc}': не удалось проверить образ (${e.message})` +
            (noRegistry ? "; похоже на ЛОКАЛЬНЫЙ образ без registry — RouterOS не сможет его скачать" : "") +
            " — продолжаю",
        );
        info = null as any;
      }
      if (info && !info.arm64) {
        throw new Error(
          `Образ ${raw.image} (сервис '${rawSvc}') не имеет linux/arm64 — на MikroTik не запустится. Импорт прерван.`,
        );
      }
    }

    // порты
    const ports: string[] = [];
    for (const p of raw.ports ?? []) {
      if (typeof p === "object") {
        // long syntax
        const { target, published, protocol = "tcp" } = p;
        if (!target || !published) {
          warnings.push(`Сервис '${rawSvc}': порт ${JSON.stringify(p)} без target/published — пропущен`);
          continue;
        }
        if (typeof published === "string" && published.includes("-")) {
          warnings.push(`Сервис '${rawSvc}': диапазон портов не поддерживается — пропущен`);
          continue;
        }
        const label = protocol === "tcp" && !webAssigned ? ((webAssigned = true), "web") : "";
        ports.push(`${published}:${target}/${protocol}${label ? ":" + label : ""}`);
      } else {
        const s = String(p);
        if (s.includes("-")) {
          warnings.push(`Сервис '${rawSvc}': диапазон портов '${s}' не поддерживается — пропущен`);
          continue;
        }
        // [ip:]host:container[/proto]
        const m = s.match(/^(?:([\d.]+):)?(\d+):(\d+)(?:\/(tcp|udp))?$/);
        if (!m) {
          warnings.push(`Сервис '${rawSvc}': порт '${s}' не разобран — пропущен`);
          continue;
        }
        const [, ip, host, cont, proto = "tcp"] = m;
        const label = proto === "tcp" && !webAssigned ? ((webAssigned = true), "web") : "";
        ports.push(
          `${ip ? ip + ":" : ""}${host}:${cont}/${proto}${label ? ":" + label : ""}`,
        );
      }
    }

    // environment + env_file (секреты -> secrets)
    const env: Record<string, string> = {};
    const envSources: Record<string, any>[] = [];
    if (raw.environment && !Array.isArray(raw.environment) && typeof raw.environment === "object") {
      envSources.push(raw.environment);
    } else if (Array.isArray(raw.environment)) {
      envSources.push(Object.fromEntries(raw.environment.map((s: string) => {
        const i = s.indexOf("=");
        return [s.slice(0, i), s.slice(i + 1)];
      })));
    }
    const envFiles: string[] = Array.isArray(raw.env_file) ? raw.env_file : raw.env_file ? [raw.env_file] : [];
    for (const f of envFiles) {
      try {
        const txt = readEnvFile(f);
        for (const line of txt.split("\n")) {
          const t = line.trim();
          if (!t || t.startsWith("#")) continue;
          const i = t.indexOf("=");
          envSources.push({ [t.slice(0, i)]: t.slice(i + 1) });
        }
      } catch {
        warnings.push(`Сервис '${rawSvc}': env_file '${f}' не прочитан — переменные из него НЕ перенесены`);
      }
    }
    for (const src of envSources) {
      for (const [k, v] of Object.entries(src)) {
        if (v == null) continue;
        if (SECRET_KEY_RE.test(k)) {
          const sname = `${svcName(rawSvc)}-${k.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
          appEnvSecrets[sname] = null;
          env[k] = `[secret:${sname}]`;
          secretLocalEnv.push(`${sname}=${v}`);
        } else {
          env[k] = String(v);
        }
      }
    }

    // volumes
    const svcVolumes: string[] = [];
    for (const v of raw.volumes ?? []) {
      if (typeof v === "object") {
        if (v.type === "tmpfs") {
          warnings.push(`Сервис '${rawSvc}': tmpfs-том не поддерживается — пропущен`);
          continue;
        }
        v.source && v.target ? svcVolumes.push(`${v.source}:${v.target}`) : null;
        if (!v.source) warnings.push(`Сервис '${rawSvc}': анонимный том ${v.target} -> именованный`);
        if (!v.source && v.target) {
          const n = `${svc}-${slug(v.target)}`;
          volumes[n] = null;
          svcVolumes.push(`${n}:${v.target}`);
        }
        continue;
      }
      const s = String(v);
      const parts = s.split(":");
      if (parts.length >= 2) {
        let [src, dst, mode] = parts;
        if (src.startsWith(".") || src.startsWith("/") ) {
          // bind mount -> именованный том (данные не переносятся)
          const n = slug(src);
          volumes[n] = null;
          svcVolumes.push(`${n}:${dst}${mode ? ":" + mode : ""}`);
          warnings.push(
            `Сервис '${rawSvc}': bind-том '${src}' заменён именованным '${n}' (содержимое НЕ скопировано)`,
          );
        } else {
          volumes[src] = null;
          svcVolumes.push(s);
        }
      } else {
        // анонимный
        const n = `${svc}-${slug(s)}`;
        volumes[n] = null;
        svcVolumes.push(`${n}:${s}`);
      }
    }

    // unsupported -> warnings
    if (raw.privileged) warnings.push(`Сервис '${rawSvc}': privileged не поддерживается RouterOS`);
    for (const c of raw.cap_add ?? []) warnings.push(`Сервис '${rawSvc}': cap_add ${c} — не поддерживается`);
    if (raw.network_mode === "host") warnings.push(`Сервис '${rawSvc}': network_mode host не поддерживается (у приложения один veth)`);
    for (const net of Object.keys(raw.networks ?? {})) warnings.push(`Сервис '${rawSvc}': сеть '${net}' проигнорирована (сервисы одного /app видны через localhost)`);
    if (raw.pid || raw.ipc || raw.cgroup) warnings.push(`Сервис '${rawSvc}': pid/ipc/cgroup namespace не поддерживаются`);
    const memLimit = raw.deploy?.resources?.limits?.memory;
    if (memLimit) warnings.push(`Сервис '${rawSvc}': memory limit ${memLimit} — проверьте RAM роутера`);
    if (raw.extends) warnings.push(`Сервис '${rawSvc}': extends не поддерживается`);
    if (raw.secrets) warnings.push(`Сервис '${rawSvc}': compose secrets (${raw.secrets}) — перенесите вручную в secrets:/configs:`);

    services[svc] = {
      image: raw.image,
      ...(ports.length ? { ports } : {}),
      ...(Object.keys(env).length ? { environment: env } : {}),
      ...(svcVolumes.length ? { volumes: svcVolumes } : {}),
      ...(raw.depends_on
        ? {
            depends_on: Array.isArray(raw.depends_on)
              ? raw.depends_on.map(svcName)
              : Object.keys(raw.depends_on).map(svcName),
          }
        : {}),
      ...(raw.restart ? { restart: raw.restart } : {}),
      ...(raw.command ? { command: raw.command } : {}),
      ...(raw.entrypoint ? { entrypoint: raw.entrypoint } : {}),
      ...(raw.hostname ? { hostname: raw.hostname } : {}),
      ...(raw.healthcheck ? { healthcheck: raw.healthcheck } : {}),
    };
  }

  if (!Object.keys(services).length) {
    throw new Error("Не перенёсся ни один сервис (см. предупреждения)");
  }

  // верхние volumes из compose — просто объявляем
  for (const v of Object.keys(doc.volumes ?? {})) volumes[svcName(v)] = null;

  const manifest: any = {
    name,
    descr: doc.name ? `Импорт compose: ${doc.name}` : `Импорт docker-compose (${Object.keys(services).length} сервисов)`,
    category: guessCategory({ name: Object.values<any>(services).map((s) => s.image).join(" ") }),
    icon: "icon.png",
    "auto-update": false,
    services,
    ...(Object.keys(volumes).length ? { volumes } : {}),
    ...(Object.keys(appEnvSecrets).length ? { secrets: appEnvSecrets } : {}),
  };
  assertValid(manifest, `apps/${name}/app.yaml`);

  const appYaml = YAML.stringify(manifest, { lineWidth: 0 });
  const readme =
    `# ${name}\n\nИмпортировано из docker-compose.yml через store-combine.\n\n` +
    (warnings.length ? `## Предупреждения конвертации\n\n${warnings.map((w) => `- ⚠️ ${w}`).join("\n")}\n\n` : "") +
    (secretLocalEnv.length
      ? `## Секреты (значения ниже — только локально, при установке вводятся вручную)\n\n${secretLocalEnv.map((s) => `- \`${s.split("=")[0]}\``).join("\n")}\n\n`
      : "") +
    `Манифест: \`apps/${name}/app.yaml\` — проверьте и поправьте при необходимости.\n`;

  return {
    name,
    manifest,
    warnings,
    secretLocalEnv,
    files: {
      "app.yaml": appYaml,
      "README.md": readme,
      "icon.png": placeholderIcon(name),
    },
  };
}

/** Загрузка compose: путь или http(s) URL. */
export async function loadCompose(source: string, baseDir = "."): Promise<string> {
  if (/^https?:\/\//.test(source)) {
    const r = await fetch(source);
    if (!r.ok) throw new Error(`Не скачался ${source}: HTTP ${r.status}`);
    return r.text();
  }
  const p = path.isAbsolute(source) ? source : path.join(baseDir, source);
  return readFileSync(p, "utf8");
}
