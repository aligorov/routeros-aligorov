// Клиент Docker Registry HTTP API v2 (анонимные pull-токены): docker.io и ghcr.io.
// Проверено вживую 2026-09-03: последовательность токен -> манифест(index) -> config-блоб.

export interface ImageInfo {
  input: string;
  registry: "docker.io" | "ghcr.io" | string;
  name: string; // library/nginx, owner/app
  tag: string;
  arm64: boolean;
  amd64: boolean; // MikroTik CHR (x86_64)
  platforms: string[];
  digest?: string; // arm64 или основной digest
  amd64Digest?: string;
  sizeCompressed: number; // байты, сумма слоёв
  env: string[]; // "KEY=value"
  exposedPorts: string[]; // "80/tcp", "53/udp"
  cmd?: string[];
  entrypoint?: string[];
  labels: Record<string, string>;
  warnings: string[];
}

export function parseImage(input: string): {
  registryHost: string;
  authHost: string;
  name: string;
  tag: string;
  displayName: string;
} {
  let s = input.trim();
  let host = "docker.io";
  let rest = s;
  const parts = s.split("/");
  if (
    parts.length > 1 &&
    (parts[0].includes(".") || parts[0].includes(":") || parts[0] === "localhost")
  ) {
    host = parts[0];
    rest = parts.slice(1).join("/");
  }
  let tag = "latest";
  const last = rest.split("/").pop() ?? "";
  if (last.includes(":")) {
    const i = rest.lastIndexOf(":");
    tag = rest.slice(i + 1);
    rest = rest.slice(0, i);
  }
  if (!rest) throw new Error(`Не удалось разобрать ссылку образа: ${input}`);

  const isDocker = host === "docker.io" || host === "registry-1.docker.io";
  const name = isDocker && !rest.includes("/") ? `library/${rest}` : rest;
  return {
    registryHost: isDocker ? "registry-1.docker.io" : host,
    authHost: isDocker ? "auth.docker.io" : host,
    name,
    tag,
    displayName: host === "docker.io" ? `${name}:${tag}` : `${host}/${name}:${tag}`,
  };
}

async function getToken(authHost: string, name: string): Promise<string> {
  let url: string;
  if (authHost === "auth.docker.io") {
    url = `https://auth.docker.io/token?service=registry.docker.io&scope=repository:${name}:pull`;
  } else {
    url = `https://${authHost}/token?scope=repository:${name}:pull&service=${authHost}`;
  }
  const r = await fetch(url);
  if (!r.ok) throw new Error(`Токен registry не получен (HTTP ${r.status}): ${url}`);
  const j: any = await r.json();
  if (!j.token) throw new Error(`Registry не выдал токен: ${url}`);
  return j.token as string;
}

const ACCEPT_INDEX =
  "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json";
const ACCEPT_MANIFEST =
  "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json";
const ACCEPT_ANY = `${ACCEPT_INDEX}, ${ACCEPT_MANIFEST}`;

async function regFetch(
  registryHost: string,
  token: string,
  path: string,
  accept: string,
): Promise<Response> {
  const r = await fetch(`https://${registryHost}${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: accept },
    redirect: "follow", // блобы редиректят на CDN
  });
  if (!r.ok) {
    throw new Error(`Registry ${path}: HTTP ${r.status} ${await r.text().catch(() => "")}`.slice(0, 300));
  }
  return r;
}

export async function checkImage(input: string): Promise<ImageInfo> {
  const ref = parseImage(input);
  const token = await getToken(ref.authHost, ref.name);

  const mr = await regFetch(
    ref.registryHost,
    token,
    `/v2/${ref.name}/manifests/${ref.tag}`,
    ACCEPT_ANY,
  );
  const manifest: any = await mr.json();

  let targetManifest: any = null;
  let arm64 = false;
  let amd64 = false;
  let platforms: string[] = [];
  let digest: string | undefined;
  let amd64Digest: string | undefined;
  const warnings: string[] = [];

  if (Array.isArray(manifest.manifests)) {
    const valid = manifest.manifests.filter(
      (m: any) =>
        m.platform?.os &&
        m.platform?.architecture &&
        m.platform.os !== "unknown" &&
        m.platform.architecture !== "unknown",
    );
    platforms = [...new Set<string>(valid.map((m: any) => `${m.platform.os}/${m.platform.architecture}`))];
    const armEntry = valid.find(
      (m: any) => m.platform.os === "linux" && m.platform.architecture === "arm64",
    );
    const amdEntry = valid.find(
      (m: any) => m.platform.os === "linux" && m.platform.architecture === "amd64",
    );
    arm64 = Boolean(armEntry);
    amd64 = Boolean(amdEntry);
    amd64Digest = amdEntry?.digest;
    digest = armEntry?.digest ?? amdEntry?.digest;

    const inspectEntry = armEntry ?? amdEntry;
    if (inspectEntry) {
      targetManifest = await regFetch(
        ref.registryHost,
        token,
        `/v2/${ref.name}/manifests/${inspectEntry.digest}`,
        ACCEPT_MANIFEST,
      ).then((r) => r.json());
    }
    if (!arm64 && !amd64) {
      warnings.push(
        `linux/arm64 и linux/amd64 (CHR) НЕ найдены; доступные: ${platforms.join(", ") || "нет"}`,
      );
    } else if (!arm64) {
      warnings.push("нет linux/arm64 — образ только для MikroTik CHR (x86_64)");
    } else if (!amd64) {
      warnings.push("нет linux/amd64 — на MikroTik CHR (x86_64) не запустится");
    }
  } else {
    // одно-архитектурный манифест
    targetManifest = manifest;
    digest = manifest.config?.digest;
  }

  let sizeCompressed = 0;
  let config: any = null;
  if (targetManifest) {
    sizeCompressed = (targetManifest.layers ?? []).reduce(
      (s: number, l: any) => s + (l.size ?? 0),
      0,
    );
    const cfgDigest = targetManifest.config?.digest;
    if (cfgDigest) {
      const cr = await regFetch(
        ref.registryHost,
        token,
        `/v2/${ref.name}/blobs/${cfgDigest}`,
        "application/vnd.docker.container.image.v1+json",
      );
      const blob: any = await cr.json();
      config = blob.config ?? {};
      if (!Array.isArray(manifest.manifests)) {
        const os = blob.os ?? config.os;
        const arch = blob.architecture ?? config.architecture;
        if (os && arch) platforms = [`${os}/${arch}`];
        arm64 = arch === "arm64" && os === "linux";
        amd64 = arch === "amd64" && os === "linux";
        if (amd64) amd64Digest = digest;
        if (!arm64 && !amd64) {
          warnings.push(
            `образ одно-архитектурный: ${os}/${arch}, нужен linux/arm64 или linux/amd64 (CHR)`,
          );
        } else if (!arm64) {
          warnings.push("образ одно-архитектурный: только linux/amd64 (MikroTik CHR)");
        } else if (!amd64) {
          warnings.push("образ одно-архитектурный: только linux/arm64 (без CHR x86_64)");
        }
      }
    }
  }

  if (ref.tag === "latest") {
    warnings.push("тег latest нестабилен — укажите конкретную версию");
  }
  if (sizeCompressed > 400 * 1024 * 1024) {
    warnings.push(
      `большой образ: ${(sizeCompressed / 1024 / 1024).toFixed(0)} МБ (сжато) — проверьте RAM/диск роутера`,
    );
  }

  return {
    input,
    registry: ref.registryHost === "registry-1.docker.io" ? "docker.io" : ref.registryHost,
    name: ref.name,
    tag: ref.tag,
    arm64,
    amd64,
    platforms,
    digest,
    amd64Digest,
    sizeCompressed,
    env: config?.Env ?? [],
    exposedPorts: Object.keys(config?.ExposedPorts ?? {}),
    cmd: config?.Cmd,
    entrypoint: config?.Entrypoint,
    labels: config?.Labels ?? {},
    warnings,
  };
}

export type TargetArch = "any" | "arm64" | "amd64" | "chr" | "both";

export function assertImageArch(
  image: string,
  info: Pick<ImageInfo, "arm64" | "amd64" | "platforms">,
  arch: TargetArch = "any",
  contextLabel = "",
): void {
  const ctx = contextLabel ? ` (${contextLabel})` : "";
  if (arch === "arm64" && !info.arm64) {
    throw new Error(
      `Образ ${image}${ctx} не имеет linux/arm64 — на ARM-роутерах MikroTik не запустится. Добавление прервано.`,
    );
  }
  if ((arch === "amd64" || arch === "chr") && !info.amd64) {
    throw new Error(
      `Образ ${image}${ctx} не имеет linux/amd64 — на MikroTik CHR не запустится. Добавление прервано.`,
    );
  }
  if (arch === "both" && (!info.arm64 || !info.amd64)) {
    throw new Error(
      `Образ ${image}${ctx} не поддерживает обе архитектуры (linux/arm64 и linux/amd64 для CHR). Доступны: ${info.platforms.join(", ") || "нет"}.`,
    );
  }
  if (!info.arm64 && !info.amd64) {
    throw new Error(
      `Образ ${image}${ctx} не имеет ни linux/arm64 (ARM), ни linux/amd64 (CHR) — на MikroTik не запустится. Добавление прервано.`,
    );
  }
}

export function formatArchList(info: Pick<ImageInfo, "arm64" | "amd64" | "digest" | "amd64Digest">): string {
  const parts: string[] = [];
  if (info.arm64) parts.push(`linux/arm64 (${info.digest?.slice(0, 19) ?? "n/a"}…)`);
  if (info.amd64) parts.push(`linux/amd64 CHR (${info.amd64Digest?.slice(0, 19) ?? "n/a"}…)`);
  return parts.join(", ") || "нет";
}

export function formatInfo(info: ImageInfo): string {
  const mb = (info.sizeCompressed / 1024 / 1024).toFixed(1);
  const lines = [
    `Образ: ${info.registry}/${info.name}:${info.tag}`,
    `arm64 (ARM): ${info.arm64 ? "✅ да" : "❌ нет"} | amd64 (CHR): ${info.amd64 ? "✅ да" : "❌ нет"}`,
    `Размер (сжато): ${mb} МБ`,
  ];
  if (info.exposedPorts.length) lines.push(`Порты контейнера: ${info.exposedPorts.join(", ")}`);
  if (Object.keys(info.labels).length) {
    lines.push(`Labels: ${Object.keys(info.labels).slice(0, 10).join(", ")}`);
  }
  if (info.warnings.length) lines.push(`⚠️ ${info.warnings.join("\n⚠️ ")}`);
  return lines.join("\n");
}
