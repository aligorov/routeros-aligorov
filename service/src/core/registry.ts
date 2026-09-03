// Клиент Docker Registry HTTP API v2 (анонимные pull-токены): docker.io и ghcr.io.
// Проверено вживую 2026-09-03: последовательность токен -> манифест(index) -> config-блоб.

export interface ImageInfo {
  input: string;
  registry: "docker.io" | "ghcr.io" | string;
  name: string; // library/nginx, owner/app
  tag: string;
  arm64: boolean;
  digest?: string; // arm64-манифест
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

  let armManifest: any = null;
  let arm64 = false;
  let digest: string | undefined;
  const warnings: string[] = [];

  if (Array.isArray(manifest.manifests)) {
    const entry = manifest.manifests.find(
      (m: any) =>
        m.platform?.os === "linux" &&
        m.platform?.architecture === "arm64" &&
        m.platform?.os !== "unknown" &&
        m.platform?.architecture !== "unknown",
    );
    if (entry) {
      arm64 = true;
      digest = entry.digest;
      armManifest = await regFetch(
        ref.registryHost,
        token,
        `/v2/${ref.name}/manifests/${digest}`,
        ACCEPT_MANIFEST,
      ).then((r) => r.json());
    } else {
      const archs = [...new Set(manifest.manifests.map((m: any) => m.platform?.architecture))];
      warnings.push(
        `linux/arm64 НЕ найден; доступные архитектуры: ${archs.join(", ")}`,
      );
    }
  } else {
    // одно-архитектурный манифест
    armManifest = manifest;
    digest = manifest.config?.digest;
  }

  let sizeCompressed = 0;
  let config: any = null;
  if (armManifest) {
    sizeCompressed = (armManifest.layers ?? []).reduce(
      (s: number, l: any) => s + (l.size ?? 0),
      0,
    );
    const cfgDigest = armManifest.config?.digest;
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
        arm64 = config.architecture === "arm64" && config.os === "linux";
        if (!arm64) {
          warnings.push(
            `образ одно-архитектурный: ${config.os}/${config.architecture}, нужен linux/arm64`,
          );
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
    digest,
    sizeCompressed,
    env: config?.Env ?? [],
    exposedPorts: Object.keys(config?.ExposedPorts ?? {}),
    cmd: config?.Cmd,
    entrypoint: config?.Entrypoint,
    labels: config?.Labels ?? {},
    warnings,
  };
}

export function formatInfo(info: ImageInfo): string {
  const mb = (info.sizeCompressed / 1024 / 1024).toFixed(1);
  const lines = [
    `Образ: ${info.registry}/${info.name}:${info.tag}`,
    `arm64: ${info.arm64 ? "✅ да" : "❌ НЕТ"}`,
    `Размер (сжато): ${mb} МБ`,
  ];
  if (info.exposedPorts.length) lines.push(`Порты контейнера: ${info.exposedPorts.join(", ")}`);
  if (Object.keys(info.labels).length) {
    lines.push(`Labels: ${Object.keys(info.labels).slice(0, 10).join(", ")}`);
  }
  if (info.warnings.length) lines.push(`⚠️ ${info.warnings.join("\n⚠️ ")}`);
  return lines.join("\n");
}
