// M4: публикация в стор БЕЗ локального клона — через GitHub Git Data API.
// Нужен GITHUB_TOKEN (fine-grained, Contents: RW на репо стора).
import YAML from "yaml";
import { GitHub } from "./github.js";
import { buildStoreFiles, type AppEntry } from "./build-store.js";
import { manifestErrors } from "./validate.js";
import { config } from "../config.js";

export function remoteClient(): GitHub {
  if (!process.env.GITHUB_TOKEN) {
    throw new Error("Remote-режим требует GITHUB_TOKEN (Contents: RW на репо стора)");
  }
  return new GitHub(process.env.GITHUB_TOKEN);
}

export async function remoteReadApps(gh = remoteClient()): Promise<AppEntry[]> {
  const entries = await gh.listDir("apps");
  const out: AppEntry[] = [];
  for (const e of entries) {
    if (e.type !== "dir" || e.name.startsWith("_") || e.name.startsWith(".")) continue;
    const text = await gh.fileText(`apps/${e.name}/app.yaml`);
    if (!text) continue;
    const manifest = YAML.parse(text);
    if (!manifest?.services) continue;
    out.push({ dir: e.name, manifest });
  }
  return out.sort((a, b) => a.dir.localeCompare(b.dir));
}

/** Список файлов приложения (для удаления). */
async function appFiles(gh: GitHub, name: string): Promise<string[]> {
  const dir = await gh.listDir(`apps/${name}`);
  return dir.map((e) => e.path);
}

export interface RemoteResult {
  apps: number;
  commit: string;
  storeUrl: string;
}

/** Применить изменения (добавить приложение / удалить) + пересобрать стор, одним атомарным коммитом. */
async function apply(
  appName: string | null,
  addFiles: Record<string, Buffer | string> | null,
  message: string,
): Promise<RemoteResult> {
  const gh = remoteClient();

  // актуальное состояние стора минус удаляемое приложение
  let apps = await remoteReadApps(gh);
  if (appName) apps = apps.filter((a) => a.dir !== appName);

  // валидация: существующие + новое
  const toValidate = [...apps];
  if (addFiles?.["app.yaml"]) {
    const m = YAML.parse(String(addFiles["app.yaml"]));
    toValidate.push({ dir: appName!.toLowerCase(), manifest: m });
  }
  const problems: string[] = [];
  for (const { dir, manifest } of toValidate) {
    for (const e of manifestErrors(manifest)) problems.push(`apps/${dir}/app.yaml: ${e}`);
  }
  if (problems.length) {
    throw new Error(`Валидация не прошла:\n  - ${problems.join("\n  - ")}`);
  }

  const finalApps = addFiles?.["app.yaml"]
    ? [...apps, { dir: appName!.toLowerCase(), manifest: YAML.parse(String(addFiles["app.yaml"])) }].sort((a, b) =>
        a.dir.localeCompare(b.dir),
      )
    : apps;

  const generated = buildStoreFiles(finalApps, config.storeBaseUrl);

  const adds: Record<string, Buffer | string> = { ...generated };
  const dir = appName!.toLowerCase();
  if (addFiles) {
    for (const [rel, content] of Object.entries(addFiles)) {
      adds[`apps/${dir}/${rel}`] = content;
    }
  }
  const removes: string[] = appName && !addFiles ? await appFiles(gh, appName.toLowerCase()) : [];

  const commit = await gh.applyChanges(adds, removes, message);
  return { apps: finalApps.length, commit, storeUrl: `${config.storeBaseUrl}/store.yaml` };
}

export async function remotePublishApp(
  name: string,
  files: Record<string, Buffer | string>,
): Promise<RemoteResult> {
  // safety-scan общий с локальным режимом
  const { safetyScan } = await import("./publisher-local.js");
  safetyScan(files);
  return apply(name, files, `combine: add ${name}`);
}

export async function remoteRemoveApp(name: string): Promise<RemoteResult> {
  // папка может отличаться от отображаемого имени — ищем реальный dir
  const gh = remoteClient();
  const apps = await remoteReadApps(gh);
  const entry = apps.find((a) => a.dir === name.toLowerCase() || a.manifest?.name === name);
  const dir = entry ? entry.dir : name.toLowerCase();
  return apply(dir, null, `combine: remove ${name}`);
}
