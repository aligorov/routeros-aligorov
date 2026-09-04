// Публикация в стор через локальный git-клон репозитория.
// Файлы -> safety-scan -> валидация всех приложений -> пересборка store.yaml -> commit+push.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import path from "node:path";
import { config } from "../config.js";
import { readApps, rebuildStore } from "./build-store.js";
import { manifestErrors } from "./validate.js";

const exec = promisify(execFile);

const git = (...args: string[]) => exec("git", args, { cwd: config.repoDir });

// ---- safety scan: репо публичный ----
const FORBIDDEN = [
  /github_pat_[A-Za-z0-9_]+/,
  /gh[pousr]_[A-Za-z0-9]{20,}/,
  /sk-[A-Za-z0-9]{20,}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /(password|passwd|secret|token)\s*[:=]\s*"(?![*]|changeme|\$\{|\[secret:)[^"\s]{6,}"/i,
  /\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b/,
];

export function safetyScan(files: Record<string, Buffer | string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const text = content.toString("utf8");
    for (const re of FORBIDDEN) {
      const m = text.match(re);
      if (m) {
        throw new Error(
          `Безопасность: в ${rel} найдено подозрительное '${m[0].slice(0, 24)}…' — публикация заблокирована`,
        );
      }
    }
  }
}

export function appDir(name: string): string {
  // папка — всегда в нижнем регистре (файловая система/Pages), регистр имени — только в name:
  const dir = name.toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]*$/.test(dir)) throw new Error(`Плохое имя: ${name}`);
  return path.join(config.repoDir, "apps", dir);
}

export function writeAppFiles(name: string, files: Record<string, Buffer | string>): void {
  const dir = appDir(name);
  mkdirSync(dir, { recursive: true });
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    mkdirSync(path.dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
}

function validateAll(): void {
  const apps = readApps();
  if (!apps.length) throw new Error("apps/ пуст — публиковать нечего");
  const problems: string[] = [];
  for (const { dir, manifest } of apps) {
    for (const e of manifestErrors(manifest)) problems.push(`apps/${dir}/app.yaml: ${e}`);
  }
  if (problems.length) throw new Error(`Валидация не прошла:\n  - ${problems.join("\n  - ")}`);
}

async function commitAndPush(message: string): Promise<{ commit: string; pushed: boolean }> {
  await git("add", "-A");
  const { stdout } = await git("status", "--porcelain");
  if (!stdout.trim()) return { commit: "", pushed: false };
  await git("commit", "-m", message);
  const { stdout: sha } = await git("rev-parse", "--short", "HEAD");
  try {
    await git("push");
    return { commit: sha.trim(), pushed: true };
  } catch (e: any) {
    throw new Error(
      `Коммит ${sha.trim()} создан, но push не удался: ${e.message}\nРазберитесь вручную (git push) — стор пока не обновился.`,
    );
  }
}

export interface PublishResult {
  apps: number;
  commit: string;
  pushed: boolean;
  storeUrl: string;
}

export async function publishApp(
  name: string,
  files: Record<string, Buffer | string>,
): Promise<PublishResult> {
  safetyScan(files);
  writeAppFiles(name, files);
  return finalize(`combine: add ${name}`);
}

/** Перевалидировать всё, пересобрать стор, закоммитить и запушить. */
export async function finalize(commitMsg: string): Promise<PublishResult> {
  validateAll();
  const apps = rebuildStore();
  const { commit, pushed } = await commitAndPush(commitMsg);
  return { apps, commit, pushed, storeUrl: `${config.storeBaseUrl}/store.yaml` };
}

export async function removeApp(name: string): Promise<PublishResult> {
  const dir = appDir(name);
  if (!existsSync(dir)) throw new Error(`Приложение не найдено: apps/${name}`);
  rmSync(dir, { recursive: true, force: true });
  return finalize(`combine: remove ${name}`);
}
