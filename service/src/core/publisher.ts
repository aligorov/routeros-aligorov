// Диспетчер публикаторов: local-git (по умолчанию) или github-api (без клона).
// Выбор: env PUBLISHER=github-api, либо авто — если задан GITHUB_TOKEN и нет локального репо.
import { existsSync } from "node:fs";
import path from "node:path";
import { config } from "../config.js";

export type PublishResult = {
  apps: number;
  commit: string;
  pushed?: boolean;
  storeUrl: string;
};

export function publisherMode(): "local" | "github-api" {
  if (process.env.PUBLISHER === "github-api") return "github-api";
  if (process.env.PUBLISHER === "local") return "local";
  const hasLocalRepo = existsSync(path.join(config.repoDir, "store.yaml"));
  return process.env.GITHUB_TOKEN && !hasLocalRepo ? "github-api" : "local";
}

export async function publishApp(name: string, files: Record<string, Buffer | string>): Promise<PublishResult> {
  if (publisherMode() === "github-api") {
    const { remotePublishApp } = await import("./publisher-remote.js");
    return remotePublishApp(name, files);
  }
  const { publishApp: local } = await import("./publisher-local.js");
  return local(name, files);
}

export async function removeApp(name: string): Promise<PublishResult> {
  if (publisherMode() === "github-api") {
    const { remoteRemoveApp } = await import("./publisher-remote.js");
    return remoteRemoveApp(name);
  }
  const { removeApp: local } = await import("./publisher-local.js");
  return local(name);
}

export async function finalize(commitMsg: string): Promise<PublishResult> {
  if (publisherMode() === "github-api") {
    // remote-режим: пересобрать стор по удалённому состоянию без изменений приложений
    const { remoteReadApps } = await import("./publisher-remote.js");
    const apps = await remoteReadApps();
    if (!apps.length) throw new Error("Стор пуст");
    const { buildStoreFiles } = await import("./build-store.js");
    const { remoteClient } = await import("./publisher-remote.js");
    const gh = remoteClient();
    const commit = await gh.applyChanges(
      { ...buildStoreFiles(apps, config.storeBaseUrl) } as Record<string, string>,
      [],
      commitMsg,
    );
    return { apps: apps.length, commit, storeUrl: `${config.storeBaseUrl}/store.yaml` };
  }
  const { finalize: local } = await import("./publisher-local.js");
  return local(commitMsg);
}

/** Список приложений стора в любом режиме. */
export async function listApps(): Promise<Array<{ dir: string; manifest: any }>> {
  if (publisherMode() === "github-api") {
    const { remoteReadApps } = await import("./publisher-remote.js");
    return remoteReadApps();
  }
  const { readApps } = await import("./build-store.js");
  return readApps();
}
