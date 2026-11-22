// Общий набор MCP-инструментов store-combine (используется stdio и http входами).
import path from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkImage, formatInfo } from "./core/registry.js";
import { buildAppFiles } from "./core/converter.js";
import { publishApp, removeApp, finalize, listApps, publisherMode } from "./core/publisher.js";
import { config } from "./config.js";

export const text = (s: string) => ({ content: [{ type: "text" as const, text: s }] });

export function registerTools(server: McpServer): void {
  server.registerTool(
    "check_image",
    {
      description:
        "Проверить Docker-образ (docker.io/ghcr.io): arm64 (ARM), amd64 (CHR), размер, порты, env. Без побочных эффектов.",
      inputSchema: { image: z.string().describe("например docker.io/library/nginx:1.27-alpine") },
    },
    async ({ image }) => text(formatInfo(await checkImage(image))),
  );

  server.registerTool(
    "add_docker_image",
    {
      description:
        "Конвертировать Docker-образ в приложение RouterOS app-store (ARM64 и/или CHR x86_64). По умолчанию dry-run " +
        "(возвращает YAML); commit:true — записать и опубликовать в стор.",
      inputSchema: {
        image: z.string(),
        name: z.string().optional(),
        descr: z.string().optional(),
        category: z.string().optional(),
        env: z.record(z.string(), z.string()).optional(),
        ports: z.array(z.string()).optional().describe('["8080:80", "53:53/udp"]'),
        volumes: z.array(z.string()).optional().describe('["data:/var/lib/app"]'),
        arch: z.enum(["any", "arm64", "amd64", "chr", "both"]).optional().describe("требуемая архитектура: any (по умолчанию), arm64, amd64/chr, both"),
        commit: z.boolean().optional(),
      },
    },
    async (p) => {
      const r = await buildAppFiles(p.image, {
        name: p.name,
        descr: p.descr,
        category: p.category,
        env: p.env,
        ports: p.ports,
        volumes: p.volumes,
        arch: p.arch,
      }, await listApps());
      let out = formatInfo(r.info) + `\n\napps/${r.name}/app.yaml:\n${r.files["app.yaml"]}`;
      if (p.commit) {
        const res = await publishApp(r.name, r.files);
        out += res.commit
          ? `\n\n✅ Опубликовано: ${res.commit}; стор: ${res.storeUrl}`
          : "\n\n⚠️ Изменений нет";
      } else {
        out += "\n\n(dry-run; commit:true или publish_app для публикации)";
      }
      return text(out);
    },
  );

  server.registerTool(
    "import_compose",
    {
      description:
        "Импортировать docker-compose.yml (локальный путь или URL) в одно приложение RouterOS (ARM64 и/или CHR x86_64). " +
        "По умолчанию dry-run; commit:true — опубликовать.",
      inputSchema: {
        source: z.string().describe("путь к docker-compose.yml или https://URL"),
        name: z.string().optional(),
        arch: z.enum(["any", "arm64", "amd64", "chr", "both"]).optional(),
        commit: z.boolean().optional(),
      },
    },
    async (p) => {
      const { importCompose, loadCompose } = await import("./core/compose.js");
      const isRemote = /^https?:\/\//.test(p.source);
      const r = await importCompose(await loadCompose(p.source), {
        name: p.name,
        arch: p.arch,
        ...(isRemote
          ? { allowEnvFile: false }
          : { baseDir: path.dirname(path.resolve(p.source)) }),
      });
      let out = `apps/${r.name}/app.yaml:\n${r.files["app.yaml"]}`;
      if (r.warnings.length) out += `\n\n⚠️ Предупреждения:\n${r.warnings.map((w) => `- ${w}`).join("\n")}`;
      if (r.secretLocalEnv.length) {
        out += `\n\n🔒 Секреты вводятся при установке (значения НЕ в репо): ${r.secretLocalEnv.map((s) => s.split("=")[0]).join(", ")}`;
      }
      if (p.commit) {
        const res = await publishApp(r.name, r.files);
        out += res.commit ? `\n\n✅ Опубликовано: ${res.commit}; стор: ${res.storeUrl}` : "\n\n⚠️ Изменений нет";
      } else {
        out += "\n\n(dry-run; commit:true для публикации)";
      }
      return text(out);
    },
  );

  server.registerTool(
    "publish_app",
    {
      description: "Опубликовать изменения (после ручной правки): валидация, пересборка store.yaml, push.",
      inputSchema: { name: z.string().optional() },
    },
    async () => {
      const res = await finalize("combine: publish");
      return text(res.commit ? `✅ ${res.commit}, стор: ${res.storeUrl}` : "Изменений нет");
    },
  );

  server.registerTool("list_apps", { description: "Приложения в сторе" }, async () => {
    const apps = await listApps();
    return text(
      apps
        .map(({ dir, manifest }) => {
          const imgs = Object.values<any>(manifest.services ?? {}).map((s) => s.image).join(", ");
          return `- ${dir} [${manifest.category ?? "?"}] ${imgs}`;
        })
        .join("\n") || "(пусто)",
    );
  });

  server.registerTool(
    "remove_app",
    { description: "Удалить приложение из стора.", inputSchema: { name: z.string() } },
    async ({ name }) => {
      const res = await removeApp(name);
      return text(res.commit ? `✅ Удалено (${res.commit})` : "Изменений нет");
    },
  );

  server.registerTool("store_status", { description: "Состояние стора: приложения, URL, режим." }, async () => {
    const apps = await listApps();
    return text(
      `Приложений: ${apps.length} (${apps.map((a) => a.dir).join(", ")})\n` +
        `Стор: ${config.storeBaseUrl}/store.yaml\nРежим публикации: ${publisherMode()}`,
    );
  });
}
