// MCP server (stdio): инструменты комбайна для ИИ-агента.
// Запуск: npm run mcp  (или node --import tsx src/mcp.ts)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { checkImage, formatInfo } from "./core/registry.js";
import { buildAppFiles } from "./core/converter.js";
import { readApps, rebuildStore } from "./core/build-store.js";
import { publishApp, removeApp } from "./core/publisher-local.js";
import { config } from "./config.js";

const server = new McpServer({ name: "store-combine", version: "0.1.0" });

const text = (s: string) => ({ content: [{ type: "text" as const, text: s }] });

server.registerTool(
  "check_image",
  {
    description:
      "Проверить Docker-образ (docker.io/ghcr.io): arm64, размер, порты, env. Без побочных эффектов.",
    inputSchema: { image: z.string().describe("например docker.io/library/nginx:1.27-alpine") },
  },
  async ({ image }) => text(formatInfo(await checkImage(image))),
);

server.registerTool(
  "add_docker_image",
  {
    description:
      "Конвертировать Docker-образ в приложение RouterOS app-store. По умолчанию dry-run " +
      "(возвращает YAML); commit:true — записать и опубликовать в стор (git push).",
    inputSchema: {
      image: z.string(),
      name: z.string().optional(),
      descr: z.string().optional(),
      category: z.string().optional(),
      env: z.record(z.string(), z.string()).optional(),
      ports: z.array(z.string()).optional().describe('["8080:80", "53:53/udp"]'),
      commit: z.boolean().optional(),
    },
  },
  async (p) => {
    const r = await buildAppFiles(
      p.image,
      {
        name: p.name,
        descr: p.descr,
        category: p.category,
        env: p.env,
        ports: p.ports,
      },
      readApps(),
    );
    let out = formatInfo(r.info) + `\n\napps/${r.name}/app.yaml:\n${r.files["app.yaml"]}`;
    if (p.commit) {
      const res = await publishApp(r.name, r.files);
      out += res.pushed
        ? `\n\n✅ Опубликовано: ${res.commit}; стор: ${res.storeUrl}`
        : "\n\n⚠️ Изменений нет";
    } else {
      out += "\n\n(dry-run; вызовите с commit:true или publish_app для публикации)";
    }
    return text(out);
  },
);

server.registerTool(
  "publish_app",
  {
    description:
      "Опубликовать приложение (после ручной правки apps/<name>/app.yaml): валидация, пересборка store.yaml, git push.",
    inputSchema: { name: z.string().optional() },
  },
  async () => {
    const { finalize } = await import("./core/publisher-local.js");
    const res = await finalize("combine: publish");
    return text(res.pushed ? `✅ ${res.commit}, стор: ${res.storeUrl}` : "Изменений нет");
  },
);

server.registerTool(
  "import_compose",
  {
    description:
      "Импортировать docker-compose.yml (локальный путь или URL) в одно приложение RouterOS. " +
      "По умолчанию dry-run (возвращает YAML + предупреждения); commit:true — опубликовать.",
    inputSchema: {
      source: z.string().describe("путь к docker-compose.yml или https://URL"),
      name: z.string().optional(),
      commit: z.boolean().optional(),
    },
  },
  async (p) => {
    const { importCompose, loadCompose } = await import("./core/compose.js");
    const r = await importCompose(await loadCompose(p.source), { name: p.name });
    let out = `apps/${r.name}/app.yaml:\n${r.files["app.yaml"]}`;
    if (r.warnings.length) out += `\n\n⚠️ Предупреждения:\n${r.warnings.map((w) => `- ${w}`).join("\n")}`;
    if (r.secretLocalEnv.length) {
      out += `\n\n🔒 Секреты вводятся при установке (значения НЕ в репо): ${r.secretLocalEnv.map((s) => s.split("=")[0]).join(", ")}`;
    }
    if (p.commit) {
      const res = await publishApp(r.name, r.files);
      out += res.pushed ? `\n\n✅ Опубликовано: ${res.commit}; стор: ${res.storeUrl}` : "\n\n⚠️ Изменений нет";
    } else {
      out += "\n\n(dry-run; commit:true для публикации)";
    }
    return text(out);
  },
);

server.registerTool("list_apps", { description: "Приложения в сторе (локальный репо)" }, async () =>
  text(
    readApps()
      .map(({ dir, manifest }) => {
        const imgs = Object.values<any>(manifest.services ?? {}).map((s) => s.image).join(", ");
        return `- ${dir} [${manifest.category ?? "?"}] ${imgs}`;
      })
      .join("\n") || "(пусто)",
  ),
);

server.registerTool(
  "remove_app",
  {
    description: "Удалить приложение из стора (apps/<name>/ + пересборка + push).",
    inputSchema: { name: z.string() },
  },
  async ({ name }) => {
    const res = await removeApp(name);
    return text(res.pushed ? `✅ Удалено (${res.commit})` : "Изменений нет");
  },
);

server.registerTool(
  "store_status",
  { description: "Состояние стора: число приложений, URL." },
  async () => {
    const apps = readApps().map((a) => a.dir);
    rebuildStore(); // поддерживаем сгенерированные файлы актуальными локально
    return text(
      `Приложений: ${apps.length} (${apps.join(", ")})\nСтор: ${config.storeBaseUrl}/store.yaml\nРепо: ${config.githubRepo}`,
    );
  },
);

await server.connect(new StdioServerTransport());
