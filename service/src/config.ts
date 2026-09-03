import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url)); // .../service/src

export const config = {
  repoDir: process.env.REPO_DIR ?? path.resolve(here, "../.."),
  storeBaseUrl:
    process.env.STORE_BASE_URL ?? "https://aligorov.github.io/routeros-aligorov",
  githubRepo: process.env.GITHUB_REPO ?? "aligorov/routeros-aligorov",
  telegramBotToken: process.env.TELEGRAM_BOT_TOKEN ?? "",
  telegramAllowedIds: (process.env.TELEGRAM_ALLOWED_IDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map(Number),
  allowCommit: process.env.ALLOW_COMMIT === "1",
  mcpToken: process.env.MCP_TOKEN ?? "",
  httpPort: Number(process.env.PORT ?? 8765),
};

export const schemaPath = path.join(
  config.repoDir,
  "schemas",
  "routeros-app-yaml.schema.json",
);
