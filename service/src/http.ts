// M3: HTTP-вход — streamable HTTP MCP на /mcp (bearer MCP_TOKEN) + /healthz.
// Запуск: MCP_TOKEN=... PORT=8765 npm run http
import http from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { registerTools } from "./tools.js";
import { config } from "./config.js";
import { publisherMode, listApps } from "./core/publisher.js";

if (!config.mcpToken) {
  console.warn("⚠️  MCP_TOKEN не задан — эндпоинт /mcp открыт БЕЗ авторизации!");
}

const esc = (s: any) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

async function statusPage(res: http.ServerResponse): Promise<void> {
  let appsHtml = "<em>(не удалось прочитать стор)</em>";
  try {
    const apps = await listApps();
    appsHtml = apps.length
      ? `<ul>${apps
          .map((a) => `<li><b>${esc(a.dir)}</b> <code>${esc(a.manifest.category ?? "")}</code></li>`)
          .join("")}</ul>`
      : "<em>(стор пуст)</em>";
  } catch (e: any) {
    appsHtml = `<em>${esc(e.message)}</em>`;
  }
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>store-combine</title>
<style>
 body{font-family:-apple-system,system-ui,sans-serif;background:#111418;color:#e5e7eb;margin:40px auto;max-width:680px}
 h1{font-size:1.4em} code{background:#1b2027;padding:2px 6px;border-radius:5px}
 .ok{color:#34d399} .box{background:#1b2027;border:1px solid #2a303a;border-radius:10px;padding:16px;margin:12px 0}
 ul{margin:8px 0} em{color:#9ca3af}
</style></head><body>
<h1>store-combine — комбайн app-store</h1>
<p class="ok">✅ Сервис работает</p>
<div class="box"><b>MCP-эндпоинт:</b> <code>POST /mcp</code><br>
<b>Авторизация:</b> Bearer-токен (переменная MCP_TOKEN)<br>
<b>Режим публикации:</b> ${esc(publisherMode())}<br>
<b>Healthcheck:</b> <a href="/healthz" style="color:#60a5fa">/healthz</a></div>
<div class="box"><b>Инструменты:</b> check_image, add_docker_image, import_compose,
publish_app, list_apps, remove_app, store_status<br>
<em>Это API для ИИ-агента (MCP-протокол), не веб-интерфейс:
откройте в агенте http://host:8765/mcp с заголовком Authorization.</em></div>
<div class="box"><b>Приложения в сторе:</b>${appsHtml}</div>
</body></html>`);
}

function makeServer(): McpServer {
  const server = new McpServer({ name: "store-combine", version: "0.2.0" });
  registerTools(server);
  return server;
}

async function readBody(req: http.IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

const srv = http.createServer(async (req, res) => {
  const url = req.url ?? "";

  if (url === "/" || url === "/index.html") {
    return statusPage(res);
  }

  if (url === "/healthz") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ok: true, mode: "http" }));
  }

  if (url === "/mcp" || url === "/mcp/") {
    if (config.mcpToken && req.headers.authorization !== `Bearer ${config.mcpToken}`) {
      res.writeHead(401, { "WWW-Authenticate": 'Bearer realm="mcp"' });
      return res.end();
    }
    if (req.method === "POST") {
      try {
        const body = await readBody(req);
        // stateless: на каждый запрос новая пара server+transport
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });
        const server = makeServer();
        res.on("close", () => {
          server.close();
          transport.close();
        });
        await server.connect(transport);
        await transport.handleRequest(req, res, body);
      } catch (e: any) {
        if (!res.headersSent) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32700, message: e.message } }));
        }
      }
      return;
    }
    // stateless-режим: GET (SSE-стрим сессий) не поддерживаем
    res.writeHead(405, { Allow: "POST" });
    return res.end();
  }

  res.writeHead(404);
  res.end("not found; see /mcp, /healthz");
});

srv.listen(config.httpPort, () => {
  console.log(`store-combine HTTP: http://localhost:${config.httpPort}/mcp (healthz: /healthz)`);
});
