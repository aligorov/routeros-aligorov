// M3: HTTP-вход — streamable HTTP MCP на /mcp (bearer MCP_TOKEN) + /healthz.
// Запуск: MCP_TOKEN=... PORT=8765 npm run http
import http from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { registerTools } from "./tools.js";
import { config } from "./config.js";

if (!config.mcpToken) {
  console.warn("⚠️  MCP_TOKEN не задан — эндпоинт /mcp открыт БЕЗ авторизации!");
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
