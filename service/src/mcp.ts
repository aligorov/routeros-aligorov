// MCP server (stdio): инструменты комбайна для ИИ-агента.
// Запуск: npm run mcp
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools.js";

const server = new McpServer({ name: "store-combine", version: "0.2.0" });
registerTools(server);
await server.connect(new StdioServerTransport());
