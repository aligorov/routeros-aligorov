// Telegram-бот: добавление Docker-образов в стор по команде + кнопка подтверждения.
// Запуск: TELEGRAM_BOT_TOKEN=... TELEGRAM_ALLOWED_IDS=123,456 npm run bot
import { Bot, Context, InlineKeyboard } from "grammy";
import { checkImage, formatInfo } from "./core/registry.js";
import { buildAppFiles } from "./core/converter.js";
import { listApps, publishApp, removeApp } from "./core/publisher.js";
import { config } from "./config.js";

interface Pending {
  kind: "add" | "remove";
  name: string;
  files?: Record<string, Buffer | string>;
  info?: string;
}
const pending = new Map<number, Pending>(); // userId -> последнее предложение

if (!config.telegramBotToken) {
  console.error("Нет TELEGRAM_BOT_TOKEN (см. .env.example). Бот не запущен.");
  process.exit(1);
}
if (!config.telegramAllowedIds.length) {
  console.error(
    "TELEGRAM_ALLOWED_IDS пуст — бот никому не ответит. Укажите свой Telegram ID (см. .env.example).",
  );
  process.exit(1);
}

const bot = new Bot(config.telegramBotToken);

bot.use(async (ctx, next) => {
  const uid = ctx.from?.id;
  if (!uid || !config.telegramAllowedIds.includes(uid)) return; // чужим не отвечаем
  await next();
});

bot.command("start", (ctx) => ctx.reply(help(), { parse_mode: "HTML" }));
bot.command("help", (ctx) => ctx.reply(help(), { parse_mode: "HTML" }));

bot.command("check", async (ctx) => {
  const image = ctx.match?.trim();
  if (!image) return ctx.reply("Использование: /check <образ>\nНапример: /check docker.io/library/redis:7-alpine");
  await ctx.replyWithChatAction("typing");
  try {
    ctx.reply(formatInfo(await checkImage(image)));
  } catch (e: any) {
    ctx.reply(`❌ ${e.message}`);
  }
});

bot.command("add", async (ctx) => {
  const parts = (ctx.match ?? "").trim().split(/\s+/).filter(Boolean);
  const image = parts[0];
  if (!image) {
    return ctx.reply(
      "Использование: /add <образ> [имя]\nНапример: /add docker.io/library/redis:7-alpine redis",
    );
  }
  await ctx.replyWithChatAction("typing");
  try {
    const r = await buildAppFiles(image, { name: parts[1] }, await listApps());
    pending.set(ctx.from!.id, { kind: "add", name: r.name, files: r.files, info: formatInfo(r.info) });
    const yaml = String(r.files["app.yaml"]);
    const body = yaml.length > 2800 ? yaml.slice(0, 2800) + "\n…" : yaml;
    await ctx.reply(
      `${formatInfo(r.info)}\n\n<b>apps/${r.name}/app.yaml</b>\n<pre>${escape(body)}</pre>\n\nПубликовать в стор?`,
      {
        parse_mode: "HTML",
        reply_markup: new InlineKeyboard()
          .text("✅ Опубликовать", "pub")
          .text("Отмена", "cancel"),
      },
    );
  } catch (e: any) {
    ctx.reply(`❌ ${e.message}`);
  }
});

bot.command("import", async (ctx) => {
  const source = ctx.match?.trim();
  if (!source) {
    return ctx.reply(
      "Использование: /import <URL docker-compose.yml>\n" +
        "Или просто пришлите файл docker-compose.yml документом 📎",
    );
  }
  await doImport(ctx, source);
});

// приём compose-файла документом
bot.on(":document", async (ctx) => {
  const doc = ctx.message?.document;
  if (!doc || !/\.(ya?ml)$/i.test(doc.file_name ?? "")) return;
  const f = await ctx.getFile();
  if (!f.file_path) return ctx.reply("Не смог получить файл");
  const url = `https://api.telegram.org/file/bot${config.telegramBotToken}/${f.file_path}`;
  await doImport(ctx, url, doc.file_name);
});

async function doImport(ctx: Context, source: string, label?: string) {
  await ctx.replyWithChatAction("typing");
  try {
    const { importCompose, loadCompose } = await import("./core/compose.js");
    const r = await importCompose(await loadCompose(source));
    pending.set(ctx.from!.id, { kind: "add", name: r.name, files: r.files });
    const yaml = String(r.files["app.yaml"]);
    const body = yaml.length > 2600 ? yaml.slice(0, 2600) + "\n…" : yaml;
    let msg = `<b>${escape(label ?? "docker-compose.yml")} → apps/${escape(r.name)}</b>\n`;
    if (r.warnings.length) {
      msg += `\n⚠️ Предупреждения:\n${r.warnings.slice(0, 10).map((w) => `• ${escape(w)}`).join("\n")}\n`;
    }
    if (r.secretLocalEnv.length) {
      msg += `\n🔒 Секреты (${r.secretLocalEnv.length} шт.) — значения вводятся при установке на роутере.\n`;
    }
    msg += `\n<pre>${escape(body)}</pre>\n\nПубликовать в стор?`;
    await ctx.reply(msg, {
      parse_mode: "HTML",
      reply_markup: new InlineKeyboard().text("✅ Опубликовать", "pub").text("Отмена", "cancel"),
    });
  } catch (e: any) {
    ctx.reply(`❌ ${e.message}`);
  }
}

bot.command("list", async (ctx) => {
  const apps = (await listApps())
    .map(({ dir, manifest }) => {
      const imgs = Object.values<any>(manifest.services ?? {}).map((s) => s.image).join(", ");
      return `• <b>${escape(dir)}</b> [${escape(manifest.category ?? "?")}] <code>${escape(imgs)}</code>`;
    })
    .join("\n");
  ctx.reply(apps || "(стор пуст)", { parse_mode: "HTML" });
});

bot.command("remove", async (ctx) => {
  const name = ctx.match?.trim();
  if (!name) return ctx.reply("Использование: /remove <имя>");
  if (!(await listApps()).some((a) => a.dir === name)) return ctx.reply(`Нет приложения: ${name}`);
  pending.set(ctx.from!.id, { kind: "remove", name });
  ctx.reply(`Удалить <b>${escape(name)}</b> из стора?`, {
    parse_mode: "HTML",
    reply_markup: new InlineKeyboard().text("🗑 Удалить", "pub").text("Отмена", "cancel"),
  });
});

bot.callbackQuery("pub", async (ctx) => {
  const p = pending.get(ctx.from.id);
  if (!p) return ctx.answerCallbackQuery({ text: "Нечего публиковать" });
  await ctx.answerCallbackQuery();
  await ctx.editMessageText("⏳ Публикую…");
  try {
    const res =
      p.kind === "add"
        ? await publishApp(p.name, p.files!)
        : await removeApp(p.name);
    await ctx.editMessageText(
      res.commit
        ? `✅ Готово (${res.commit}); приложений в сторе: ${res.apps}.\nСтор: ${res.storeUrl}\nОбновится на роутере в течение ~1 мин.`
        : "Изменений нет (уже опубликовано в таком виде).",
      { parse_mode: undefined },
    );
  } catch (e: any) {
    ctx.editMessageText(`❌ ${e.message}`);
  } finally {
    pending.delete(ctx.from.id);
  }
});

bot.callbackQuery("cancel", async (ctx) => {
  pending.delete(ctx.from.id);
  await ctx.answerCallbackQuery({ text: "Отменено" });
  ctx.editMessageText("Отменено.");
});

function help(): string {
  return [
    "<b>store-combine — комбайн app-store для MikroTik</b>",
    "",
    "/check <образ> — проверить (arm64, размер, порты)",
    "/add <образ> [имя] — конвертировать и предложить публикацию",
    "/import <URL> или файл .yml документом — импорт docker-compose",
    "/list — приложения в сторе",
    "/remove <имя> — удалить из стора",
    "",
    "Образ: docker.io/library/nginx:1.27-alpine, ghcr.io/owner/image:tag",
  ].join("\n");
}

function escape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

bot.catch((err) => console.error("bot error:", err.error));
bot.start({ drop_pending_updates: true }).catch((e) => {
  console.error("Бот упал:", e.message);
  process.exit(1);
});
console.log(`Бот запущен (разрешённые ID: ${config.telegramAllowedIds.join(", ")})`);
