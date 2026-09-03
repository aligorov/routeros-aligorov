// CLI: npm run cli -- <команда>
//   check <image>
//   add <image> [--name n] [--descr "d"] [--category c] [--env K=V]... [--port 8080:80]... [--commit]
//   list
//   remove <name> [--commit]
import { checkImage, formatInfo } from "./core/registry.js";
import { buildAppFiles } from "./core/converter.js";
import { readApps } from "./core/build-store.js";
import { publishApp, removeApp } from "./core/publisher-local.js";
import { config } from "./config.js";

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const flag = (name: string) => {
    const i = rest.indexOf(name);
    return i >= 0 ? (rest.splice(i, 2)[1] ?? "") : undefined;
  };
  const many = (name: string) => {
    const out: string[] = [];
    let v: string | undefined;
    while ((v = flag(name)) !== undefined) out.push(v);
    return out;
  };

  switch (cmd) {
    case "check": {
      if (!rest[0]) throw new Error("usage: check <image>");
      console.log(formatInfo(await checkImage(rest[0])));
      break;
    }
    case "add": {
      const image = rest[0];
      if (!image) throw new Error("usage: add <image> [опции]");
      const env: Record<string, string> = {};
      for (const kv of many("--env")) {
        const [k, ...v] = kv.split("=");
        if (!k || !v.length) throw new Error(`--env ожидает K=V, получено '${kv}'`);
        env[k] = v.join("=");
      }
      const ports = many("--port");
      const r = await buildAppFiles(image, {
        name: flag("--name"),
        descr: flag("--descr"),
        category: flag("--category"),
        env,
        ports,
      }, readApps());
      console.log(formatInfo(r.info));
      console.log(`\n--- apps/${r.name}/app.yaml ---\n${r.files["app.yaml"]}`);
      if (flag("--commit") !== undefined || config.allowCommit) {
        const res = await publishApp(r.name, r.files);
        console.log(
          res.pushed
            ? `\n✅ Опубликовано: ${res.commit} (приложений в сторе: ${res.apps})\n${res.storeUrl}`
            : `\n⚠️ Изменений нет (приложение уже было в таком виде)`,
        );
      } else {
        console.log("\n(dry-run: файлы НЕ записаны; добавьте --commit для публикации)");
      }
      break;
    }
    case "import": {
      const source = rest[0];
      if (!source) throw new Error("usage: import <docker-compose.yml | URL> [--name n] [--commit]");
      const { importCompose, loadCompose } = await import("./core/compose.js");
      const content = await loadCompose(source);
      const r = await importCompose(content, { name: flag("--name") });
      if (r.warnings.length) console.log(`\n⚠️ Предупреждения:\n${r.warnings.map((w) => `  - ${w}`).join("\n")}`);
      if (r.secretLocalEnv.length) {
        console.log(`\n🔒 Секреты сохранены ТОЛЬКО локально (введите при установке):`);
        for (const s of r.secretLocalEnv) console.log(`  ${s.split("=")[0]}=***`);
      }
      console.log(`\n--- apps/${r.name}/app.yaml ---\n${r.files["app.yaml"]}`);
      if (flag("--commit") !== undefined || config.allowCommit) {
        const res = await publishApp(r.name, r.files);
        console.log(
          res.pushed
            ? `\n✅ Опубликовано: ${res.commit} (приложений: ${res.apps})\n${res.storeUrl}`
            : "\n⚠️ Изменений нет",
        );
      } else {
        console.log("\n(dry-run: файлы НЕ записаны; добавьте --commit для публикации)");
      }
      break;
    }
    case "list": {
      for (const { dir, manifest } of readApps()) {
        const imgs = Object.values<any>(manifest.services ?? {})
          .map((s) => s.image)
          .join(", ");
        console.log(`- ${dir}  [${manifest.category ?? "?"}]  ${imgs}`);
      }
      break;
    }
    case "remove": {
      if (!rest[0]) throw new Error("usage: remove <name> [--commit]");
      if (flag("--commit") === undefined && !config.allowCommit) {
        console.log(`dry-run: удалить apps/${rest[0]} — добавьте --commit`);
        break;
      }
      const res = await removeApp(rest[0]);
      console.log(res.pushed ? `✅ Удалено, стор пересобран (${res.commit})` : "Изменений нет");
      break;
    }
    default:
      console.log(
        "Команды: check <image> | add <image> [--name --descr --category --env K=V --port h:c] [--commit] | list | remove <name> [--commit]",
      );
  }
}

main().catch((e) => {
  console.error(`❌ ${e.message}`);
  process.exit(1);
});
