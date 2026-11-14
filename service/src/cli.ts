// CLI: npm run cli -- <команда>
//   check <image>
//   add <image> [--name n] [--descr "d"] [--category c] [--env K=V]... [--port 8080:80]... [--commit]
//   list
//   remove <name> [--commit]
import path from "node:path";
import { checkImage, formatInfo } from "./core/registry.js";
import { buildAppFiles } from "./core/converter.js";
import { listApps, publishApp, removeApp, publisherMode } from "./core/publisher.js";
import { config } from "./config.js";

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const flag = (name: string) => {
    const i = rest.indexOf(name);
    return i >= 0 ? (rest.splice(i, 2)[1] ?? "") : undefined;
  };
  const boolFlag = (name: string): boolean => {
    const i = rest.indexOf(name);
    if (i >= 0) {
      rest.splice(i, 1);
      return true;
    }
    return false;
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
      const commit = boolFlag("--commit");
      const env: Record<string, string> = {};
      for (const kv of many("--env")) {
        const [k, ...v] = kv.split("=");
        if (!k || !v.length) throw new Error(`--env ожидает K=V, получено '${kv}'`);
        env[k] = v.join("=");
      }
      const ports = many("--port");
      const volumes = many("--volume");
      const name = flag("--name");
      const descr = flag("--descr");
      const category = flag("--category");
      const image = rest[0];
      if (!image) throw new Error("usage: add <image> [опции]");
      const r = await buildAppFiles(image, {
        name,
        descr,
        category,
        env,
        ports,
        volumes,
      }, await listApps());
      console.log(formatInfo(r.info));
      console.log(`\n--- apps/${r.name}/app.yaml ---\n${r.files["app.yaml"]}`);
      if (commit || config.allowCommit) {
        const res = await publishApp(r.name, r.files);
        console.log(
          res.commit
            ? `\n✅ Опубликовано: ${res.commit} (приложений в сторе: ${res.apps})\n${res.storeUrl}`
            : "\n⚠️ Изменений нет (приложение уже было в таком виде)",
        );
      } else {
        console.log("\n(dry-run: файлы НЕ записаны; добавьте --commit для публикации)");
      }
      break;
    }
    case "import": {
      const commit = boolFlag("--commit");
      const name = flag("--name");
      const source = rest[0];
      if (!source) throw new Error("usage: import <docker-compose.yml | URL> [--name n] [--commit]");
      const { importCompose, loadCompose } = await import("./core/compose.js");
      const isRemote = /^https?:\/\//.test(source);
      const content = await loadCompose(source);
      const r = await importCompose(content, {
        name,
        ...(isRemote
          ? { allowEnvFile: false }
          : { baseDir: path.dirname(path.resolve(source)) }),
      });
      if (r.warnings.length) console.log(`\n⚠️ Предупреждения:\n${r.warnings.map((w) => `  - ${w}`).join("\n")}`);
      if (r.secretLocalEnv.length) {
        console.log(`\n🔒 Секреты сохранены ТОЛЬКО локально (введите при установке):`);
        for (const s of r.secretLocalEnv) console.log(`  ${s.split("=")[0]}=***`);
      }
      console.log(`\n--- apps/${r.name}/app.yaml ---\n${r.files["app.yaml"]}`);
      if (commit || config.allowCommit) {
        const res = await publishApp(r.name, r.files);
        console.log(
          res.commit
            ? `\n✅ Опубликовано: ${res.commit} (приложений: ${res.apps})\n${res.storeUrl}`
            : "\n⚠️ Изменений нет",
        );
      } else {
        console.log("\n(dry-run: файлы НЕ записаны; добавьте --commit для публикации)");
      }
      break;
    }
    case "list": {
      for (const { dir, manifest } of await listApps()) {
        const imgs = Object.values<any>(manifest.services ?? {})
          .map((s) => s.image)
          .join(", ");
        console.log(`- ${dir}  [${manifest.category ?? "?"}]  ${imgs}`);
      }
      console.log(`(режим публикации: ${publisherMode()})`);
      break;
    }
    case "remove": {
      const commit = boolFlag("--commit");
      if (!rest[0]) throw new Error("usage: remove <name> [--commit]");
      if (!commit && !config.allowCommit) {
        console.log(`dry-run: удалить apps/${rest[0]} — добавьте --commit`);
        break;
      }
      const res = await removeApp(rest[0]);
      console.log(res.commit ? `✅ Удалено, стор пересобран (${res.commit})` : "Изменений нет");
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
