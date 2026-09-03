import * as AjvNS from "ajv";
import * as FormatsNS from "ajv-formats";
import { readFileSync } from "node:fs";
import { schemaPath } from "../config.js";

const AjvCtor: any = (AjvNS as any).default ?? AjvNS; // CJS-интероп под NodeNext
const addFormats: any = (FormatsNS as any).default ?? FormatsNS;
const ajv = new AjvCtor({ allErrors: true, strict: false });
addFormats(ajv);
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const validateFn = ajv.compile(schema);

export interface AppManifest {
  [k: string]: any;
}

/** Ошибки манифеста по официальной схеме RouterOS; пустой список = валиден. */
export function manifestErrors(doc: AppManifest): string[] {
  // в исходнике apps/*/app.yaml иконка может быть относительной (build.ts
  // перепишет её на абсолютный URL) — для проверки схемы подставляем заглушку
  const probe =
    doc.icon && !String(doc.icon).startsWith("http")
      ? { ...doc, icon: "https://example.com/icon.png" }
      : doc;
  const ok = validateFn(probe);
  if (ok) return [];
  return (validateFn.errors ?? []).map(
    (e: any) => `${e.instancePath || "/"}: ${e.message ?? e.keyword}`,
  );
}

export function assertValid(doc: AppManifest, label: string): void {
  const errors = manifestErrors(doc);
  if (errors.length) {
    throw new Error(`${label}: манифест не прошёл схему:\n  - ${errors.join("\n  - ")}`);
  }
}
