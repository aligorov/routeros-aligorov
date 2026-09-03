// Минимальный клиент GitHub REST API: атомарные коммиты через Git Data API.
import { config } from "../config.js";

export interface TreeItem {
  path: string;
  mode: "100644";
  type: "blob";
  sha: string | null; // null = удалить
}

export class GitHub {
  constructor(
    private token: string,
    private repo: string = config.githubRepo,
  ) {}

  private async api(path: string, init: RequestInit = {}): Promise<any> {
    const r = await fetch(`https://api.github.com/repos/${this.repo}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${this.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "store-combine",
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...(init.headers ?? {}),
      },
    });
    if (!r.ok) {
      const t = await r.text().catch(() => "");
      throw new Error(`GitHub API ${path}: HTTP ${r.status} ${t.slice(0, 200)}`);
    }
    return r.status === 204 ? null : r.json();
  }

  /** sha последнего коммита ветки */
  ref(branch = "main"): Promise<{ object: { sha: string } }> {
    return this.api(`/git/ref/heads/${branch}`);
  }

  commit(sha: string): Promise<{ tree: { sha: string } }> {
    return this.api(`/git/commits/${sha}`);
  }

  createBlob(content: string | Buffer, encoding: "utf-8" | "base64"): Promise<{ sha: string }> {
    return this.api(`/git/blobs`, {
      method: "POST",
      body: JSON.stringify({
        content: Buffer.isBuffer(content) ? content.toString("base64") : content,
        encoding,
      }),
    });
  }

  createTree(baseTree: string, tree: TreeItem[]): Promise<{ sha: string }> {
    return this.api(`/git/trees`, {
      method: "POST",
      body: JSON.stringify({ base_tree: baseTree, tree }),
    });
  }

  createCommit(message: string, tree: string, parents: string[]): Promise<{ sha: string }> {
    return this.api(`/git/commits`, {
      method: "POST",
      body: JSON.stringify({ message, tree, parents }),
    });
  }

  updateRef(branch: string, sha: string): Promise<unknown> {
    return this.api(`/git/refs/heads/${branch}`, {
      method: "PATCH",
      body: JSON.stringify({ sha, force: false }),
    });
  }

  /** Содержимое каталога: [{name, path, sha, type}] */
  listDir(dirPath: string): Promise<Array<{ name: string; path: string; sha: string; type: string }>> {
    return this.api(`/contents/${dirPath}`);
  }

  /** Текст файла (utf-8), null если 404 */
  async fileText(path: string): Promise<string | null> {
    const r = await fetch(`https://api.github.com/repos/${this.repo}/contents/${path}`, {
      headers: {
        Authorization: `Bearer ${this.token}`,
        Accept: "application/vnd.github.raw+json",
        "User-Agent": "store-combine",
      },
    });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`GitHub contents ${path}: HTTP ${r.status}`);
    return r.text();
  }

  /** Атомарный коммит набора изменений в ветку. Возвращает короткий sha. */
  async applyChanges(
    adds: Record<string, Buffer | string>,
    removes: string[],
    message: string,
    branch = "main",
  ): Promise<string> {
    const { object } = await this.ref(branch);
    const { tree } = await this.commit(object.sha);

    const treeItems: TreeItem[] = [];
    for (const [p, content] of Object.entries(adds)) {
      const sha = await this.createBlob(content, "utf-8").then((b) => b.sha);
      treeItems.push({ path: p, mode: "100644", type: "blob", sha });
    }
    for (const p of removes) {
      treeItems.push({ path: p, mode: "100644", type: "blob", sha: null });
    }
    const newTree = await this.createTree(tree.sha, treeItems);
    const commit = await this.createCommit(message, newTree.sha, [object.sha]);
    await this.updateRef(branch, commit.sha);
    return commit.sha.slice(0, 7);
  }
}
