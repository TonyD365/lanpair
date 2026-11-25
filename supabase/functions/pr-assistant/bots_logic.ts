// Decisions for commands, issue triage and file labels, with no network access.
import { addressed } from "./logic.ts";

export type Command = { cmd: string; arg: string; rest: string };

export function parseCommand(body: string): Command | null {
  const text = addressed(body);
  if (text === null) return null;
  const line = text.split("\n")[0].replaceAll("\r", "").trim();
  const m = line.match(/^(\/[A-Za-z]+)(?:\s+(.*))?$/);
  if (!m) return null;
  const rest = (m[2] ?? "").trim();
  return { cmd: m[1].toLowerCase(), arg: (rest.split(/\s+/)[0] ?? "").toLowerCase(), rest };
}

export function isMaintainer(role: string): boolean {
  return ["OWNER", "MEMBER", "COLLABORATOR"].includes(role);
}

export function remindSeconds(arg: string): number | null {
  const m = arg.match(/^([1-9][0-9]{0,2})([dh])$/);
  if (!m) return null;
  const seconds = Number(m[1]) * (m[2] === "d" ? 86400 : 3600);
  return seconds <= 30 * 86400 ? seconds : null;
}

export function labelNames(rest: string): string[] {
  return rest.split(/[,\s]+/).filter(Boolean);
}

export function reminderNote(rest: string): string {
  return rest.replace(/^\S+\s*/, "").replace(/[`<>@]/g, "").slice(0, 200);
}

const AREAS: [RegExp, string][] = [
  [/discover|mdns|zeroconf|bonjour|find(ing)? (the )?device|发现/, "discovery"],
  [/pair(ing)?|qr|code|配对|扫码/, "pairing"],
  [/sign(ature)?|verify|replay|envelope|签名|验证/, "crypto"],
  [/keychain|key ?store|credential manager|keyring|密钥|钥匙串/, "keystore"],
  [/install|pip|wheel|安装/, "installing"],
  [/windows|win(10|11)/, "platform: Windows"],
  [/macos|mac os|apple silicon|intel mac|macbook|imac|苹果/, "platform: macOS"],
  [/linux|ubuntu|debian|fedora|arch|raspberry|appimage|树莓派/, "platform: Linux"],
];

export function triageLabels(title: string, body: string): string[] {
  const text = `${title}\n${body}`.toLowerCase();
  return AREAS.filter(([re]) => re.test(text)).map(([, label]) => label);
}

export function missingInfo(title: string, body: string): string[] {
  const text = `${title}\n${body}`.toLowerCase();
  const missing: string[] = [];
  if (!/[0-9]+\.[0-9]+\.[0-9]+/.test(text)) {
    missing.push("the **lanpair version** (`pip show lanpair`)");
  }
  if (!/windows|macos|mac os|apple silicon|intel|linux|ubuntu|debian|fedora|raspberry/.test(text)) {
    missing.push("your **system** (macOS, Windows or Linux, and which version)");
  }
  return missing;
}

export function fixedIssues(title: string, body: string): number[] {
  const found = `${title}\n${body}`.matchAll(
    /(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?) +#([0-9]+)/gi,
  );
  return [...new Set([...found].map((m) => Number(m[1])))].sort((a, b) => a - b);
}

export function fileLabels(files: string[]): string[] {
  const rules: [string, (f: string) => boolean][] = [
    [
      "crypto",
      (f) => /^src\/lanpair\/(identity\.py|envelope\.py|pairing.*\.py|channel.*\.py)$/.test(f),
    ],
    ["discovery", (f) => /^src\/lanpair\/discovery.*\.py$/.test(f)],
    ["keystore", (f) => /^src\/lanpair\/keystore.*\.py$/.test(f)],
    ["ci", (f) => f.startsWith(".github/")],
    [
      "documentation",
      (f) => /^[^/]+\.md$/.test(f) || f.startsWith("docs/") || f.startsWith("site/"),
    ],
    ["dependencies", (f) => f === "pyproject.toml"],
    ["tests", (f) => f.startsWith("tests/")],
  ];
  return rules.filter(([, match]) => files.some(match)).map(([label]) => label);
}

export type StaleAction = "none" | "mark" | "unmark" | "close";

export function staleAction(o: {
  labels: string[];
  lastActivity: number;
  staleNote: number | null;
  now: number;
}): StaleAction {
  const limit = 30 * 86400_000;
  if (o.labels.includes("Stale")) {
    if (o.staleNote !== null && o.lastActivity > o.staleNote) return "unmark";
    if (o.staleNote !== null && o.now - o.staleNote >= limit) return "close";
    return "none";
  }
  if (o.labels.includes("Needs-Author-Action") && o.now - o.lastActivity >= limit) return "mark";
  return "none";
}
