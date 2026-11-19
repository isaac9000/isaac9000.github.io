#!/usr/bin/env node
// Encrypts journal/*.md into assets/journal/journal.enc.json with the password in .env (JOURNAL_PASSWORD=...).
// journal/ and .env are gitignored; only the encrypted file is committed. Decrypted in the browser by journal.html.
// Entry files are named YYYY-MM-DD.md (or YYYY-MM-DD-anything.md); an optional first line "# Title" sets the title.
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const env = Object.fromEntries(
  readFileSync(".env", "utf8")
    .split("\n")
    .map((l) => l.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/))
    .filter(Boolean)
    .map((m) => [m[1], m[2].replace(/^["']|["']$/g, "")])
);
const password = env.JOURNAL_PASSWORD;
if (!password) throw new Error("Set JOURNAL_PASSWORD in .env");

const entries = readdirSync("journal")
  .filter((f) => f.endsWith(".md"))
  .sort()
  .reverse()
  .map((f) => {
    let body = readFileSync(`journal/${f}`, "utf8").trim();
    let title = "";
    const m = body.match(/^# (.*)\n?/);
    if (m) {
      title = m[1].trim();
      body = body.slice(m[0].length).trim();
    }
    return { date: f.slice(0, 10), title, body };
  });

const iterations = 600000;
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, baseKey, { name: "AES-GCM", length: 256 }, false, [
  "encrypt",
]);
const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(entries)));

const b64 = (b) => Buffer.from(b).toString("base64");
mkdirSync("assets/journal", { recursive: true });
writeFileSync("assets/journal/journal.enc.json", JSON.stringify({ iterations, salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext) }) + "\n");
console.log(`Encrypted ${entries.length} entries into assets/journal/journal.enc.json`);
