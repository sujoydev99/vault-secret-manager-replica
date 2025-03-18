import dotenv from "dotenv";
dotenv.config();
import express from "express";
import sss from "shamirs-secret-sharing";
import sqlite3 from "sqlite3";
import crypto from "crypto";
import { promisify } from "util";
import { join } from 'path';
import { mkdir } from 'fs/promises';

const app = express();
app.use(express.json());

const SECRETS_DB_PATH = join(process.env.SECRETS_DB_PATH || '/tmp', 'vault.db');
await mkdir(process.env.SECRETS_DB_PATH || '/tmp', { recursive: true });

// Connect to SQLite (Promise-based)
const db = new sqlite3.Database(SECRETS_DB_PATH);
const runAsync = promisify(db.run.bind(db));
const getAsync = promisify(db.get.bind(db));
const allAsync = promisify(db.all.bind(db));

// Create necessary tables if not exists
await runAsync(`CREATE TABLE IF NOT EXISTS encryption_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL
)`);
await runAsync(`CREATE TABLE IF NOT EXISTS secrets (
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    key_id INTEGER NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(key, version),
    FOREIGN KEY(key_id) REFERENCES encryption_keys(id)
)`);

// 🔒 Initially, Vault is Sealed
let encryptionKey = null;
let currentKeyId = null;
let sealed = true;

// 📌 Load latest key but keep it sealed
const loadLatestKey = async () => {
    const row = await getAsync("SELECT * FROM encryption_keys ORDER BY id DESC LIMIT 1");
    if (row) {
        currentKeyId = row.id;
        encryptionKey = Buffer.from(row.key, "hex");
        console.log("✅ Vault initialized.");
        console.log(`🔒 Vault is sealed. Must be unsealed first.`);
    } else {
        console.log(`🔒 Vault is empty. Initialize it first.`);
    }
};
await loadLatestKey();

// 🔑 Encrypt Data (Only if Unsealed)
const encryptData = (text) => {
    if (sealed) throw new Error("Vault is sealed! Unseal first.");

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    return `${currentKeyId}:${iv.toString("hex")}:${encrypted}`;
};

// 🔓 Decrypt Data (Only if Unsealed)
const decryptData = async (encryptedText) => {
    if (sealed) throw new Error("Vault is sealed! Unseal first.");

    const [keyId, iv, encrypted] = encryptedText.split(":");
    const row = await getAsync("SELECT key FROM encryption_keys WHERE id = ?", [keyId]);
    if (!row) throw new Error("Encryption key not found!");

    const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(row.key, 'hex'), Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encrypted, "hex", "utf8");

    return decrypted;
};

const requireInitialized = (req, res, next) => {
    if (encryptionKey) {
        return res.status(400).json({ error: "Vault is already initialized." });
    }
    next();
};
const requireUnsealed = (req, res, next) => {
    if (sealed) {
        return res.status(403).json({ error: "Vault is sealed. Unseal it first." });
    }
    next();
};
const requireSealed = (req, res, next) => {
    if (!sealed) {
        return res.status(403).json({ error: "Vault must be sealed." });
    }
    next();
};

// 🏗️ Initialize the Vault
app.post("/init", requireInitialized, async (req, res) => {
    const existingKey = await getAsync("SELECT * FROM encryption_keys LIMIT 1");
    if (existingKey || encryptionKey) {
        return res.status(400).json({ error: "Vault is already initialized." });
    }

    encryptionKey = crypto.randomBytes(32); // 256-bit key
    await runAsync("INSERT INTO encryption_keys (key) VALUES (?)", [encryptionKey.toString("hex")]);

    const newKeyRow = await getAsync("SELECT last_insert_rowid() AS id");
    currentKeyId = newKeyRow.id;

    res.json({ message: "✅ Vault initialized.", keyId: currentKeyId });
});

// 🛠️ Store a Secret (Requires Unseal)
app.post("/store-secret", requireUnsealed, async (req, res) => {
    const { key, value } = req.body;
    if (!key || !value) {
        return res.status(400).json({ error: "Both key and value are required." });
    }

    const encryptedValue = encryptData(value);

    // Get the latest version and increment it
    const row = await getAsync("SELECT MAX(version) AS maxVersion FROM secrets WHERE key = ?", [key]);
    const newVersion = (row?.maxVersion || 0) + 1;

    await runAsync("INSERT INTO secrets (key, value, key_id, version) VALUES (?, ?, ?, ?)", [key, encryptedValue, currentKeyId, newVersion]);

    res.json({ message: "✅ Secret stored successfully.", version: newVersion });
});

// 🔍 Retrieve a Secret (Requires Unseal)
app.get("/get-secret/:key", requireUnsealed, async (req, res) => {
    const key = req.params.key;
    const version = req.query.version ? parseInt(req.query.version, 10) : null;

    let query = "SELECT value, version FROM secrets WHERE key = ? ORDER BY version DESC LIMIT 1";
    let params = [key];

    if (version) {
        query = "SELECT value, version FROM secrets WHERE key = ? AND version = ? LIMIT 1";
        params.push(version);
    }

    const row = await getAsync(query, params);

    if (!row) return res.status(404).json({ error: "❌ Secret not found." });

    try {
        const decryptedValue = await decryptData(row.value);
        res.json({ key, value: decryptedValue, version: row.version });
    } catch (error) {
        res.status(400).json({ error: "Failed to decrypt secret." });
    }
});

// 🔄 Rotate Encryption Key (Requires Unseal)
app.post("/rotate-key", requireUnsealed, async (req, res) => {
    const newKey = crypto.randomBytes(32);
    await runAsync("INSERT INTO encryption_keys (key) VALUES (?)", [newKey.toString("hex")]);

    const newKeyRow = await getAsync("SELECT last_insert_rowid() AS id");
    encryptionKey = newKey;
    currentKeyId = newKeyRow.id;
    sealed = true;

    res.json({ message: `🔄 Encryption key rotated successfully. New Key ID: ${currentKeyId}` });
});

// 🔑 Split Master Key (For Unsealing) (Requires Seal)
app.post("/split-key", requireSealed, async (req, res) => {
    if (!sealed) return res.status(400).json({ error: "Vault is already unsealed." });

    const { shares = 5, threshold = 3 } = req.body;
    const secretShares = sss.split(encryptionKey, { shares, threshold });

    res.json({ message: "🔑 Master key split into shares.", shares: secretShares.map(share => share.toString("hex")) });
});

// 🔓 Unseal the Vault (Requires Seal)
app.post("/unseal", requireSealed, async (req, res) => {
    const { shares } = req.body;

    if (!shares || shares.length < 3) {
        return res.status(400).json({ error: "At least 3 shares are required to unseal." });
    }

    try {
        const reconstructedKey = Buffer.from(sss.combine(shares.map(share => Buffer.from(share, "hex"))), "hex");
        // Verify the reconstructed key matches the stored key
        if (!reconstructedKey.equals(encryptionKey)) {
            return res.status(400).json({ error: "Invalid key shares provided" });
        }
        encryptionKey = reconstructedKey;
        sealed = false;

        res.json({ message: "✅ Vault successfully unsealed." });
    } catch (error) {
        res.status(400).json({ error: "❌ Failed to unseal vault." });
    }
});

// 🔒 Seal the Vault (Requires Unseal)
app.post("/seal", requireUnsealed, async (req, res) => {
    sealed = true;
    res.json({ message: "🔒 Vault sealed." });
});

// 🚀 Start Server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Vault server running on port ${PORT}`);
});
