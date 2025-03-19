import express from "express";
import { requireUnsealed } from "../middlewares/auth.js";
import { encryptData, decryptData } from "../utils/crypto.js";
import { runAsync, getAsync } from "../database/init.js";
import { getCurrentKeyId, getEncryptionKey } from "../utils/globalVars.js";
import e from "express";

const router = express.Router();

router.post("/store", requireUnsealed, async (req, res) => {
    const { key, value } = req.body;
    if (!key || !value) return res.status(400).json({ error: "Key and value are required." });

    const encryptedValue = encryptData(value);
    const row = await getAsync("SELECT MAX(version) AS maxVersion FROM secrets WHERE key = ?", [key]);
    const newVersion = (row?.maxVersion || 0) + 1;

    await runAsync("INSERT INTO secrets (key, value, key_id, version) VALUES (?, ?, ?, ?)", [key, encryptedValue, getCurrentKeyId(), newVersion]);
    res.json({ message: "Secret stored.", version: newVersion });
});

router.get("/get/:key", requireUnsealed, async (req, res) => {
    const key = req.params.key;
    let encKey = getEncryptionKey();
    const row = await getAsync("SELECT value, key_id FROM secrets WHERE key = ? ORDER BY version DESC LIMIT 1", [key]);
    if (getCurrentKeyId() !== row.key_id) {
        const res = await getAsync("SELECT key FROM encryption_keys WHERE id = ?", [row.key_id]);
        encKey = Buffer.from(res.key, "hex");
    }
    if (!row) return res.status(404).json({ error: "Secret not found." });

    const decryptedValue = decryptData(row.value, encKey);
    res.json({ key, value: decryptedValue });
});

router.delete("/delete/:key", requireUnsealed, async (req, res) => {
    const key = req.params.key;
    await runAsync("DELETE FROM secrets WHERE key = ?", [key]);
    res.json({ message: "Secret deleted." });
});

export default router;
