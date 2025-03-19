import express from "express";
import { requireInitialized, requireSealed, requireUnsealed } from "../middlewares/auth.js";
import { getCurrentKeyId, getEncryptionKey, isSealed, setCurrentKeyId, setEncryptionKey, setSealed } from "../utils/globalVars.js";
import { runAsync, getAsync } from "../database/init.js";
import sss from "shamirs-secret-sharing";
import crypto from "crypto";
import e from "express";

const router = express.Router();

router.post("/status", async (req, res) => {
    res.json({ initialized: !!getEncryptionKey(), sealed: isSealed() });
});

router.post("/init", requireInitialized, async (req, res) => {
    const encryptionKey = crypto.randomBytes(32);
    await runAsync("INSERT INTO encryption_keys (key) VALUES (?)", [encryptionKey.toString("hex")]);
    const newKeyRow = await getAsync("SELECT last_insert_rowid() AS id");
    setEncryptionKey(encryptionKey);
    setCurrentKeyId(newKeyRow.id);
    setSealed(true);
    res.json({ message: "Vault initialized." });
});

router.post("/split-key", requireSealed, (req, res) => {
    const { shares = 5, threshold = 3 } = req.body;
    const encryptionKey = getEncryptionKey();
    const secretShares = sss.split(encryptionKey, { shares, threshold });
    res.json({ shares: secretShares.map((share) => share.toString("hex")) });
});

router.post("/unseal", requireSealed, async (req, res) => {
    const { shares } = req.body;
    try {
        const reconstructedKey = Buffer.from(sss.combine(shares.map((share) => Buffer.from(share, "hex"))));
        const latestKey = await getAsync("SELECT key FROM encryption_keys ORDER BY id DESC LIMIT 1");
        if (reconstructedKey.toString('hex') !== latestKey.key) {
            return res.status(400).json({ error: "Invalid key shares." });
        }
        setEncryptionKey(reconstructedKey);
        setSealed(false);
        res.json({ message: "Vault unsealed." });
    } catch (error) {
        res.status(400).json({ error: "Failed to unseal vault." });
    }
});
router.post("/rotate-key", requireUnsealed, async (req, res) => {
    const newKey = crypto.randomBytes(32);
    await runAsync("INSERT INTO encryption_keys (key) VALUES (?)", [newKey.toString("hex")]);
    const newKeyRow = await getAsync("SELECT last_insert_rowid() AS id");

    setEncryptionKey(newKey);
    setCurrentKeyId(newKeyRow.id);
    setSealed(true);
    res.json({ message: `🔄 Encryption key rotated successfully. Unseal vault to continue` });
});


router.post("/seal", requireUnsealed, (req, res) => {
    setSealed(true);
    res.json({ message: "Vault sealed." });
});

export default router;
