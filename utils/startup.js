import { setCurrentKeyId, setEncryptionKey } from "./globalVars.js";
import { getAsync } from "../database/init.js";

export const loadLatestKey = async () => {
    const row = await getAsync("SELECT * FROM encryption_keys ORDER BY id DESC LIMIT 1");
    if (row) {
        setCurrentKeyId(row.id);
        setEncryptionKey(Buffer.from(row.key, "hex"));
        console.log("✅ Vault initialized.");
        console.log(`🔒 Vault is sealed. Must be unsealed first.`);
    } else {
        console.log(`🔒 Vault is empty. Initialize it first.`);
    }
}