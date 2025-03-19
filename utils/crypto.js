import crypto from "crypto";
import { getEncryptionKey, isSealed } from "./globalVars.js";

export const encryptData = (text) => {
    if (isSealed()) throw new Error("Vault is sealed! Unseal first.");

    const encryptionKey = getEncryptionKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    return `${iv.toString("hex")}:${encrypted}`;
};

export const decryptData = (encryptedText, key) => {
    if (isSealed()) throw new Error("Vault is sealed! Unseal first.");
    const encryptionKey = getEncryptionKey();
    const [iv, encrypted] = encryptedText.split(":");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "hex"));
    return decipher.update(encrypted, "hex", "utf8");
};