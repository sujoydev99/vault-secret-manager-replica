import { isSealed, getEncryptionKey } from "../utils/globalVars.js";

export const requireInitialized = (req, res, next) => {
    if (getEncryptionKey()) {
        return res.status(400).json({ error: "Vault is already initialized." });
    }
    next();
};

export const requireUnsealed = (req, res, next) => {
    if (isSealed()) {
        return res.status(403).json({ error: "Vault is sealed. Unseal it first." });
    }
    next();
};

export const requireSealed = (req, res, next) => {
    if (!isSealed()) {
        return res.status(403).json({ error: "Vault must be sealed." });
    }
    next();
};
