import dotenv from "dotenv";
dotenv.config();
import express from "express";
import { mkdir } from "fs/promises";
import { initializeDatabase } from "./database/init.js";
import vaultRoutes from "./routes/vault.js";
import secretRoutes from "./routes/secrets.js";
import { loadLatestKey } from "./utils/startup.js";

const app = express();
app.use(express.json());

// Ensure secrets directory exists
await mkdir(process.env.SECRETS_DB_PATH || "/tmp", { recursive: true });
// Initialize database
await initializeDatabase();
// load latest key
await loadLatestKey();
// Mount routes
app.use("/vault", vaultRoutes);
app.use("/secrets", secretRoutes);

// Start server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Vault server running on port ${PORT}`);
});
