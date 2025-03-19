import sqlite3 from "sqlite3";
import { promisify } from "util";
import { join } from "path";

const SECRETS_DB_PATH = join(process.env.SECRETS_DB_PATH || "/tmp", "vault.db");
const db = new sqlite3.Database(SECRETS_DB_PATH);

export const runAsync = promisify(db.run.bind(db));
export const getAsync = promisify(db.get.bind(db));
export const allAsync = promisify(db.all.bind(db));

export const initializeDatabase = async () => {
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
};
