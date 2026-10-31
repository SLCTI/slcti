const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3-multiple-ciphers');
const util = require('util');

const scrypt = util.promisify(crypto.scrypt);

// The configuration and the database key live in .env (never committed); see .env.example
const ENV_FILE = path.resolve(__dirname, '..', '.env');

if (fs.existsSync(ENV_FILE)) process.loadEnvFile(ENV_FILE);

const SCHEMA = `
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'accountant',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf_token TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS resource (
        id INTEGER PRIMARY KEY,
        code VARCHAR,
        last_name VARCHAR,
        first_name VARCHAR,
        title VARCHAR,
        organisation VARCHAR,
        neq VARCHAR,
        gst_number VARCHAR,
        qst_number VARCHAR,
        bank_account VARCHAR,
        email VARCHAR,
        website VARCHAR,
        telephone VARCHAR,
        address VARCHAR
    );

    -- Start and end are stored as "YYYY-MM-DD HH:MM"
    CREATE TABLE IF NOT EXISTS timesheet (
        id INTEGER PRIMARY KEY,
        billed_resource_id INTEGER REFERENCES resource (id),
        shipped_resource_id INTEGER REFERENCES resource (id),
        assigned_resource_id INTEGER REFERENCES resource (id),
        start DATE,
        "end" DATE,
        rate REAL,
        description VARCHAR
    );

    CREATE TABLE IF NOT EXISTS expense (
        id INTEGER PRIMARY KEY,
        billed_resource_id INTEGER REFERENCES resource (id),
        shipped_resource_id INTEGER REFERENCES resource (id),
        assigned_resource_id INTEGER REFERENCES resource (id),
        start DATE,
        unit REAL,
        rate REAL,
        gst REAL,
        qst REAL,
        description VARCHAR
    );

    CREATE TABLE IF NOT EXISTS payment (
        id INTEGER PRIMARY KEY,
        resource_id INTEGER REFERENCES resource (id),
        date DATE,
        payer_id INTEGER REFERENCES resource (id),
        amount REAL
    );

    CREATE INDEX IF NOT EXISTS ix_timesheet_start ON timesheet (start);
    CREATE INDEX IF NOT EXISTS ix_timesheet_shipped_resource_id ON timesheet (shipped_resource_id);
`;

// Resolve the private database location (SLCTI_DATABASE); it must stay outside of Git (see .gitignore)
function databasePath() {
    return path.resolve(__dirname, '..', process.env.SLCTI_DATABASE || 'private/slcti.db');
}

// The database is encrypted with SQLCipher; its key comes from SLCTI_DB_KEY
function databaseKey() {
    const key = process.env.SLCTI_DB_KEY;

    if (!key) throw new Error(`SLCTI_DB_KEY is missing: add it to ${ENV_FILE} (or to the environment)`);

    return key;
}

// Open the encrypted database, create the schema and expose promise-based helpers
async function openDatabase(file, key = databaseKey()) {
    fs.mkdirSync(path.dirname(file), { recursive: true });

    const db = new Database(file);

    db.pragma("cipher = 'sqlcipher'");
    db.pragma(`key = '${key.replace(/'/g, "''")}'`);

    // Fails here with a clear message when the key does not match the file
    try {
        db.prepare('SELECT COUNT(*) FROM sqlite_master').get();
    } catch (err) {
        db.close();
        throw new Error(`Cannot open ${file}: wrong SLCTI_DB_KEY or unencrypted database (${err.message})`);
    }

    const wrapper = {
        run: async (sql, params = []) => db.prepare(sql).run(params),
        get: async (sql, params = []) => db.prepare(sql).get(params),
        all: async (sql, params = []) => db.prepare(sql).all(params),
        exec: async sql => { db.exec(sql); },
        close: async () => { db.close(); }
    };

    await wrapper.exec(SCHEMA);

    // Roles came after the first users, who all had full access: they stay administrators
    if (!(await wrapper.all('PRAGMA table_info(users)')).some(column => column.name === 'role')) {
        await wrapper.exec(`
            ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'accountant';
            UPDATE users SET role = 'admin';
        `);
    }

    return wrapper;
}

// Password hashes are stored as "scrypt$<salt>$<hash>"
async function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = await scrypt(password, salt, 64);

    return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

async function verifyPassword(password, stored) {
    const [scheme, saltHex, hashHex] = String(stored).split('$');

    if (scheme !== 'scrypt' || !saltHex || !hashHex) return false;

    const expected = Buffer.from(hashHex, 'hex');
    const actual = await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length);

    return crypto.timingSafeEqual(actual, expected);
}

module.exports = { databasePath, openDatabase, hashPassword, verifyPassword };
