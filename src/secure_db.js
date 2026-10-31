const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3-multiple-ciphers');
const util = require('util');

const scrypt = util.promisify(crypto.scrypt);

// The configuration and the database key live in .env (never committed); see .env.example
const ENV_FILE = path.resolve(__dirname, '..', '.env');

if (fs.existsSync(ENV_FILE)) process.loadEnvFile(ENV_FILE);

// Each session belongs to the resource that signed in
const SESSIONS = `
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        resource_id INTEGER NOT NULL REFERENCES resource (id) ON DELETE CASCADE,
        csrf_token TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );
`;

const SCHEMA = `
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;

    ${SESSIONS}

    -- A resource with a role (admin or accountant) and a password signs in with its email
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
        address VARCHAR,
        role VARCHAR,
        password_hash VARCHAR
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

// The database is encrypted with SQLCipher; its key comes from SLCTI_DATABASE_KEY
function databaseKey() {
    const key = process.env.SLCTI_DATABASE_KEY;

    if (!key) throw new Error(`SLCTI_DATABASE_KEY is missing: add it to ${ENV_FILE} (or to the environment)`);

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
        throw new Error(`Cannot open ${file}: wrong SLCTI_DATABASE_KEY or unencrypted database (${err.message})`);
    }

    const wrapper = {
        run: async (sql, params = []) => db.prepare(sql).run(params),
        get: async (sql, params = []) => db.prepare(sql).get(params),
        all: async (sql, params = []) => db.prepare(sql).all(params),
        exec: async sql => { db.exec(sql); },
        close: async () => { db.close(); }
    };

    await wrapper.exec(SCHEMA);

    const columns = async table => (await wrapper.all(`PRAGMA table_info(${table})`)).map(column => column.name);

    if (!(await columns('resource')).includes('role')) {
        await wrapper.exec('ALTER TABLE resource ADD COLUMN role VARCHAR; ALTER TABLE resource ADD COLUMN password_hash VARCHAR;');
    }

    // Sessions belonged to users before; dropping them signs everyone out once
    if (!(await columns('sessions')).includes('resource_id')) {
        await wrapper.exec(`DROP TABLE sessions; ${SESSIONS}`);
    }

    if ((await columns('users')).length) await moveUsers(wrapper, await columns('users'));

    // One login per email
    await wrapper.exec('CREATE UNIQUE INDEX IF NOT EXISTS ix_resource_login ON resource (lower(email)) WHERE role IS NOT NULL');

    return wrapper;
}

// Logins were in a users table before they moved to resources. Each one goes to the resource it was linked to, else the
// resource with its email, else the provider for an administrator, else a new resource with its email. Logins that reach
// the same resource merge: the highest role, and the password of the login that is the resource email (else of the latest)
async function moveUsers(db, columns) {
    const role = columns.includes('role') ? 'role' : "'admin' AS role"; // Before roles, every user had full access
    const linked = columns.includes('resource_id') ? 'resource_id' : 'NULL AS resource_id';
    const access = new Map();

    await db.exec('BEGIN');

    try {
        for (const user of await db.all(`SELECT username, password_hash, ${role}, ${linked} FROM users ORDER BY id`)) {
            const resource = (user.resource_id && await db.get('SELECT id, email FROM resource WHERE id = ?', [user.resource_id]))
                || await db.get('SELECT id, email FROM resource WHERE lower(email) = lower(?) ORDER BY id', [user.username])
                || (user.role === 'admin' && await db.get('SELECT id, email FROM resource WHERE code = ?', [PROVIDER_CODE]))
                || { id: (await db.run('INSERT INTO resource (code, email) VALUES (?, ?)', [user.username.split('@')[0], user.username])).lastInsertRowid, email: user.username };
            const own = String(resource.email).toLowerCase() === user.username.toLowerCase();
            const merged = access.get(resource.id);

            access.set(resource.id, {
                role: user.role === 'admin' || (merged && merged.role === 'admin') ? 'admin' : 'accountant',
                password_hash: !merged || own || !merged.own ? user.password_hash : merged.password_hash,
                own: own || Boolean(merged && merged.own)
            });
        }

        for (const [id, login] of access) {
            await db.run('UPDATE resource SET role = ?, password_hash = ? WHERE id = ?', [login.role, login.password_hash, id]);
        }

        await db.exec('DROP TABLE users; COMMIT');
    } catch (err) {
        await db.exec('ROLLBACK');
        throw err;
    }
}

// Logins and passwords, shared by the Resources page and set_password.js
const ROLES = ['admin', 'accountant'];
const PASSWORD_MIN_LENGTH = 12;

// The resource of the business itself: the provider of the bills
const PROVIDER_CODE = 'SLCTI';

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

module.exports = { databasePath, openDatabase, hashPassword, verifyPassword, ROLES, PASSWORD_MIN_LENGTH, PROVIDER_CODE };
