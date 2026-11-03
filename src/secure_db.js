const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3-multiple-ciphers');
const util = require('util');

const scrypt = util.promisify(crypto.scrypt);

// The configuration and the database key live in .env (never committed); see .env.example
const ENV_FILE = path.resolve(__dirname, '..', '.env');

if (fs.existsSync(ENV_FILE)) process.loadEnvFile(ENV_FILE);

// Each session belongs to the user that signed in
const SESSIONS = `
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES user (id) ON DELETE CASCADE,
        csrf_token TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );
`;

const USER = `
    -- The people of the organisations; a user with a role and a password signs in with its email, and a client only
    -- sees the data of its organisation. The first user of an organisation is its contact on the invoices
    CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY,
        resource_id INTEGER REFERENCES resource (id) ON DELETE CASCADE,
        first_name VARCHAR,
        last_name VARCHAR,
        title VARCHAR,
        email VARCHAR,
        telephone VARCHAR,
        role VARCHAR,
        password_hash VARCHAR
    );
`;

// The hours of a client: a date ("YYYY-MM-DD") with start and end times ("HH:MM") on that day; the number of hours,
// amounts and taxes are calculated
const TIMESHEET = `
    CREATE TABLE IF NOT EXISTS timesheet (
        id INTEGER PRIMARY KEY,
        resource_id INTEGER REFERENCES resource (id),
        date DATE,
        start TIME,
        "end" TIME,
        rate REAL,
        description VARCHAR
    );
`;

// The expenses of a client: gst and qst are flags (1 = taxable); the amounts and taxes are calculated
const EXPENSE = `
    CREATE TABLE IF NOT EXISTS expense (
        id INTEGER PRIMARY KEY,
        resource_id INTEGER REFERENCES resource (id),
        date DATE,
        unit REAL,
        rate REAL,
        gst INTEGER,
        qst INTEGER,
        description VARCHAR
    );
`;

const SCHEMA = `
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;

    ${SESSIONS}

    -- The organisations: clients, payers and the provider itself. The invoices of a client go to its billed resource
    -- (e.g. SPL is billed to Vigiteck), else to the client itself
    CREATE TABLE IF NOT EXISTS resource (
        id INTEGER PRIMARY KEY,
        code VARCHAR,
        organisation VARCHAR,
        neq VARCHAR,
        gst_number VARCHAR,
        qst_number VARCHAR,
        bank_account VARCHAR,
        website VARCHAR,
        address VARCHAR,
        billed_resource_id INTEGER REFERENCES resource (id)
    );

    -- The roles of the users, in their display order
    CREATE TABLE IF NOT EXISTS role (
        code VARCHAR PRIMARY KEY,
        sort_order INTEGER NOT NULL
    );

    ${USER}

    ${TIMESHEET}

    ${EXPENSE}

    CREATE TABLE IF NOT EXISTS payment (
        id INTEGER PRIMARY KEY,
        resource_id INTEGER REFERENCES resource (id),
        date DATE,
        payer_id INTEGER REFERENCES resource (id),
        amount REAL
    );
`;

// Created once the tables have their current columns
const INDEXES = `
    CREATE INDEX IF NOT EXISTS ix_timesheet_date ON timesheet (date);
    CREATE INDEX IF NOT EXISTS ix_timesheet_resource_id ON timesheet (resource_id);
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

    // Sessions belonged to resources before; dropping them signs everyone out once
    if (!(await columns('sessions')).includes('user_id')) {
        await wrapper.exec(`DROP TABLE sessions; ${SESSIONS}`);
    }

    // Logins were first in a users table, then on the resources; both now go to the user table
    if ((await columns('users')).length) {
        if (!(await columns('resource')).includes('role')) {
            await wrapper.exec('ALTER TABLE resource ADD COLUMN role VARCHAR; ALTER TABLE resource ADD COLUMN password_hash VARCHAR;');
        }

        await moveUsers(wrapper, await columns('users'));
    }

    // The first user table required a login: rebuild it to also hold contacts, before moving the logins into it
    if (!(await columns('user')).includes('telephone')) {
        await wrapper.exec(`DROP TABLE sessions; ALTER TABLE user RENAME TO user_old; ${USER}
            INSERT INTO user (id, resource_id, first_name, last_name, email, role, password_hash)
            SELECT id, resource_id, first_name, last_name, email, role, password_hash FROM user_old;
            DROP TABLE user_old; ${SESSIONS}`);
    }

    if ((await columns('resource')).includes('role')) await moveLogins(wrapper);
    if ((await columns('resource')).includes('telephone')) await moveContacts(wrapper);

    // One login per email; contacts without a site access may share one
    await wrapper.exec('CREATE UNIQUE INDEX IF NOT EXISTS ix_user_login ON user (lower(email)) WHERE role IS NOT NULL');

    // The entries first had their billed and assigned resources, and their date in both start and end
    if ((await columns('timesheet')).includes('shipped_resource_id')) await normalizeEntries(wrapper, await columns('resource'));

    await wrapper.exec(INDEXES);

    // The roles known to the code, numbered in the order of ROLES
    for (const [index, code] of ROLES.entries()) {
        await wrapper.run('INSERT INTO role (code, sort_order) VALUES (?, ?) ON CONFLICT (code) DO UPDATE SET sort_order = excluded.sort_order', [code, index + 1]);
    }

    return wrapper;
}

// The billed resource of the entries depends on their client only: it goes to the client (the latest one that is not
// the client itself). The assigned resource is dropped (the description tells whose hours an expense charges), and the
// date of a time entry is only kept once
async function normalizeEntries(db, resourceColumns) {
    await db.exec('BEGIN');

    try {
        const overnight = await db.get('SELECT COUNT(*) AS count FROM timesheet WHERE substr(start, 1, 10) IS NOT substr("end", 1, 10)');

        if (overnight.count) throw new Error(`${overnight.count} time entries end on another day than they start`);

        if (!resourceColumns.includes('billed_resource_id')) await db.exec('ALTER TABLE resource ADD COLUMN billed_resource_id INTEGER REFERENCES resource (id)');

        await db.run(
            `UPDATE resource SET billed_resource_id = (
                 SELECT x.billed_resource_id FROM (
                     SELECT shipped_resource_id, billed_resource_id, start FROM timesheet
                     UNION ALL SELECT shipped_resource_id, billed_resource_id, start FROM expense
                 ) x
                 WHERE x.shipped_resource_id = resource.id AND x.billed_resource_id != resource.id
                 ORDER BY x.start DESC LIMIT 1)
             WHERE billed_resource_id IS NULL`
        );
        await db.exec(`
            ALTER TABLE timesheet RENAME TO timesheet_old;
            ${TIMESHEET}
            INSERT INTO timesheet (id, resource_id, date, start, "end", rate, description)
            SELECT id, shipped_resource_id, substr(start, 1, 10), substr(start, 12, 5), substr("end", 12, 5), rate, description FROM timesheet_old;
            DROP TABLE timesheet_old;

            ALTER TABLE expense RENAME TO expense_old;
            ${EXPENSE}
            INSERT INTO expense (id, resource_id, date, unit, rate, gst, qst, description)
            SELECT id, shipped_resource_id, start, unit, rate, CAST(gst AS INTEGER), CAST(qst AS INTEGER), description FROM expense_old;
            DROP TABLE expense_old;

            COMMIT`);
    } catch (err) {
        await db.exec('ROLLBACK');
        throw err;
    }
}

// The contact of each organisation (name, title, email and telephone) becomes one of its users: the user that already
// signs in with that email, else a new user without a site access
async function moveContacts(db) {
    await db.exec('BEGIN');

    try {
        const contacts = await db.all(
            `SELECT id, first_name, last_name, title, email, telephone FROM resource
             WHERE COALESCE(first_name, last_name, title, email, telephone) IS NOT NULL ORDER BY id`
        );

        for (const contact of contacts) {
            const user = contact.email && await db.get('SELECT id FROM user WHERE resource_id = ? AND lower(email) = lower(?)', [contact.id, contact.email]);

            if (user) {
                await db.run(
                    `UPDATE user SET first_name = COALESCE(first_name, ?), last_name = COALESCE(last_name, ?), title = COALESCE(title, ?),
                     telephone = COALESCE(telephone, ?) WHERE id = ?`,
                    [contact.first_name, contact.last_name, contact.title, contact.telephone, user.id]
                );
            } else {
                await db.run(
                    'INSERT INTO user (resource_id, first_name, last_name, title, email, telephone) VALUES (?, ?, ?, ?, ?, ?)',
                    [contact.id, contact.first_name, contact.last_name, contact.title, contact.email, contact.telephone]
                );
            }
        }

        await db.exec(`${['first_name', 'last_name', 'title', 'email', 'telephone'].map(column => `ALTER TABLE resource DROP COLUMN ${column};`).join(' ')} COMMIT`);
    } catch (err) {
        await db.exec('ROLLBACK');
        throw err;
    }
}

// Each resource with a role and a password becomes a user of that organisation, with its name and email
async function moveLogins(db) {
    await db.exec('BEGIN');

    try {
        await db.run(
            `INSERT INTO user (resource_id, first_name, last_name, email, role, password_hash)
             SELECT id, first_name, last_name, email, role, password_hash FROM resource
             WHERE role IS NOT NULL AND password_hash IS NOT NULL AND email IS NOT NULL ORDER BY id`
        );
        await db.exec('DROP INDEX IF EXISTS ix_resource_login; ALTER TABLE resource DROP COLUMN role; ALTER TABLE resource DROP COLUMN password_hash; COMMIT');
    } catch (err) {
        await db.exec('ROLLBACK');
        throw err;
    }
}

// The first logins were in a users table. Each one goes to the resource it was linked to, else the
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

// Logins and passwords, shared by the Users page and set_password.js
// A client only sees the data of its organisation. In their display order (sort_order of the role table)
const ROLES = ['admin', 'associate', 'accountant', 'client'];
const PASSWORD_MIN_LENGTH = 12;

// The resource of the business itself: the provider of the invoices
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
