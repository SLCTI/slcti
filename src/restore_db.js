// Usage: node src/restore_db.js <file>
// Replaces the data of the secure database with the data of <file>, an encrypted copy with the same key (a backup, or
// the production database copied by bin/deploy.ps1), after backing it up to private/backups/slcti-local-<time>.db.
// The data is copied through SQLite, so it works while the server runs (Windows does not let it replace an open file).
// Sessions are not copied: everyone signs in again.

const fs = require('fs');
const path = require('path');
const { databasePath, openDatabase } = require('./secure_db');

async function main() {
    const source = process.argv[2];

    if (!source || !fs.existsSync(source)) {
        console.error('Usage: node src/restore_db.js <file>');
        process.exit(1);
    }

    const file = databasePath();
    const stamp = new Date().toLocaleString('sv-SE').replace(/[-:]/g, '').replace(' ', '-'); // Local time, as YYYYMMDD-HHMMSS
    const backup = path.join(path.dirname(file), 'backups', `slcti-local-${stamp}.db`);
    const from = await openDatabase(path.resolve(source));
    const to = await openDatabase(file);

    fs.mkdirSync(path.dirname(backup), { recursive: true });
    await to.run('VACUUM INTO ?', [backup]);

    const tables = (await from.all("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'sessions'")).map(t => t.name);

    // Foreign keys cannot be switched inside a transaction, and the tables are emptied in any order
    await to.exec('PRAGMA foreign_keys = OFF; BEGIN');

    try {
        await to.run('DELETE FROM sessions');

        for (const table of tables) {
            const target = (await to.all(`PRAGMA table_info("${table}")`)).map(column => column.name);

            if (!target.length) throw new Error(`Table ${table} is missing from ${file}`);

            const columns = (await from.all(`PRAGMA table_info("${table}")`)).map(column => column.name).filter(name => target.includes(name));
            const list = columns.map(name => `"${name}"`).join(', ');
            const rows = await from.all(`SELECT ${list} FROM "${table}"`);

            await to.run(`DELETE FROM "${table}"`);

            for (const row of rows) {
                await to.run(`INSERT INTO "${table}" (${list}) VALUES (${columns.map(() => '?').join(', ')})`, columns.map(name => row[name]));
            }

            console.log(`${table}: ${rows.length} rows`);
        }

        await to.exec('COMMIT; PRAGMA foreign_keys = ON');
    } catch (err) {
        await to.exec('ROLLBACK; PRAGMA foreign_keys = ON');
        throw err;
    } finally {
        await from.close();
        await to.close();
    }

    console.log(`${file} now holds the data of ${source} (previous data backed up to ${backup})`);
}

main().catch(err => {
    console.error(err.message);
    process.exit(1);
});
