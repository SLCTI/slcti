// Usage: node src/backup_db.js [target]
// Copies the encrypted secure database to target, by default private/backups/slcti-YYYY-MM-DD.db (same key, still encrypted).

const fs = require('fs');
const path = require('path');
const { databasePath, openDatabase } = require('./secure_db');

async function main() {
    const file = databasePath();
    const target = path.resolve(process.argv[2] || path.join(path.dirname(file), 'backups', `slcti-${new Date().toLocaleDateString('en-CA')}.db`));

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.rmSync(target, { force: true });

    const db = await openDatabase(file);

    // VACUUM INTO writes a consistent copy, encrypted with the same key
    await db.run('VACUUM INTO ?', [target]);
    await db.close();

    console.log(`Backup written to ${target}`);
}

main();
