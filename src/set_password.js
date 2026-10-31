// Usage: node src/set_password.js <email> [admin|accountant]
// Gives a site access to the resource with this email (a new resource when there is none), or changes its password
// (and its role, when given), and signs out its sessions. A new access is an accountant (read-only) unless admin is given.
// The Resources page does the same; this is for when nobody can sign in.

const readline = require('readline');
const { databasePath, openDatabase, hashPassword, ROLES, PASSWORD_MIN_LENGTH } = require('./secure_db');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: process.stdin.isTTY });
const lines = rl[Symbol.asyncIterator]();

// Do not echo the typed characters while a password is being entered
rl._writeToOutput = () => {};

async function askHidden(question) {
    process.stdout.write(question);

    const { value } = await lines.next();

    process.stdout.write('\n');

    return value || '';
}

async function main() {
    const email = (process.argv[2] || '').trim();
    const role = process.argv[3] || null;

    if (!email || (role && !ROLES.includes(role))) {
        console.error('Usage: node src/set_password.js <email> [admin|accountant]');
        process.exit(1);
    }

    const password = await askHidden('Password: ');

    if (password.length < PASSWORD_MIN_LENGTH) {
        console.error(`Password must be at least ${PASSWORD_MIN_LENGTH} characters.`);
        process.exit(1);
    }

    if (password !== await askHidden('Confirm password: ')) {
        console.error('Passwords do not match.');
        process.exit(1);
    }

    rl.close();

    const db = await openDatabase(databasePath());

    // The resource that already signs in with this email, else the first one with it, else a new one
    const resource = await db.get('SELECT id, code FROM resource WHERE lower(email) = lower(?) ORDER BY role IS NULL, id', [email])
        || { id: (await db.run('INSERT INTO resource (code, email) VALUES (?, ?)', [email.split('@')[0], email])).lastInsertRowid, code: email.split('@')[0] };

    await db.run(
        "UPDATE resource SET password_hash = ?, role = COALESCE(?, role, 'accountant') WHERE id = ?",
        [await hashPassword(password), role, resource.id]
    );
    await db.run('DELETE FROM sessions WHERE resource_id = ?', [resource.id]);

    const { role: saved } = await db.get('SELECT role FROM resource WHERE id = ?', [resource.id]);

    await db.close();

    console.log(`Password set for "${email}" (resource ${resource.code}, ${saved}).`);
}

main();
