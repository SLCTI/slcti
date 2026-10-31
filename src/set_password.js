// Usage: node src/set_password.js <username> [admin|accountant]
// Creates the user, or changes the password (and the role, when given) of an existing one, and signs out its sessions.
// New users are accountants (read-only) unless the admin role is given.

const readline = require('readline');
const { databasePath, openDatabase, hashPassword } = require('./secure_db');

const MIN_LENGTH = 12;
const ROLES = ['admin', 'accountant'];

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
    const username = (process.argv[2] || '').trim();
    const role = process.argv[3] || null;

    if (!username || (role && !ROLES.includes(role))) {
        console.error('Usage: node src/set_password.js <username> [admin|accountant]');
        process.exit(1);
    }

    const password = await askHidden('Password: ');

    if (password.length < MIN_LENGTH) {
        console.error(`Password must be at least ${MIN_LENGTH} characters.`);
        process.exit(1);
    }

    if (password !== await askHidden('Confirm password: ')) {
        console.error('Passwords do not match.');
        process.exit(1);
    }

    rl.close();

    const db = await openDatabase(databasePath());

    await db.run(
        `INSERT INTO users (username, password_hash, role) VALUES (?, ?, COALESCE(?, 'accountant'))
         ON CONFLICT (username) DO UPDATE SET password_hash = excluded.password_hash, role = COALESCE(?, role)`,
        [username, await hashPassword(password), role, role]
    );
    await db.run('DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)', [username]);

    const user = await db.get('SELECT role FROM users WHERE username = ?', [username]);

    await db.close();

    console.log(`Password set for "${username}" (${user.role}).`);
}

main();
