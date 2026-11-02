// Usage: node src/set_password.js <email> [admin|accountant|client] [organisation code]
// Creates the user with this email, or changes its password (and its role and organisation, when given), and signs out
// its sessions. A new user is an accountant (read-only) unless another role is given; a client needs an organisation.
// The Users page does the same; this is for when nobody can sign in.

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
    const code = process.argv[4] || null;

    if (!email || (role && !ROLES.includes(role))) {
        console.error('Usage: node src/set_password.js <email> [admin|accountant|client] [organisation code]');
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
    const organisation = code && await db.get('SELECT id FROM resource WHERE code = ?', [code]);

    if (code && !organisation) {
        console.error(`No organisation has the code "${code}".`);
        process.exit(1);
    }

    const hash = await hashPassword(password);
    // The user that signs in with this email, else a contact with it
    const existing = await db.get('SELECT id, role, resource_id FROM user WHERE lower(email) = lower(?) ORDER BY role IS NULL, id', [email]);
    const user = {
        role: role || (existing ? existing.role : 'accountant'),
        resource_id: organisation ? organisation.id : existing ? existing.resource_id : null
    };

    if (user.role === 'client' && !user.resource_id) {
        console.error('A client needs an organisation: add its code after the role.');
        process.exit(1);
    }

    if (existing) {
        await db.run('UPDATE user SET password_hash = ?, role = ?, resource_id = ? WHERE id = ?', [hash, user.role, user.resource_id, existing.id]);
        await db.run('DELETE FROM sessions WHERE user_id = ?', [existing.id]);
    } else {
        await db.run('INSERT INTO user (email, role, resource_id, password_hash) VALUES (?, ?, ?, ?)', [email, user.role, user.resource_id, hash]);
    }

    await db.close();

    console.log(`Password set for "${email}" (${user.role}${code ? `, ${code}` : ''}).`);
}

main();
