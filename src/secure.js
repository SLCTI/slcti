const crypto = require('crypto');
const express = require('express');
const { hashPassword, verifyPassword, ROLES, PASSWORD_MIN_LENGTH, PROVIDER_CODE } = require('./secure_db');

const SESSION_COOKIE = 'sid';
const SESSION_TTL = 12 * 60 * 60 * 1000; // 12 hours
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const randomToken = () => crypto.randomBytes(32).toString('base64url');

function safeEqual(a, b) {
    const bufferA = Buffer.from(String(a));
    const bufferB = Buffer.from(String(b));

    return bufferA.length === bufferB.length && crypto.timingSafeEqual(bufferA, bufferB);
}

function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

// Form parsing helpers
const text = value => {
    const trimmed = String(value ?? '').trim();

    return trimmed.length > 0 ? trimmed : null;
};

const number = value => {
    const parsed = parseFloat(String(value ?? '').replace(',', '.'));

    return Number.isFinite(parsed) ? parsed : null;
};

const isDate = value => /^\d{4}-\d{2}-\d{2}$/.test(value || '') && !isNaN(new Date(value));

// The lists are filtered by a month ("YYYY-MM") picked among the months of their data and the current month, which is
// the default; an empty month shows every date
function currentMonth() {
    const now = new Date();

    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

const withCurrentMonth = months => [...new Set([...months, currentMonth()])].sort();

function pickMonth(query, months) {
    if (query.month === undefined) return currentMonth();

    return months.includes(query.month) ? query.month : '';
}

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

// Week number as in Excel WEEKNUM: week 1 contains January 1 and weeks start on Sunday
function weekOfYear(date) {
    const day = new Date(date + 'T00:00:00Z');
    const january = Date.UTC(day.getUTCFullYear(), 0, 1);
    const dayOfYear = Math.round((day - january) / 86400000);

    return Math.floor((dayOfYear + new Date(january).getUTCDay()) / 7) + 1;
}

const dayOfWeek = date => DAYS[new Date(date + 'T00:00:00Z').getUTCDay()];

// Prevent spreadsheet formula injection and quote values for CSV export
function csvValue(value) {
    let string = value == null ? '' : String(value);

    // Plain numbers such as -2.00 stay numbers
    if (/^[=+\-@\t\r]/.test(string) && !/^-?\d+(\.\d+)?$/.test(string)) string = `'${string}`;

    return /[",\r\n]/.test(string) ? `"${string.replace(/"/g, '""')}"` : string;
}

// Load the signed-in session, if any; the public pages use it too, so the site menu shows the secure links
function sessionLoader(db) {
    return asyncHandler(async (req, res, next) => {
        const token = req.cookies[SESSION_COOKIE];

        if (token) {
            const session = await db.get(
                `SELECT s.token_hash, s.user_id, s.csrf_token, u.email AS username, u.role, u.resource_id
                 FROM sessions s
                 JOIN user u ON u.id = s.user_id
                 WHERE s.token_hash = ? AND s.expires_at > ? AND u.role IS NOT NULL`,
                [sha256(token), Date.now()]
            );

            if (session) {
                req.session = session;
                res.locals.session = session;
                res.locals.csrf = session.csrf_token;
                res.locals.isAdmin = session.role === 'admin';
            }
        }

        next();
    });
}

function createSecureRouter({ db, logger, production }) {
    const router = express.Router();
    const attempts = new Map();
    const dummyHash = hashPassword(randomToken());

    router.use(express.urlencoded({ extended: false, limit: '100kb' }));

    // Private pages must never be cached, indexed or framed
    router.use((req, res, next) => {
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('X-Robots-Tag', 'noindex, nofollow');
        res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'");
        next();
    });

    // Load the session, if any
    router.use(sessionLoader(db));

    // Reject cross-site form submissions
    router.use((req, res, next) => {
        if (req.method !== 'POST') return next();

        const origin = req.get('origin');

        if (origin) {
            let host = null;

            try { host = new URL(origin).host; } catch { /* Invalid origin */ }

            if (host !== req.get('host')) {
                logger.warn(`Rejected cross-origin POST to /secure${req.path} from ${origin}`);

                return res.status(403).send('Forbidden');
            }
        }

        if (req.path !== '/login' && (!req.session || !safeEqual(req.body._csrf, req.session.csrf_token))) {
            logger.warn(`Rejected POST to /secure${req.path} with an invalid CSRF token from ${req.ip}`);

            return res.status(403).send('Forbidden');
        }

        next();
    });

    // Authentication
    router.get('/login', (req, res) => {
        if (req.session) return res.redirect('/secure');

        res.render('secure/login', { error: null, username: '' });
    });

    router.post('/login', asyncHandler(async (req, res) => {
        const now = Date.now();
        const entry = attempts.get(req.ip);
        const username = String(req.body.username || '').trim();
        const password = String(req.body.password || '');

        if (entry && entry.count >= MAX_ATTEMPTS && now - entry.first < LOCKOUT_TIME) {
            logger.warn(`Locked out login attempt for "${username}" from ${req.ip}`);

            return res.status(429).render('secure/login', { error: 'Too many attempts. Please try again later.', username });
        }

        const user = await db.get('SELECT id, password_hash FROM user WHERE lower(email) = lower(?) AND role IS NOT NULL AND password_hash IS NOT NULL', [username]);

        // Always verify a hash so that unknown usernames take as long as known ones
        const valid = await verifyPassword(password, user ? user.password_hash : await dummyHash);

        if (!user || !valid) {
            if (!entry || now - entry.first >= LOCKOUT_TIME) attempts.set(req.ip, { count: 1, first: now });
            else entry.count++;

            // Forget stale entries
            if (attempts.size > 1000) {
                for (const [ip, value] of attempts) if (now - value.first >= LOCKOUT_TIME) attempts.delete(ip);
            }

            logger.warn(`Failed login for "${username}" from ${req.ip}`);

            return res.status(401).render('secure/login', { error: 'Invalid email or password.', username });
        }

        attempts.delete(req.ip);

        const token = randomToken();

        await db.run('DELETE FROM sessions WHERE expires_at <= ?', [now]);
        await db.run(
            'INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)',
            [sha256(token), user.id, randomToken(), now + SESSION_TTL]
        );

        res.cookie(SESSION_COOKIE, token, {
            httpOnly: true,
            secure: production,
            sameSite: 'strict',
            path: '/',
            maxAge: SESSION_TTL
        });

        logger.info(`User "${username}" logged in from ${req.ip}`);
        res.redirect('/secure');
    }));

    router.post('/logout', asyncHandler(async (req, res) => {
        await db.run('DELETE FROM sessions WHERE token_hash = ?', [req.session.token_hash]);
        res.clearCookie(SESSION_COOKIE, { path: '/' });
        res.clearCookie(SESSION_COOKIE, { path: '/secure' });
        res.redirect('/secure/login');
    }));

    // Everything below requires an authenticated session
    router.use((req, res, next) => {
        if (!req.session) return res.redirect('/secure/login');

        next();
    });

    // Administrators can do everything; accountants can only read these pages (no organisations nor users), and clients
    // the bills and totals only
    const READ_ONLY_PAGES = {
        accountant: ['/', '/timesheets', '/timesheets.csv', '/expenses', '/bills', '/totals', '/totals.csv'],
        client: ['/', '/bills', '/totals', '/totals.csv']
    };

    router.use((req, res, next) => {
        if (req.session.role === 'admin' || (req.method === 'GET' && (READ_ONLY_PAGES[req.session.role] || []).includes(req.path))) return next();

        logger.warn(`Denied ${req.method} /secure${req.path} to "${req.session.username}" (${req.session.role})`);
        res.status(403).send('Forbidden');
    });

    router.get('/', (req, res) => res.redirect(req.session.role === 'client' ? '/secure/bills' : '/secure/timesheets'));

    // A client only sees the data of its organisation: the timesheets and expenses where it is the client or the billed
    // resource, and the bills and payments where it is the client, the billed resource or the payer. Null for everyone
    // else (all data); -1 (nothing) for a client user without an organisation, which the Users page does not allow
    const ownId = req => req.session.role === 'client' ? req.session.resource_id || -1 : null;
    const ownBill = own => bill => !own || bill.customer_id === own || bill.billed_id === own || bill.payers.includes(own);

    // Date helpers for the list views
    router.use((req, res, next) => {
        res.locals.weekOfYear = weekOfYear;
        res.locals.dayOfWeek = date => res.locals.t(dayOfWeek(date));
        next();
    });

    // Timesheets: the hours and the expenses of the clients, listed and entered together; each kind keeps its own table,
    // which the bills read
    const HOURS = `ROUND((julianday(t."end") - julianday(t.start)) * 24, 2)`;
    const resourceName = alias => `${alias}.code`;

    // Expenses: gst and qst are flags (1 = taxable)
    const GST_RATE = 0.05;
    const QST_RATE = 0.09975;
    // The small offset rounds half-cents up like Excel despite floating point (26.925 is stored as 26.924999...)
    const SUBTOTAL = 'ROUND(COALESCE(e.unit, 0) * COALESCE(e.rate, 0) + 1e-9, 2)';
    const GST = `CASE WHEN e.gst = 1 THEN ROUND(${SUBTOTAL} * ${GST_RATE} + 1e-9, 2) ELSE 0 END`;
    const QST = `CASE WHEN e.qst = 1 THEN ROUND(${SUBTOTAL} * ${QST_RATE} + 1e-9, 2) ELSE 0 END`;

    // The own entries of a client: those of its organisation and of the organisations billed to it (one parameter)
    const ownEntries = alias => `${alias}.resource_id IN (SELECT id FROM resource WHERE ? IN (id, billed_resource_id))`;

    // Customer and month filters, for the timesheet (t) or expense (e) table
    function readFilters(query, alias, own, months) {
        const filters = { customer: query.customer || '', month: pickMonth(query, months) };
        const conditions = [];
        const params = [];

        if (own) { conditions.push(ownEntries(alias)); params.push(own); }
        if (filters.customer) { conditions.push(`${alias}.resource_id = ?`); params.push(filters.customer); }
        if (filters.month) { conditions.push(`substr(${alias}.date, 1, 7) = ?`); params.push(filters.month); }

        return { filters, where: conditions.length ? 'WHERE ' + conditions.join(' AND ') : '', params };
    }

    // The months of the entries of a table (a client's own entries only) and the current month, in chronological order
    const listMonths = async (table, own) => withCurrentMonth((await db.all(
        `SELECT DISTINCT substr(x.date, 1, 7) AS month FROM ${table} x WHERE x.date IS NOT NULL${own ? ` AND ${ownEntries('x')}` : ''}`,
        own ? [own] : [])).map(row => row.month));

    const listCustomers = () => db.all(`SELECT r.id, ${resourceName('r')} AS name FROM resource r ORDER BY name COLLATE NOCASE`);

    // The list filters only show the clients that have entries in a table; for a client, its own entries only
    const listUsedResources = (table, own) => db.all(
        `SELECT r.id, ${resourceName('r')} AS name
         FROM resource r
         WHERE EXISTS (SELECT 1 FROM ${table} x WHERE x.resource_id = r.id${own ? ` AND ${ownEntries('x')}` : ''})
         ORDER BY name COLLATE NOCASE`,
        own ? [own] : []
    );

    // Hours are always taxable: the GST and QST of each entry are rounded to the cent
    function timesheetTaxes(row) {
        if (row.hours == null || row.rate == null) return { subtotal: null, gst: null, qst: null, total: null };

        const subtotal = round(row.hours * row.rate);
        const gst = round(subtotal * GST_RATE);
        const qst = round(subtotal * QST_RATE);

        return { subtotal, gst, qst, total: round(subtotal + gst + qst) };
    }

    // The hours and expenses of a month and client, by date, with their subtotal, taxes and total; descriptions are only
    // shown to administrators
    async function findEntries(query, isAdmin, own) {
        const months = withCurrentMonth([...await listMonths('timesheet', own), ...await listMonths('expense', own)]);
        const hours = readFilters(query, 't', own, months);
        const expenses = readFilters(query, 'e', own, months);
        const names = `${resourceName('s')} AS customer_name, ${resourceName('b')} AS billed_name`;
        const joins = alias => `LEFT JOIN resource s ON s.id = ${alias}.resource_id
             LEFT JOIN resource b ON b.id = s.billed_resource_id`;
        const timesheets = await db.all(`SELECT t.*, ${HOURS} AS hours, ${names} FROM timesheet t ${joins('t')} ${hours.where}`, hours.params);
        const others = await db.all(
            `SELECT e.*, ${SUBTOTAL} AS subtotal, ${GST} AS gst_amount, ${QST} AS qst_amount, ${SUBTOTAL} + ${GST} + ${QST} AS total, ${names}
             FROM expense e ${joins('e')} ${expenses.where}`, expenses.params);
        const rows = [
            ...timesheets.map(row => ({ ...row, type: 'hours', ...timesheetTaxes(row) })),
            ...others.map(row => ({ ...row, type: 'expense', start: null, end: null, hours: null, gst: row.gst_amount, qst: row.qst_amount }))
        ].sort((a, b) =>
            String(a.date).localeCompare(String(b.date)) || String(a.start ?? '').localeCompare(String(b.start ?? '')) ||
            String(a.customer_name).localeCompare(String(b.customer_name), undefined, { sensitivity: 'base' }) ||
            a.type.localeCompare(b.type) || a.id - b.id);

        return { filters: hours.filters, months, rows: isAdmin ? rows : rows.map(({ description, ...row }) => row) };
    }

    router.get('/timesheets', asyncHandler(async (req, res) => {
        const own = ownId(req);
        const { filters, months, rows } = await findEntries(req.query, res.locals.isAdmin, own);
        // The clients that have hours or expenses
        const customers = [...new Map([
            ...await listUsedResources('timesheet', own),
            ...await listUsedResources('expense', own)
        ].map(customer => [customer.id, customer])).values()].sort((a, b) => String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' }));
        const sum = field => round(rows.reduce((total, row) => total + (row[field] || 0), 0));
        const totals = { hours: sum('hours'), units: sum('unit'), subtotal: sum('subtotal'), gst: sum('gst'), qst: sum('qst'), total: sum('total') };

        res.render('secure/timesheets', { filters, months, rows, customers, totals, query: new URLSearchParams(filters).toString() });
    }));

    router.get('/timesheets.csv', asyncHandler(async (req, res) => {
        const { isAdmin, t } = res.locals;
        const { rows } = await findEntries(req.query, isAdmin, ownId(req));
        const header = ['Type', 'Start', 'End', 'Client', 'Billed to', 'Hours', 'Units', 'Rate', 'Subtotal', 'GST (5 %)', 'QST (9.975 %)', 'Total',
            ...(isAdmin ? ['Description'] : [])].map(t).map(csvValue);
        const fixed = value => value == null ? '' : value.toFixed(2);
        const lines = rows.map(row => [
            t(row.type === 'hours' ? 'Time' : 'Expense'),
            row.start ? `${row.date} ${row.start}` : row.date,
            row.end ? `${row.date} ${row.end}` : '',
            row.customer_name,
            row.billed_name,
            row.hours ?? '',
            row.type === 'expense' ? row.unit ?? '' : '',
            row.rate ?? '',
            fixed(row.subtotal),
            fixed(row.gst),
            fixed(row.qst),
            fixed(row.total),
            ...(isAdmin ? [row.description] : [])
        ].map(csvValue).join(','));

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="timesheets.csv"');
        res.send('﻿' + [header.join(','), ...lines].join('\r\n'));
    }));

    const isTime = value => /^([01]\d|2[0-3]):[0-5]\d$/.test(value || '');
    const resourceId = value => parseInt(value, 10) || null;

    // One form for both kinds of entries: its type shows the fields of hours (start, end, hourly rate) or of an expense
    // (units, rate, taxes). Billed to is not on it: it is the billed resource of the client (e.g. SPL is billed to Vigiteck)
    async function renderEntryForm(res, entry, errors = []) {
        res.status(errors.length ? 400 : 200).render('secure/timesheet_form', { entry, customers: await listCustomers(), errors });
    }

    // After saving, the list shows the month of the entry
    const listMonth = date => `/secure/timesheets?month=${String(date).slice(0, 7)}`;

    // Hours: a date with start and end times
    function readTimesheet(body) {
        const form = {
            type: 'hours',
            date: text(body.date),
            start_time: text(body.start_time),
            end_time: text(body.end_time),
            resource_id: resourceId(body.resource_id),
            rate: number(body.rate),
            description: text(body.description)
        };
        const errors = [];

        if (!form.resource_id) errors.push('Client is required.');
        if (!isDate(form.date)) errors.push('Date is invalid.');
        if (!isTime(form.start_time) || !isTime(form.end_time)) errors.push('Start and end times are required.');
        else if (form.end_time <= form.start_time) errors.push('End time must be after start time.');
        if (form.rate !== null && form.rate < 0) errors.push('Rate cannot be negative.');

        const values = [form.resource_id, form.date, form.start_time, form.end_time, form.rate, form.description];

        return { form, values, errors };
    }

    const timesheetForm = timesheet => ({ ...timesheet, type: 'hours', start_time: timesheet.start, end_time: timesheet.end });

    // Expenses: the rate of an expense is shown in its own field, apart from the hourly rate
    function readExpense(body) {
        const expense = {
            resource_id: resourceId(body.resource_id),
            date: text(body.date),
            unit: number(body.unit),
            rate: number(body.rate),
            gst: body.gst ? 1 : 0,
            qst: body.qst ? 1 : 0,
            description: text(body.description)
        };
        const errors = [];

        if (!expense.resource_id) errors.push('Client is required.');
        if (!isDate(expense.date)) errors.push('Date is invalid.');
        if (expense.unit === null || expense.rate === null) errors.push('Units and rate are required.');

        return { expense, errors };
    }

    const EXPENSE_FIELDS = ['date', 'resource_id', 'unit', 'rate', 'gst', 'qst', 'description'];
    const expenseForm = expense => ({ ...expense, type: 'expense', rate: null, expense_rate: expense.rate });

    router.get('/timesheets/new', asyncHandler(async (req, res) => {
        const last = await db.get('SELECT resource_id, rate FROM timesheet ORDER BY id DESC LIMIT 1') || {};

        await renderEntryForm(res, {
            type: req.query.type === 'expense' ? 'expense' : 'hours',
            resource_id: parseInt(req.query.customer, 10) || last.resource_id,
            date: new Date().toLocaleDateString('en-CA'),
            rate: last.rate,
            unit: 1,
            gst: 1,
            qst: 1
        });
    }));

    // A new entry is hours or an expense, by its type
    router.post('/timesheets', asyncHandler(async (req, res) => {
        if (req.body.type === 'expense') {
            const { expense, errors } = readExpense(req.body);

            if (errors.length) return renderEntryForm(res, expenseForm(expense), errors);

            await db.run(
                `INSERT INTO expense (${EXPENSE_FIELDS.join(', ')}) VALUES (${EXPENSE_FIELDS.map(() => '?').join(', ')})`,
                EXPENSE_FIELDS.map(field => expense[field])
            );

            return res.redirect(listMonth(expense.date));
        }

        const { form, values, errors } = readTimesheet(req.body);

        if (errors.length) return renderEntryForm(res, form, errors);

        await db.run('INSERT INTO timesheet (resource_id, date, start, "end", rate, description) VALUES (?, ?, ?, ?, ?, ?)', values);
        res.redirect(listMonth(form.date));
    }));

    router.get('/timesheets/:id/edit', asyncHandler(async (req, res, next) => {
        const timesheet = await db.get('SELECT * FROM timesheet WHERE id = ?', [req.params.id]);

        if (!timesheet) return next();

        await renderEntryForm(res, timesheetForm(timesheet));
    }));

    router.post('/timesheets/:id', asyncHandler(async (req, res) => {
        const { form, values, errors } = readTimesheet(req.body);

        form.id = req.params.id;

        if (errors.length) return renderEntryForm(res, form, errors);

        await db.run(
            'UPDATE timesheet SET resource_id = ?, date = ?, start = ?, "end" = ?, rate = ?, description = ? WHERE id = ?',
            [...values, form.id]
        );
        res.redirect(listMonth(form.date));
    }));

    router.post('/timesheets/:id/delete', asyncHandler(async (req, res) => {
        await db.run('DELETE FROM timesheet WHERE id = ?', [req.params.id]);
        res.redirect('/secure/timesheets');
    }));

    // The expenses are edited with the same form, and listed with the hours
    router.get('/expenses', (req, res) => res.redirect(301, '/secure/timesheets'));

    router.get('/expenses/:id/edit', asyncHandler(async (req, res, next) => {
        const expense = await db.get('SELECT * FROM expense WHERE id = ?', [req.params.id]);

        if (!expense) return next();

        await renderEntryForm(res, expenseForm(expense));
    }));

    router.post('/expenses/:id', asyncHandler(async (req, res) => {
        const { expense, errors } = readExpense(req.body);

        expense.id = req.params.id;

        if (errors.length) return renderEntryForm(res, expenseForm(expense), errors);

        await db.run(
            `UPDATE expense SET ${EXPENSE_FIELDS.map(field => `${field} = ?`).join(', ')} WHERE id = ?`,
            [...EXPENSE_FIELDS.map(field => expense[field]), expense.id]
        );
        res.redirect(listMonth(expense.date));
    }));

    router.post('/expenses/:id/delete', asyncHandler(async (req, res) => {
        await db.run('DELETE FROM expense WHERE id = ?', [req.params.id]);
        res.redirect('/secure/timesheets');
    }));

    // Bills: calculated, one per month and client; the bill is sent to the payer, else to the billed resource, else to the client
    // Round half-cents up like Excel (35.9 * 0.75 is stored as 26.924999... but must give 26.93)
    const round = value => Number(Math.round(Number(value.toFixed(8) + 'e2')) + 'e-2');
    const pad = n => String(n).padStart(2, '0');

    // As in the Excel invoices: taxes are rounded per line, subtotals and totals are only rounded once summed
    function taxLine(line, gst, qst) {
        line.gst = gst ? round(line.subtotal * GST_RATE) : 0;
        line.qst = qst ? round(line.subtotal * QST_RATE) : 0;
        line.total = line.subtotal + line.gst + line.qst;

        return line;
    }

    // Split a month into weeks starting on Sunday, as in the Excel invoices
    function weeksOfMonth(month) {
        const [year, number] = month.split('-').map(Number);
        const last = new Date(Date.UTC(year, number, 0)).getUTCDate();
        const weeks = [];
        let from = 1;

        for (let day = 1; day <= last; day++) {
            if (new Date(Date.UTC(year, number - 1, day)).getUTCDay() === 6 || day === last) {
                weeks.push({ from: `${month}-${pad(from)}`, to: `${month}-${pad(day)}` });
                from = day + 1;
            }
        }

        return weeks;
    }

    async function loadBills() {
        const provider = await db.get('SELECT id FROM resource WHERE code = ?', [PROVIDER_CODE]);
        const timesheets = await db.all(
            `SELECT substr(t.date, 1, 7) AS month, t.date, t.resource_id AS customer_id, s.code AS project, ${HOURS} AS hours,
                    COALESCE(t.rate, 0) AS rate
             FROM timesheet t
             LEFT JOIN resource s ON s.id = t.resource_id
             WHERE t.date IS NOT NULL`
        );
        const expenses = await db.all(
            `SELECT substr(e.date, 1, 7) AS month, e.date, e.resource_id AS customer_id, s.code AS project, e.unit, e.rate,
                    e.gst, e.qst, e.description
             FROM expense e
             LEFT JOIN resource s ON s.id = e.resource_id
             WHERE e.date IS NOT NULL
             ORDER BY e.date, e.id`
        );
        const bills = new Map();
        const billFor = row => {
            const key = `${row.month}/${row.customer_id}`;

            if (!bills.has(key)) bills.set(key, { month: row.month, customer_id: row.customer_id, timesheets: [], expenses: [] });

            return bills.get(key);
        };

        for (const row of timesheets) if (row.customer_id && row.customer_id !== provider?.id) billFor(row).timesheets.push(row);
        for (const row of expenses) if (row.customer_id && row.customer_id !== provider?.id) billFor(row).expenses.push(row);

        const resources = await db.all('SELECT id, code, billed_resource_id FROM resource');
        const codes = Object.fromEntries(resources.map(r => [r.id, r.code]));
        const billedTo = Object.fromEntries(resources.map(r => [r.id, r.billed_resource_id]));
        const list = [...bills.values()].sort((a, b) =>
            a.month.localeCompare(b.month) || String(codes[a.customer_id]).localeCompare(String(codes[b.customer_id]), undefined, { sensitivity: 'base' }));

        // Numbers follow the chronological order of all bills
        list.forEach((bill, index) => {
            bill.number = index + 1;
            bill.customer_name = codes[bill.customer_id];
            bill.billed_id = billedTo[bill.customer_id] || null;
            buildBillLines(bill);
        });

        return list;
    }

    function buildBillLines(bill) {
        // Hours: one line per week, project and rate
        bill.hourLines = [];

        for (const week of weeksOfMonth(bill.month)) {
            const groups = new Map();

            for (const row of bill.timesheets.filter(r => r.date >= week.from && r.date <= week.to)) {
                const key = `${row.project}/${row.rate}`;

                if (!groups.has(key)) groups.set(key, { ...week, project: row.project, rate: row.rate, hours: 0 });
                groups.get(key).hours += row.hours || 0;
            }

            for (const line of groups.values()) {
                line.hours = round(line.hours);
                line.subtotal = line.hours * line.rate;
                bill.hourLines.push(taxLine(line, true, true));
            }
        }

        bill.expenseLines = bill.expenses.map(row =>
            taxLine({ date: row.date, project: row.project, unit: row.unit, rate: row.rate, subtotal: (row.unit || 0) * (row.rate || 0), description: row.description }, row.gst === 1, row.qst === 1));

        const sum = (lines, field) => round(lines.reduce((total, line) => total + line[field], 0));
        const lines = [...bill.hourLines, ...bill.expenseLines];

        bill.hours = sum(bill.hourLines, 'hours');
        bill.units = round(bill.expenseLines.reduce((total, line) => total + (line.unit || 0), 0));
        bill.hoursAmount = sum(bill.hourLines, 'subtotal');
        bill.expensesAmount = sum(bill.expenseLines, 'subtotal');
        bill.subtotal = sum(lines, 'subtotal');
        bill.gst = sum(lines, 'gst');
        bill.qst = sum(lines, 'qst');
        bill.total = sum(lines, 'total');
    }

    router.get('/bills', asyncHandler(async (req, res) => {
        // Show one bill, picked by "YYYY-MM/customer id"; the latest one by default
        // Payments are matched on all bills before keeping a client's own
        const every = await loadBills();

        await applyPayments(every);

        const all = every.filter(ownBill(ownId(req)));
        const bill = all.find(b => `${b.month}/${b.customer_id}` === req.query.bill) || all[all.length - 1] || null;
        // An organisation with the name, title, email and telephone of its contact: its first user
        const party = async (where, id) => await db.get(
            `SELECT r.*, u.first_name, u.last_name, u.title, u.email, u.telephone
             FROM resource r LEFT JOIN user u ON u.id = (SELECT MIN(id) FROM user WHERE resource_id = r.id)
             WHERE r.${where} = ?`, [id]) || {};
        const provider = await party('code', PROVIDER_CODE);
        // The client box is only shown to administrators
        const customer = bill && res.locals.isAdmin ? await party('id', bill.customer_id) : {};
        // Billed to is whoever paid the bill; before it is paid, the billed resource of its entries, else the client
        const billedTo = bill ? await party('id', bill.payers[0] || bill.billed_id || bill.customer_id) : {};

        res.render('secure/bills', { bill, options: all, provider, customer, billedTo });
    }));

    // Totals: one line per bill, like the Total sheet of the Excel workbook
    // Payments are not linked to bills, so each one is matched for its customer:
    // 1. a payment equal to a bill's total (within 5 cents) pays that bill;
    // 2. any other payment pays the oldest open bill issued before it, with the following open bills when their total
    //    is closer to its amount (customers pay their bills in order, even when one was underpaid); the difference
    //    stays on the last bill of the run, where it belongs;
    // 3. a payment with no open bill left is an overpayment on the customer's latest bill.
    async function applyPayments(bills) {
        const payments = await db.all('SELECT id, resource_id, date, payer_id, amount FROM payment WHERE amount IS NOT NULL ORDER BY date, id');

        // Who paid each bill, when, and with which payments (the Totals page edits them)
        const paidBy = (bill, payment) => {
            if (payment.payer_id && !bill.payers.includes(payment.payer_id)) bill.payers.push(payment.payer_id);
            if (payment.date && !bill.paid_dates.includes(payment.date)) bill.paid_dates.push(payment.date);
            if (!bill.payments.includes(payment)) bill.payments.push(payment);
        };

        for (const bill of bills) {
            bill.paid = 0;
            bill.matched = false;
            bill.payments = [];
            bill.payers = [];
            bill.paid_dates = [];
        }

        const unmatched = payments.filter(payment => {
            const bill = bills.find(b => b.customer_id === payment.resource_id && !b.matched && Math.abs(b.total - payment.amount) <= 0.05);

            if (bill) {
                bill.paid = payment.amount;
                bill.matched = true;
                paidBy(bill, payment);
            }

            return !bill;
        });

        for (const payment of unmatched) {
            const own = bills.filter(bill => bill.customer_id === payment.resource_id);
            const open = own.filter(bill => !bill.matched);
            const before = open.filter(bill => bill.month <= String(payment.date).slice(0, 7));
            const candidates = before.length ? before : open;
            let best = null;
            let sum = 0;

            for (let last = 0; last < candidates.length; last++) {
                sum += candidates[last].total;

                const gap = Math.abs(sum - payment.amount);

                if (!best || gap < best.gap - 0.005) best = { gap, run: candidates.slice(0, last + 1) };
            }

            if (!best) {
                const latest = own[own.length - 1];

                if (latest) {
                    latest.paid = round(latest.paid + payment.amount);
                    paidBy(latest, payment);
                }
                continue;
            }

            let left = payment.amount;

            best.run.forEach((bill, index) => {
                const part = index === best.run.length - 1 ? left : bill.total;

                bill.paid = round(bill.paid + part);
                bill.matched = true;
                paidBy(bill, payment);
                left = round(left - part);
            });
        }
    }

    // Payments are matched on all bills, so filtering does not change which payment goes to which bill
    async function findTotals(query, own) {
        const every = await loadBills();
        const names = new Map((await db.all(`SELECT r.id, ${resourceName('r')} AS name FROM resource r`)).map(r => [r.id, r.name]));

        await applyPayments(every);

        const all = every.filter(ownBill(own));

        for (const bill of all) bill.payer_name = bill.payers.map(id => names.get(id)).join(', ');

        // The months of the bills and the current month
        const months = withCurrentMonth(all.map(bill => bill.month));
        const filters = { customer: query.customer || '', payer: query.payer || '', month: pickMonth(query, months) };
        const bills = all.filter(bill =>
            (!filters.customer || String(bill.customer_id) === filters.customer) &&
            (!filters.payer || bill.payers.some(id => String(id) === filters.payer)) &&
            (!filters.month || bill.month === filters.month));

        // The filter only lists clients that have bills
        const byName = (a, b) => String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' });
        const customers = [...new Map(all.map(bill => [bill.customer_id, { id: bill.customer_id, name: bill.customer_name }])).values()].sort(byName);

        // The payer filter only lists those who paid a bill
        const payers = [...new Set(all.flatMap(bill => bill.payers))].map(id => ({ id, name: names.get(id) })).sort(byName);

        return { filters, months, bills, customers, payers };
    }

    router.get('/totals', asyncHandler(async (req, res) => {
        const { filters, months, bills, customers, payers } = await findTotals(req.query, ownId(req));
        const sum = field => round(bills.reduce((total, bill) => total + bill[field], 0));

        res.render('secure/totals', {
            filters, months, bills, customers, payers, subtotal: sum('subtotal'), gst: sum('gst'), qst: sum('qst'), total: sum('total'), paid: sum('paid'), query: new URLSearchParams(filters).toString()
        });
    }));

    router.get('/totals.csv', asyncHandler(async (req, res) => {
        const { bills } = await findTotals(req.query, ownId(req));
        const header = ['Bill', 'Month', 'Client', 'Payer', 'Date', 'Payment', 'Subtotal', 'GST (5 %)', 'QST (9.975 %)', 'Total', 'Difference'].map(res.locals.t).map(csvValue);
        const lines = bills.map(bill => [
            String(bill.number).padStart(3, '0'),
            bill.month,
            bill.customer_name,
            bill.payer_name,
            bill.paid_dates.join(', '),
            bill.paid ? bill.paid.toFixed(2) : '',
            bill.subtotal.toFixed(2),
            bill.gst.toFixed(2),
            bill.qst.toFixed(2),
            bill.total.toFixed(2),
            round(bill.paid - bill.total) ? round(bill.paid - bill.total).toFixed(2) : ''
        ].map(csvValue).join(','));

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="totals.csv"');
        res.send('﻿' + [header.join(','), ...lines].join('\r\n'));
    }));

    // Payments are added from the Totals page (administrators only), where they are matched to the bills
    function readPayment(body) {
        const payment = {
            resource_id: resourceId(body.resource_id),
            date: text(body.date),
            payer_id: resourceId(body.payer_id),
            amount: number(body.amount)
        };
        const errors = [];

        if (!payment.resource_id) errors.push('Client is required.');
        if (!isDate(payment.date)) errors.push('Date is invalid.');
        if (payment.amount === null) errors.push('Payment is required.');

        return { payment, errors };
    }

    // The payment forms go back to the Totals page with its filters ("back"), else to the month of the payment
    function totalsUrl(back, month) {
        const from = new URLSearchParams(String(back || ''));
        const filters = new URLSearchParams(['month', 'customer', 'payer'].filter(name => from.has(name)).map(name => [name, from.get(name)]));

        return `/secure/totals?${filters.size ? filters : new URLSearchParams({ month })}`;
    }

    async function renderPaymentForm(res, payment, back, errors = []) {
        res.status(errors.length ? 400 : 200).render('secure/payment_form', { payment, back, customers: await listCustomers(), errors });
    }

    const PAYMENT_FIELDS = ['resource_id', 'date', 'payer_id', 'amount'];

    router.get('/payments/new', asyncHandler(async (req, res) => {
        await renderPaymentForm(res, {
            resource_id: parseInt(req.query.customer, 10) || null,
            payer_id: parseInt(req.query.payer, 10) || null,
            date: new Date().toLocaleDateString('en-CA')
        }, req.query.back);
    }));

    router.post('/payments', asyncHandler(async (req, res) => {
        const { payment, errors } = readPayment(req.body);

        if (errors.length) return renderPaymentForm(res, payment, req.body.back, errors);

        await db.run(`INSERT INTO payment (${PAYMENT_FIELDS.join(', ')}) VALUES (${PAYMENT_FIELDS.map(() => '?').join(', ')})`, PAYMENT_FIELDS.map(field => payment[field]));
        res.redirect(totalsUrl(req.body.back, payment.date.slice(0, 7)));
    }));

    router.get('/payments/:id/edit', asyncHandler(async (req, res, next) => {
        const payment = await db.get('SELECT * FROM payment WHERE id = ?', [req.params.id]);

        if (!payment) return next();

        await renderPaymentForm(res, payment, req.query.back);
    }));

    router.post('/payments/:id', asyncHandler(async (req, res) => {
        const { payment, errors } = readPayment(req.body);

        payment.id = req.params.id;

        if (errors.length) return renderPaymentForm(res, payment, req.body.back, errors);

        await db.run(`UPDATE payment SET ${PAYMENT_FIELDS.map(field => `${field} = ?`).join(', ')} WHERE id = ?`, [...PAYMENT_FIELDS.map(field => payment[field]), payment.id]);
        res.redirect(totalsUrl(req.body.back, payment.date.slice(0, 7)));
    }));

    router.post('/payments/:id/delete', asyncHandler(async (req, res) => {
        await db.run('DELETE FROM payment WHERE id = ?', [req.params.id]);
        res.redirect(totalsUrl(req.body.back, ''));
    }));

    // The full bill is now shown on the Bills page
    router.get('/bills/:month/:customer', (req, res) =>
        res.redirect(301, '/secure/bills?bill=' + encodeURIComponent(`${req.params.month}/${req.params.customer}`)));

    // Resources (the page was named Customers before)
    router.get('/customers', (req, res) => res.redirect(301, '/secure/resources'));

    // The contact, email and telephone are on the users of the organisation; its bills go to its billed resource, if any
    const RESOURCE_TEXTS = ['code', 'organisation', 'neq', 'gst_number', 'qst_number', 'bank_account', 'website', 'address'];
    const RESOURCE_FIELDS = [...RESOURCE_TEXTS, 'billed_resource_id'];

    const countUses = `
        (SELECT COUNT(*) FROM timesheet x WHERE x.resource_id = r.id)
      + (SELECT COUNT(*) FROM expense x WHERE x.resource_id = r.id)
      + (SELECT COUNT(*) FROM payment x WHERE r.id IN (x.resource_id, x.payer_id))
      + (SELECT COUNT(*) FROM resource x WHERE x.billed_resource_id = r.id)`;

    const RESOURCE_COLUMNS = `r.id, ${RESOURCE_FIELDS.map(field => `r.${field}`).join(', ')}, ${resourceName('r')} AS name`;

    const RESOURCE_ERRORS = {
        in_use: 'This organisation is used by timesheets, expenses or payments and cannot be deleted.',
        users: 'This organisation has users and cannot be deleted.'
    };

    router.get('/resources', asyncHandler(async (req, res) => {
        const resources = await db.all(`SELECT ${RESOURCE_COLUMNS} FROM resource r ORDER BY name COLLATE NOCASE`);

        res.render('secure/resources', { resources, error: RESOURCE_ERRORS[req.query.error] || null });
    }));

    async function readResource(body, id) {
        const resource = { ...Object.fromEntries(RESOURCE_TEXTS.map(field => [field, text(body[field])])), billed_resource_id: resourceId(body.billed_resource_id) };
        const errors = [];

        if (!resource.code) errors.push('Code is required.');
        if (resource.billed_resource_id && (resource.billed_resource_id === id || !await db.get('SELECT 1 FROM resource WHERE id = ?', [resource.billed_resource_id]))) errors.push('Billed to is invalid.');

        return { resource: { ...resource, id }, errors };
    }

    // Billed to lists the other organisations
    const renderResourceForm = async (res, resource, errors = []) => res.status(errors.length ? 400 : 200).render('secure/resource_form', {
        resource, organisations: (await listCustomers()).filter(organisation => organisation.id !== resource.id), errors
    });

    router.get('/resources/new', asyncHandler(async (req, res) => renderResourceForm(res, {})));

    router.post('/resources', asyncHandler(async (req, res) => {
        const { resource, errors } = await readResource(req.body, null);

        if (errors.length) return renderResourceForm(res, resource, errors);

        await db.run(
            `INSERT INTO resource (${RESOURCE_FIELDS.join(', ')}) VALUES (${RESOURCE_FIELDS.map(() => '?').join(', ')})`,
            RESOURCE_FIELDS.map(field => resource[field])
        );
        res.redirect('/secure/resources');
    }));

    router.get('/resources/:id/edit', asyncHandler(async (req, res, next) => {
        const resource = await db.get(`SELECT ${RESOURCE_COLUMNS} FROM resource r WHERE r.id = ?`, [req.params.id]);

        if (!resource) return next();

        await renderResourceForm(res, resource);
    }));

    router.post('/resources/:id', asyncHandler(async (req, res, next) => {
        const existing = await db.get('SELECT id FROM resource WHERE id = ?', [req.params.id]);

        if (!existing) return next();

        const { resource, errors } = await readResource(req.body, existing.id);

        if (errors.length) return renderResourceForm(res, resource, errors);

        await db.run(
            `UPDATE resource SET ${RESOURCE_FIELDS.map(field => `${field} = ?`).join(', ')} WHERE id = ?`,
            [...RESOURCE_FIELDS.map(field => resource[field]), resource.id]
        );
        res.redirect('/secure/resources');
    }));

    router.post('/resources/:id/delete', asyncHandler(async (req, res) => {
        const used = await db.get(`SELECT ${countUses} AS count FROM resource r WHERE r.id = ?`, [req.params.id]);

        if (used && used.count > 0) return res.redirect('/secure/resources?error=in_use');
        if (await db.get('SELECT 1 FROM user WHERE resource_id = ?', [req.params.id])) return res.redirect('/secure/resources?error=users');

        await db.run('DELETE FROM resource WHERE id = ?', [req.params.id]);
        res.redirect('/secure/resources');
    }));

    // Users: the people of the organisations. A user with a role and a password signs in with its email; without a
    // role, it is only a contact. A client user belongs to an organisation and only sees its data
    const USER_COLUMNS = `u.id, u.resource_id, u.first_name, u.last_name, u.title, u.email, u.telephone, u.role,
        u.password_hash IS NOT NULL AS has_password, ${resourceName('r')} AS organisation`;

    const USER_ERRORS = {
        own: 'You cannot delete your own user.'
    };

    router.get('/users', asyncHandler(async (req, res) => {
        const users = await db.all(
            `SELECT ${USER_COLUMNS} FROM user u LEFT JOIN resource r ON r.id = u.resource_id
             ORDER BY organisation COLLATE NOCASE, u.last_name COLLATE NOCASE, u.first_name COLLATE NOCASE, u.email COLLATE NOCASE`
        );

        res.render('secure/users', { users, error: USER_ERRORS[req.query.error] || null });
    }));

    // Never the password hash; a new site access needs a password, an existing one keeps it when none is typed
    async function readUser(body, id, session) {
        const current = id ? await db.get('SELECT password_hash IS NOT NULL AS has_password FROM user WHERE id = ?', [id]) : null;
        const user = {
            id,
            first_name: text(body.first_name),
            last_name: text(body.last_name),
            title: text(body.title),
            email: text(body.email),
            telephone: text(body.telephone),
            role: ROLES.includes(body.role) ? body.role : null,
            resource_id: resourceId(body.resource_id),
            has_password: Boolean(current && current.has_password)
        };
        const password = String(body.password || '');
        const errors = [];

        if (user.email && !/^[^\s@]+@[^\s@]+$/.test(user.email)) errors.push('Email is invalid.');
        if (user.resource_id && !await db.get('SELECT 1 FROM resource WHERE id = ?', [user.resource_id])) errors.push('Organisation is invalid.');
        if (id && Number(id) === session.user_id && user.role !== 'admin') errors.push('You cannot remove your own administrator access.');

        if (user.role) {
            if (!user.email) errors.push('A site access needs an email, which is its login.');
            else if (await db.get('SELECT 1 FROM user WHERE lower(email) = lower(?) AND role IS NOT NULL AND id != ?', [user.email, id || 0])) errors.push('Another user already has this email.');
            if (user.role === 'client' && !user.resource_id) errors.push('A client user needs an organisation.');
            if (!user.has_password && !password) errors.push('A password is required for a new site access.');
            if (password && password.length < PASSWORD_MIN_LENGTH) errors.push('Password must be at least 12 characters.');
            if (password !== String(body.password_confirm || '')) errors.push('Passwords do not match.');
        }

        return { user, password, errors };
    }

    // No role removes the password and signs the user out; a new password signs out its other sessions
    async function saveUser(user, password, session) {
        const fields = ['resource_id', 'first_name', 'last_name', 'title', 'email', 'telephone', 'role'];
        const id = user.id || (await db.run(
            `INSERT INTO user (${fields.join(', ')}) VALUES (${fields.map(() => '?').join(', ')})`, fields.map(field => user[field]))).lastInsertRowid;

        if (user.id) await db.run(`UPDATE user SET ${fields.map(field => `${field} = ?`).join(', ')} WHERE id = ?`, [...fields.map(field => user[field]), id]);

        if (!user.role || password) {
            await db.run('UPDATE user SET password_hash = ? WHERE id = ?', [user.role ? await hashPassword(password) : null, id]);
            await db.run('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', [id, session.token_hash]);
        }
    }

    async function renderUserForm(res, user, errors = []) {
        res.status(errors.length ? 400 : 200).render('secure/user_form', { user, organisations: await listCustomers(), errors });
    }

    router.get('/users/new', asyncHandler(async (req, res) => {
        await renderUserForm(res, { resource_id: parseInt(req.query.organisation, 10) || null });
    }));

    router.post('/users', asyncHandler(async (req, res) => {
        const { user, password, errors } = await readUser(req.body, null, req.session);

        if (errors.length) return renderUserForm(res, user, errors);

        await saveUser(user, password, req.session);
        res.redirect('/secure/users');
    }));

    router.get('/users/:id/edit', asyncHandler(async (req, res, next) => {
        const user = await db.get(`SELECT ${USER_COLUMNS} FROM user u LEFT JOIN resource r ON r.id = u.resource_id WHERE u.id = ?`, [req.params.id]);

        if (!user) return next();

        await renderUserForm(res, user);
    }));

    router.post('/users/:id', asyncHandler(async (req, res, next) => {
        const existing = await db.get('SELECT id FROM user WHERE id = ?', [req.params.id]);

        if (!existing) return next();

        const { user, password, errors } = await readUser(req.body, existing.id, req.session);

        if (errors.length) return renderUserForm(res, user, errors);

        await saveUser(user, password, req.session);
        res.redirect('/secure/users');
    }));

    // Its sessions go with it
    router.post('/users/:id/delete', asyncHandler(async (req, res) => {
        if (Number(req.params.id) === req.session.user_id) return res.redirect('/secure/users?error=own');

        await db.run('DELETE FROM user WHERE id = ?', [req.params.id]);
        res.redirect('/secure/users');
    }));

    return router;
}

module.exports = { createSecureRouter, sessionLoader };
