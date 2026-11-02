// Ask for confirmation before submitting destructive forms
document.addEventListener('submit', event => {
    const message = event.target.dataset.confirm;

    if (message && !window.confirm(message)) event.preventDefault();
});

// Print buttons (the print styles turn the page into a PDF-ready document)
document.addEventListener('click', event => {
    if (event.target.closest('[data-print]')) window.print();
});

// Show amounts with a fixed number of decimals (e.g. 95 becomes 95.00) once typed
document.addEventListener('change', event => {
    const field = event.target;

    if (field.dataset && field.dataset.decimals && field.value !== '' && !isNaN(field.value)) field.value = Number(field.value).toFixed(Number(field.dataset.decimals));
});

// Entry form: show the fields of the chosen type (hours or expense); the others are disabled, so they are neither
// checked nor sent
document.addEventListener('change', event => {
    if (!event.target.matches('[data-entry-type]')) return;

    for (const fieldset of event.target.form.querySelectorAll('fieldset[data-type]')) {
        const active = fieldset.dataset.type === event.target.value;

        fieldset.disabled = !active;
        fieldset.hidden = !active;
    }
});

// Submit filter forms as soon as one of their fields changes
document.addEventListener('change', event => {
    const form = event.target.form;

    if (form && form.hasAttribute('data-auto-submit')) form.requestSubmit();
});

// Sort the rows of a table by clicking its column headers (tables with the "sortable" class)
function cellValue(row, index) {
    const text = row.cells[index].textContent.trim();
    const number = /^-?[\d\s.,]+\s*\$?$/.test(text) ? parseFloat(text.replace(/[\s$]/g, '').replace(',', '.')) : NaN;

    return { text, number };
}

function sortTable(table, index, header) {
    const body = table.tBodies[0];
    const columns = table.tHead.rows[0].cells.length;
    const ascending = header.getAttribute('aria-sort') !== 'ascending';
    const rows = [...body.rows].filter(row => row.cells.length === columns);

    rows.sort((a, b) => {
        const x = cellValue(a, index);
        const y = cellValue(b, index);

        // Empty cells always go last
        if (!x.text || !y.text) return !x.text - !y.text;

        const order = !isNaN(x.number) && !isNaN(y.number)
            ? x.number - y.number
            : x.text.localeCompare(y.text, undefined, { numeric: true, sensitivity: 'base' });

        return ascending ? order : -order;
    });

    rows.forEach(row => body.appendChild(row));

    for (const cell of table.tHead.rows[0].cells) {
        cell.removeAttribute('aria-sort');

        const icon = cell.querySelector('.sort-icon');

        if (icon) icon.textContent = '▲▼';
    }

    header.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
    header.querySelector('.sort-icon').textContent = ascending ? '▲' : '▼';
}

document.querySelectorAll('table.sortable').forEach(table => {
    [...table.tHead.rows[0].cells].forEach((header, index) => {
        if (!header.textContent.trim()) return;

        const icon = document.createElement('span');

        icon.className = 'sort-icon';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = '▲▼';
        header.prepend(icon);
        header.classList.add('sort-header');
        header.tabIndex = 0;
        header.title = table.dataset.sortTitle || 'Sort';
        header.addEventListener('click', () => sortTable(table, index, header));
        header.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                sortTable(table, index, header);
            }
        });
    });
});
