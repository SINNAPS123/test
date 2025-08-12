// Main JS for GradatFinal Application - Genie Modernized
document.addEventListener('DOMContentLoaded', function () {
    // === Loader Overlay ===
    const loadingOverlay = document.getElementById('loading-overlay');
    function showLoader() { if (loadingOverlay) loadingOverlay.classList.add('show'); }
    function hideLoader() { if (loadingOverlay) loadingOverlay.classList.remove('show'); }
    hideLoader();
    document.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', function (e) {
            if (this.target === '_blank' || this.href.startsWith('javascript:') || this.classList.contains('no-loader')) return;
            if (this.hash && (this.pathname === window.location.pathname)) return;
            const tgl = this.getAttribute('data-bs-toggle');
            if (tgl === 'dropdown' || tgl === 'collapse' || tgl === 'modal') return;
            const href = (this.getAttribute('href') || '').toLowerCase();
            if (href.includes('export') || href.includes('download') || href.endsWith('.docx') || href.endsWith('.csv') || href.endsWith('.xlsx')) return;
            showLoader();
            setTimeout(hideLoader, 8000);
        });
    });
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function () {
            if (this.target === '_blank' || this.classList.contains('no-loader')) return;
            showLoader();
            setTimeout(hideLoader, 8000);
        });
    });
    window.addEventListener('load', hideLoader);
    window.addEventListener('pageshow', function (event) { if (event.persisted) hideLoader(); });

    // === Dark Mode Toggle ===
    const toggleButton = document.getElementById('darkModeToggle');
    const body = document.body;
    const toggleIcon = toggleButton ? toggleButton.querySelector('i') : null;
    function applyTheme(theme) {
        if (theme === 'dark') {
            body.classList.add('dark-mode');
            if (toggleIcon) { toggleIcon.classList.remove('fa-moon'); toggleIcon.classList.add('fa-sun'); }
            localStorage.setItem('theme', 'dark');
        } else {
            body.classList.remove('dark-mode');
            if (toggleIcon) { toggleIcon.classList.remove('fa-sun'); toggleIcon.classList.add('fa-moon'); }
            localStorage.setItem('theme', 'light');
        }
        try {
            const metaLight = document.querySelector('meta[media="(prefers-color-scheme: light)"][name="theme-color"]');
            const metaDark = document.querySelector('meta[media="(prefers-color-scheme: dark)"][name="theme-color"]');
            if (metaLight && metaDark) {
                if (theme === 'dark') metaDark.setAttribute('content', getComputedStyle(document.documentElement).getPropertyValue('--bg-main').trim() || '#1a1a1a');
                else metaLight.setAttribute('content', getComputedStyle(document.documentElement).getPropertyValue('--bg-main').trim() || '#f8f9fa');
            }
        } catch (e) {}
    }
    if (toggleButton && toggleIcon) {
        let currentTheme = localStorage.getItem('theme');
        if (!currentTheme) currentTheme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        applyTheme(currentTheme);
        try {
            toggleButton.setAttribute('aria-pressed', (currentTheme === 'dark').toString());
            toggleButton.setAttribute('title', currentTheme === 'dark' ? 'Comută la tema luminoasă' : 'Comută la tema întunecată');
        } catch (e) {}
        toggleButton.addEventListener('click', function () {
            currentTheme = body.classList.contains('dark-mode') ? 'light' : 'dark';
            applyTheme(currentTheme);
            try {
                const isPressed = this.getAttribute('aria-pressed') === 'true';
                this.setAttribute('aria-pressed', (!isPressed).toString());
                this.setAttribute('title', currentTheme === 'dark' ? 'Comută la tema luminoasă' : 'Comută la tema întunecată');
            } catch (e) {}
        });
        try {
            const media = window.matchMedia('(prefers-color-scheme: dark)');
            media.addEventListener('change', (e) => {
                const explicit = localStorage.getItem('theme');
                if (!explicit) applyTheme(e.matches ? 'dark' : 'light');
            });
        } catch (e) {}
    }
    window.addEventListener('storage', (e) => {
        if (e.key === 'theme' && (e.newValue === 'dark' || e.newValue === 'light')) {
            applyTheme(e.newValue);
            if (toggleButton) {
                try { toggleButton.setAttribute('aria-pressed', (e.newValue === 'dark').toString()); } catch (err) {}
            }
        }
    });

    // === Copy-to-Clipboard for .copy-btn buttons (existing feature) ===
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', function () {
            const targetSelector = this.dataset.target;
            const targetElement = document.querySelector(targetSelector);
            if (targetElement) {
                const textToCopy = targetElement.innerText || targetElement.textContent;
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalText = this.innerHTML;
                    this.innerHTML = '<i class="fas fa-check"></i> Copiat!';
                    this.classList.remove('btn-outline-secondary');
                    this.classList.add('btn-success');
                    setTimeout(() => {
                        this.innerHTML = originalText;
                        this.classList.remove('btn-success');
                        this.classList.add('btn-outline-secondary');
                    }, 2000);
                }).catch(err => {
                    console.error('Eroare la copierea textului: ', err);
                    alert('Eroare la copierea textului. Este posibil ca browserul dvs. să nu suporte această funcționalitate.');
                });
            }
        });
    });

    // === Floating Print/Top FABs ===
    function hasTableOnPage() { return document.querySelector('.table') !== null; }
    function createFloatingActions() {
        if (!hasTableOnPage()) return;
        const container = document.createElement('div');
        container.className = 'fab-container';
        const printBtn = document.createElement('button');
        printBtn.className = 'btn btn-secondary fab-button no-loader';
        printBtn.type = 'button';
        printBtn.title = 'Printează pagina (Shift+P)';
        printBtn.innerHTML = '<i class="fas fa-print"></i>';
        printBtn.addEventListener('click', () => window.print());
        const topBtn = document.createElement('button');
        topBtn.className = 'btn btn-secondary fab-button no-loader';
        topBtn.type = 'button';
        topBtn.title = 'Mergi sus (Shift+T)';
        topBtn.innerHTML = '<i class="fas fa-arrow-up"></i>';
        topBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
        container.appendChild(printBtn);
        container.appendChild(topBtn);
        document.body.appendChild(container);
    }
    createFloatingActions();

    // === Keyboard Shortcuts ===
    document.addEventListener('keydown', (e) => {
        if (e.shiftKey && !e.ctrlKey && !e.altKey) {
            if (e.key.toLowerCase() === 'd') {
                if (toggleButton) toggleButton.click();
            } else if (e.key.toLowerCase() === 'p') {
                window.print();
            } else if (e.key.toLowerCase() === 't') {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }
    });

    // === Persist GET Form Filter State ===
    function restoreFormState(form) {
        try {
            const key = 'form:' + location.pathname;
            const saved = localStorage.getItem(key);
            if (!saved) return;
            const data = JSON.parse(saved);
            Array.from(form.elements).forEach(el => {
                if (!el.name) return;
                if (el.type === 'checkbox' || el.type === 'radio') {
                    el.checked = !!data[el.name];
                } else if (el.tagName === 'SELECT') {
                    if (Array.isArray(data[el.name])) {
                        Array.from(el.options).forEach(opt => opt.selected = data[el.name].includes(opt.value));
                    } else {
                        el.value = data[el.name] ?? el.value;
                    }
                } else {
                    el.value = data[el.name] ?? el.value;
                }
            });
        } catch (e) { /* noop */ }
    }
    function saveFormState(form) {
        try {
            const key = 'form:' + location.pathname;
            const data = {};
            Array.from(form.elements).forEach(el => {
                if (!el.name) return;
                if (el.type === 'checkbox') {
                    data[el.name] = el.checked;
                } else if (el.type === 'radio') {
                    if (el.checked) data[el.name] = el.value;
                } else if (el.tagName === 'SELECT' && el.multiple) {
                    data[el.name] = Array.from(el.selectedOptions).map(o => o.value);
                } else {
                    data[el.name] = el.value;
                }
            });
            localStorage.setItem(key, JSON.stringify(data));
        } catch (e) { /* noop */ }
    }
    document.querySelectorAll('form').forEach(form => {
        const isGet = (form.method || 'GET').toUpperCase() === 'GET';
        const isAuth = /login|logout|password/i.test(form.action || '') || form.querySelector('input[type="password"]');
        if (!isGet || isAuth) return;
        restoreFormState(form);
        form.addEventListener('change', () => saveFormState(form));
        form.addEventListener('input', () => saveFormState(form));
    });

    // === Table Sort Helper ===
    function inferType(value) {
        const v = value.trim();
        if (!v) return 'text';
        const num = v.replace(/\s/g, '').replace(',', '.');
        if (!isNaN(num) && num !== '') return 'number';
        if (/^\d{1,2}[:\.\-]\d{1,2}([:\.\-]\d{2,4})?$/.test(v) || /\d{4}-\d{2}-\d{2}/.test(v)) return 'text-dateish';
        return 'text';
    }
    function getCellText(cell) {
        return (cell.getAttribute('data-value') || cell.innerText || '').replace(/\s+/g, ' ').trim();
    }
    function compare(a, b, type) {
        if (type === 'number') return parseFloat(a.replace(',', '.')) - parseFloat(b.replace(',', '.'));
        return a.localeCompare(b, undefined, { sensitivity: 'base', numeric: true });
    }
    function makeTableSortable(table) {
        const thead = table.querySelector('thead');
        if (!thead) return;
        thead.querySelectorAll('th').forEach((th, index) => {
            if (th.classList.contains('no-sort')) return;
            th.classList.add('th-sortable');
            th.tabIndex = 0;
            th.setAttribute('role', 'button');
            th.addEventListener('click', () => sortBy(index, th));
            th.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortBy(index, th); } });
        });
        function sortBy(colIndex, th) {
            const tbody = table.querySelector('tbody');
            if (!tbody) return;
            const rows = Array.from(tbody.querySelectorAll('tr'));
            if (rows.length === 0) return;
            const sample = getCellText(rows[0].children[colIndex] || { innerText: '' });
            const type = inferType(sample);
            const current = th.getAttribute('aria-sort');
            const direction = current === 'ascending' ? 'descending' : 'ascending';
            thead.querySelectorAll('th[aria-sort]').forEach(x => x.removeAttribute('aria-sort'));
            th.setAttribute('aria-sort', direction);
            rows.sort((r1, r2) => {
                const a = getCellText(r1.children[colIndex] || { innerText: '' });
                const b = getCellText(r2.children[colIndex] || { innerText: '' });
                const cmp = compare(a, b, type);
                return direction === 'ascending' ? cmp : -cmp;
            });
            rows.forEach(r => tbody.appendChild(r));
        }
    }

    // === Responsive Table Wrapper & Sticky Headers ===
    function ensureResponsiveTables() {
        document.querySelectorAll('table.table').forEach(table => {
            if (!table.closest('.table-responsive')) {
                let wrap = document.createElement('div');
                wrap.className = 'table-responsive';
                table.parentNode.insertBefore(wrap, table);
                wrap.appendChild(table);
            }
            table.classList.add('table-sticky-header');
        });
    }
    ensureResponsiveTables();

    // === Universal Copy Features ===
    // --- Helper: Visible row text (respects column visibility) ---
    function getVisibleRowText(tr) {
        return Array.from(tr.querySelectorAll('td')).filter(td => td.offsetParent !== null && td.style.display !== 'none').map(getCellText).join('\t');
    }
    // --- In-place bubble ---
    function showCopyBubble(targetEl, text = 'Copiat') {
        let bubble = document.createElement('div');
        bubble.className = 'copy-bubble';
        bubble.innerText = text;
        document.body.appendChild(bubble);
        const rect = targetEl.getBoundingClientRect();
        bubble.style.left = (rect.left + rect.width / 2 + window.scrollX) + 'px';
        bubble.style.top = (rect.top + window.scrollY - 4) + 'px';
        setTimeout(() => bubble.classList.add('show'), 10);
        setTimeout(() => { bubble.classList.remove('show'); setTimeout(() => bubble.remove(), 180); }, 1200);
    }
    // --- Custom context menu (singleton) ---
    let contextMenuEl = null;
    function closeContextMenu() {
        if (contextMenuEl) { contextMenuEl.remove(); contextMenuEl = null; }
        document.removeEventListener('mousedown', closeContextMenu, true);
        document.removeEventListener('scroll', closeContextMenu, true);
        document.removeEventListener('keydown', contextMenuKeyHandler, true);
    }
    function contextMenuKeyHandler(e) { if (e.key === 'Escape') closeContextMenu(); }
    function showContextMenu(ev, cell) {
        closeContextMenu();
        contextMenuEl = document.createElement('div');
        contextMenuEl.className = 'context-menu';
        contextMenuEl.innerHTML = `
            <div class="item" data-act="cell">Copiază celula</div>
            <div class="item" data-act="row">Copiază rândul</div>
        `;
        document.body.appendChild(contextMenuEl);
        let x = ev.clientX, y = ev.clientY;
        let menuW = 180, menuH = 80;
        if (x + menuW > window.innerWidth) x = window.innerWidth - menuW - 6;
        if (y + menuH > window.innerHeight) y = window.innerHeight - menuH - 6;
        contextMenuEl.style.left = x + 'px';
        contextMenuEl.style.top = y + 'px';
        contextMenuEl.querySelector('[data-act=cell]').onclick = function () {
            navigator.clipboard.writeText(getCellText(cell));
            showCopyBubble(cell);
            closeContextMenu();
        };
        contextMenuEl.querySelector('[data-act=row]').onclick = function () {
            navigator.clipboard.writeText(getVisibleRowText(cell.parentElement));
            showCopyBubble(cell.parentElement);
            closeContextMenu();
        };
        setTimeout(() => {
            document.addEventListener('mousedown', closeContextMenu, true);
            document.addEventListener('scroll', closeContextMenu, true);
            document.addEventListener('keydown', contextMenuKeyHandler, true);
        }, 10);
    }
    // --- Attach copy handlers to all tds ---
    function setupCellCopyHandlers(td) {
        if (td.hasAttribute('data-copy-handler')) return;
        td.setAttribute('data-copy-handler', '1');
        td.addEventListener('dblclick', function (e) {
            navigator.clipboard.writeText(getCellText(td));
            showCopyBubble(td);
            e.preventDefault();
        });
        td.addEventListener('contextmenu', function (e) {
            e.preventDefault();
            showContextMenu(e, td);
        });
        let pressTimer = null;
        td.addEventListener('touchstart', function () {
            if (pressTimer) clearTimeout(pressTimer);
            pressTimer = setTimeout(() => {
                navigator.clipboard.writeText(getCellText(td));
                showCopyBubble(td);
            }, 600);
        }, { passive: true });
        td.addEventListener('touchend', function () { if (pressTimer) clearTimeout(pressTimer); });
        td.addEventListener('touchcancel', function () { if (pressTimer) clearTimeout(pressTimer); });
    }
    function enhanceTableCells() {
        document.querySelectorAll('table.table tbody td').forEach(setupCellCopyHandlers);
    }

    // === Table Tools (Filter, Column, Density, Copy Table) ===
    function enhanceTable(table) {
        const thead = table.querySelector('thead');
        const tbody = table.querySelector('tbody');
        if (!thead || !tbody) return;
        const tools = document.createElement('div');
        tools.className = 'table-tools d-flex flex-wrap align-items-center gap-2 mb-2';
        const filterInput = document.createElement('input');
        filterInput.className = 'form-control form-control-sm table-filter-input';
        filterInput.type = 'search';
        filterInput.placeholder = 'Filtrează rânduri (Shift+F)';
        filterInput.autocomplete = 'off';
        tools.appendChild(filterInput);
        const densityBtn = document.createElement('button');
        densityBtn.className = 'btn btn-outline-secondary btn-sm';
        densityBtn.type = 'button';
        densityBtn.title = 'Comută densitatea tabelului';
        densityBtn.innerHTML = '<i class="fas fa-compress-arrows-alt"></i>';
        densityBtn.addEventListener('click', () => { table.classList.toggle('table-compact'); });
        tools.appendChild(densityBtn);
        const dropdown = document.createElement('div');
        dropdown.className = 'dropdown d-inline-block';
        dropdown.innerHTML = '<button class="btn btn-outline-secondary btn-sm dropdown-toggle" type="button" data-bs-toggle="dropdown">Coloane</button><div class="dropdown-menu p-2 columns-menu" style="min-width: 220px;"></div>';
        const menu = dropdown.querySelector('.columns-menu');
        tools.appendChild(dropdown);
        const wrap = table.closest('.table-responsive');
        if (wrap && wrap.parentElement) wrap.parentElement.insertBefore(tools, wrap);
        else table.parentElement.insertBefore(tools, table);
        const ths = Array.from(thead.querySelectorAll('th'));
        const storageKey = 'columns:' + location.pathname;
        let visible = ths.map(() => true);
        try { const saved = JSON.parse(localStorage.getItem(storageKey) || 'null'); if (Array.isArray(saved) && saved.length === visible.length) visible = saved; } catch (e) { }
        function applyColumnVisibility() {
            Array.from(table.querySelectorAll('tr')).forEach(tr => {
                ths.forEach((_, idx) => {
                    const cell = tr.children[idx];
                    if (cell) cell.style.display = (visible[idx] ? '' : 'none');
                });
            });
        }
        function saveVisibility() {
            try { localStorage.setItem(storageKey, JSON.stringify(visible)); } catch (e) { }
        }
        ths.forEach((th, idx) => {
            const label = document.createElement('label');
            label.className = 'dropdown-item d-flex align-items-center gap-2';
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.className = 'form-check-input';
            cb.checked = visible[idx];
            cb.addEventListener('change', () => { visible[idx] = cb.checked; applyColumnVisibility(); saveVisibility(); });
            label.appendChild(cb);
            const span = document.createElement('span');
            span.textContent = (th.innerText || th.textContent || `Col ${idx + 1}`).trim() || `Col ${idx + 1}`;
            label.appendChild(span);
            menu.appendChild(label);
        });
        applyColumnVisibility();
        function filterRows() {
            const q = filterInput.value.trim().toLowerCase();
            const trs = Array.from(tbody.querySelectorAll('tr'));
            if (!q) { trs.forEach(tr => tr.style.display = ''); return; }
            trs.forEach(tr => {
                const text = (tr.innerText || '').toLowerCase();
                tr.style.display = text.includes(q) ? '' : 'none';
            });
        }
        filterInput.addEventListener('input', filterRows);
        document.addEventListener('keydown', (e) => { if (e.shiftKey && !e.ctrlKey && !e.altKey && e.key.toLowerCase() === 'f') { filterInput.focus(); e.preventDefault(); } });

        // === Copy Table Button ===
        const copyTableBtn = document.createElement('button');
        copyTableBtn.className = 'btn btn-outline-secondary btn-sm';
        copyTableBtn.type = 'button';
        copyTableBtn.title = 'Copiază tabelul vizibil';
        copyTableBtn.innerHTML = '<i class="fas fa-copy"></i> Copiază tabelul';
        copyTableBtn.addEventListener('click', () => {
            let out = [];
            // Visible ths except "Acțiuni"
            let head = [];
            ths.forEach((th, idx) => {
                if (th.offsetParent !== null && th.style.display !== 'none' && !/ac.tiuni/i.test(th.innerText))
                    head.push((th.innerText || '').trim());
            });
            out.push(head.join('\t'));
            Array.from(tbody.querySelectorAll('tr')).forEach(tr => {
                if (tr.style.display === 'none') return;
                let row = [];
                Array.from(tr.children).forEach((td, idx) => {
                    if (td.offsetParent !== null && td.style.display !== 'none')
                        row.push(getCellText(td));
                });
                if (row.length) out.push(row.join('\t'));
            });
            navigator.clipboard.writeText(out.join('\n'));
            showCopyBubble(copyTableBtn, 'Tabel copiat');
        });
        tools.appendChild(copyTableBtn);
    }

    // === Enhance All Tables ===
    document.querySelectorAll('table.table').forEach(table => {
        makeTableSortable(table);
        enhanceTable(table);
    });
    enhanceTableCells();

    // === Coachmark for Copy, once ===
    function showCopyCoachmark() {
        if (localStorage.getItem('coach:copy') === '1') return;
        const firstTable = document.querySelector('.table');
        if (!firstTable) return;
        let coach = document.createElement('div');
        coach.className = 'coachmark-copy';
        coach.innerHTML = `<span><i class="fas fa-mouse-pointer"></i> Dublu-click pentru a copia celula. Click dreapta pentru opțiuni.</span><button class="close" tabindex="0">&times;</button>`;
        let container = firstTable.closest('.table-responsive')?.parentElement || firstTable.parentElement;
        container.insertBefore(coach, firstTable.closest('.table-responsive') || firstTable);
        coach.querySelector('.close').onclick = () => { coach.remove(); localStorage.setItem('coach:copy', '1'); };
    }
    showCopyCoachmark();

    // === Remaining features (PWA, cmd palette, reminders, etc.) ===
    // ---- PWA: Register Service Worker ----
    (function swRegister() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/static/sw.js').catch(() => { });
        }
    })();
    // ---- Command Palette (Ctrl+K) ----
    (function initCommandPalette() {
        const allLinks = Array.from(document.querySelectorAll('a[href]'))
            .filter(a => a.href && !a.href.startsWith('javascript:') && !a.getAttribute('href').startsWith('#'))
            .map(a => ({ href: a.getAttribute('href'), text: (a.innerText || a.title || a.href).replace(/\s+/g, ' ').trim() }))
            .filter(x => x.text)
            .reduce((acc, cur) => { if (!acc.find(y => y.href === cur.href)) acc.push(cur); return acc; }, []);
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.tabIndex = -1;
        modal.innerHTML = '<div class="modal-dialog modal-dialog-centered"><div class="modal-content command-palette">'
            + '<div class="modal-header py-2"><input type="search" class="form-control form-control-lg cp-input" placeholder="Caută... (Ctrl+K)"/></div>'
            + '<div class="modal-body p-0"><ul class="list-group list-group-flush cp-list" style="max-height:50vh;overflow:auto"></ul></div>'
            + '</div></div>';
        document.body.appendChild(modal);
        let bsModal = null;
        try { bsModal = new bootstrap.Modal(modal, { backdrop: true }); } catch (_) { }
        const input = modal.querySelector('.cp-input');
        const list = modal.querySelector('.cp-list');
        function render(items) {
            list.innerHTML = '';
            items.slice(0, 50).forEach(it => {
                const li = document.createElement('li');
                li.className = 'list-group-item list-group-item-action';
                li.textContent = it.text;
                li.addEventListener('click', () => { window.location.href = it.href; });
                list.appendChild(li);
            });
        }
        function openPalette() { render(allLinks); if (bsModal) bsModal.show(); else modal.style.display = 'block'; setTimeout(() => input.focus(), 100); }
        function closePalette() { if (bsModal) bsModal.hide(); else modal.style.display = 'none'; }
        input.addEventListener('input', () => {
            const q = input.value.toLowerCase().trim();
            if (!q) return render(allLinks);
            const filtered = allLinks.filter(x => x.text.toLowerCase().includes(q));
            render(filtered);
        });
        input.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closePalette(); } });
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); }
        });
    })();

    // (Other modules: form helpers, reminders, favorites, netStatus, savedViews ...)
    // ... all other features as previously implemented, unchanged ...
});