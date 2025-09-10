// Genie Modernized Main JS with Legacy Modules Restored (no selection/CSV)
document.addEventListener('DOMContentLoaded', function () {
    // === Loader Overlay ===
    const loadingOverlay = document.getElementById('loading-overlay');
    function showLoader() { if (loadingOverlay) loadingOverlay.classList.add('show'); }
    function hideLoader() { if (loadingOverlay) loadingOverlay.classList.remove('show'); }
    hideLoader();

    // Track if a Bootstrap modal is open to avoid trapping UI behind overlay/backdrop
    let modalOpen = false;
    document.addEventListener('shown.bs.modal', () => { modalOpen = true; hideLoader(); });
    document.addEventListener('hidden.bs.modal', () => { modalOpen = false; hideLoader(); });

    document.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', function (e) {
            // Ignore links that should not trigger the global loader
            if (modalOpen) return; // Never show loader while a modal is open
            if (this.target === '_blank' || this.href.startsWith('javascript:') || this.classList.contains('no-loader')) return;
            if (this.hash && (this.pathname === window.location.pathname)) return;
            // Ignore clicks inside any modal dialog
            if (this.closest('.modal')) return;
            const tgl = this.getAttribute('data-bs-toggle');
            if (tgl === 'dropdown' || tgl === 'collapse' || tgl === 'modal') return;
            const href = (this.getAttribute('href') || '').toLowerCase();
            if (href.includes('export') || href.includes('download') || href.endsWith('.docx') || href.endsWith('.csv') || href.endsWith('.xlsx')) return;
            // Do not show the loader for FullCalendar event anchors (they render as <a> inside .fc)
            if (this.classList.contains('fc-event') || this.closest('.fc')) return;
            showLoader();
            setTimeout(hideLoader, 8000);
        }, true);
    });
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function () {
            if (modalOpen) return; // avoid overlay when submitting forms inside modals
            if (this.target === '_blank' || this.classList.contains('no-loader')) return;
            showLoader();
            setTimeout(hideLoader, 8000);
        });
    });
    window.addEventListener('load', hideLoader);
    window.addEventListener('pageshow', function (event) { if (event.persisted) hideLoader(); });

    // === Dark Mode Toggle ===
    const toggleButton = document.getElementById('darkModeToggle');
    const htmlElement = document.documentElement;
    const toggleIcon = toggleButton ? toggleButton.querySelector('i') : null;
    function applyTheme(theme) {
        htmlElement.setAttribute('data-theme', theme);
        // Remove the preload class once a theme is applied to avoid conflicting variables
        try { document.documentElement.classList.remove('dark-mode-preload'); } catch (e) {}
        if (toggleIcon) {
            if (theme === 'dark') {
                toggleIcon.classList.remove('fa-moon');
                toggleIcon.classList.add('fa-sun');
            } else {
                toggleIcon.classList.remove('fa-sun');
                toggleIcon.classList.add('fa-moon');
            }
        }
        localStorage.setItem('theme', theme);
        try {
            const metaLight = document.querySelector('meta[media="(prefers-color-scheme: light)"][name="theme-color"]');
            const metaDark = document.querySelector('meta[media="(prefers-color-scheme: dark)"][name="theme-color"]');
            if (metaLight && metaDark) {
                const bg = getComputedStyle(document.documentElement).getPropertyValue('--bg-main').trim();
                if (theme === 'dark') metaDark.setAttribute('content', bg || '#1a1a1a');
                else metaLight.setAttribute('content', bg || '#f8f9fa');
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
            const newTheme = htmlElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            applyTheme(newTheme);
            try {
                const isPressed = this.getAttribute('aria-pressed') === 'true';
                this.setAttribute('aria-pressed', (!isPressed).toString());
                this.setAttribute('title', newTheme === 'dark' ? 'Comută la tema luminoasă' : 'Comută la tema întunecată');
            } catch (e) {}
        });
        try {
            const media = window.matchMedia('(prefers-color-scheme: dark)');
            media.addEventListener('change', (e) => {
                const explicit = localStorage.getItem('theme');
                if (!explicit) applyTheme(e.matches ? 'dark' : 'light');
            });
        } catch (e) {}
    } else {
        // If toggle is missing, still apply stored or system theme and drop preload class
        const stored = localStorage.getItem('theme');
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        applyTheme(stored || (prefersDark ? 'dark' : 'light'));
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
    function getVisibleRowText(tr) {
        return Array.from(tr.querySelectorAll('td')).filter(td => td.offsetParent !== null && td.style.display !== 'none').map(getCellText).join('\t');
    }
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

    // === Mobile-first enhancements for dense pages ===
    (function mobileDenseTables(){
        const isSmall = () => window.matchMedia('(max-width: 576px)').matches;
        function apply() {
            document.querySelectorAll('table.table').forEach(t => {
                if (isSmall()) t.classList.add('table-compact');
                else t.classList.remove('table-compact');
            });
        }
        apply();
        window.addEventListener('resize', apply);
        window.addEventListener('orientationchange', () => setTimeout(apply, 150));
    })();

    // === Mobile collapsible cards (compact sections) ===
    (function mobileCollapsibleCards(){
        const isSmall = () => window.matchMedia('(max-width: 576px)').matches;
        function enhance() {
            if (!isSmall()) return;
            document.querySelectorAll('.card').forEach((card, idx) => {
                if (card.getAttribute('data-collapsible-init') === '1') return;
                const header = card.querySelector('.card-header');
                const body = card.querySelector('.card-body');
                if (!header || !body) return;
                const id = card.id || ('card_' + Math.random().toString(36).slice(2));
                card.id = id;
                const collapseId = id + '_c';
                body.id = collapseId;

                // Start expanded by default
                body.classList.add('collapse', 'show');

                // Add toggle button to header (right aligned)
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-sm btn-outline-secondary no-loader';
                btn.setAttribute('data-bs-toggle', 'collapse');
                btn.setAttribute('data-bs-target', '#' + collapseId);
                btn.setAttribute('aria-expanded', 'true');
                btn.setAttribute('aria-controls', collapseId);
                btn.innerHTML = '<i class="fas fa-chevron-up"></i>';

                // Wrap header content to align toggle right
                const hdr = document.createElement('div');
                while (header.firstChild) hdr.appendChild(header.firstChild);
                header.appendChild(hdr);
                const right = document.createElement('div');
                right.appendChild(btn);
                header.classList.add('d-flex','justify-content-between','align-items-center','gap-2');
                header.appendChild(right);

                body.addEventListener('shown.bs.collapse', () => { btn.innerHTML = '<i class="fas fa-chevron-up"></i>'; btn.setAttribute('aria-expanded','true'); });
                body.addEventListener('hidden.bs.collapse', () => { btn.innerHTML = '<i class="fas fa-chevron-down"></i>'; btn.setAttribute('aria-expanded','false'); });
                card.setAttribute('data-collapsible-init','1');
            });
        }
        enhance();
        window.addEventListener('resize', () => { /* no-op; only enhances on first entry to small */ });
        window.addEventListener('orientationchange', () => setTimeout(enhance, 150));
    })();

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

    // === RESTORED MODULES BELOW (NO SELECTION/CSV) ===

    // 1. Favorites Module
    (function favorites(){
        const KEY='favorites:links';
        const current = { href: location.pathname + location.search, title: (document.title || location.pathname).replace(/\s*[-|].*$/,'').trim() };
        function get(){ try { return JSON.parse(localStorage.getItem(KEY)||'[]'); } catch(_){ return []; } }
        function set(v){ try { localStorage.setItem(KEY, JSON.stringify(v)); } catch(_){ } }
        function isFav(favs){ return !!favs.find(x=>x.href===current.href); }
        const favToggle = document.createElement('button');
        favToggle.className='btn btn-outline-secondary btn-sm no-loader ms-2';
        favToggle.title='Adaugă/șterge din Favorite';
        favToggle.innerHTML='<i class="far fa-star"></i>';
        const nav = document.querySelector('#navbarNav .navbar-nav');
        if (nav) { const li=document.createElement('li'); li.className='nav-item d-flex align-items-center'; li.appendChild(favToggle); nav.appendChild(li);}
        function refreshIcon(){ const favs=get(); favToggle.innerHTML = isFav(favs) ? '<i class="fas fa-star"></i>' : '<i class="far fa-star"></i>'; }
        favToggle.addEventListener('click',()=>{ const favs=get(); const i=favs.findIndex(x=>x.href===current.href); if(i>=0) favs.splice(i,1); else favs.unshift(current); set(favs.slice(0,15)); refreshIcon(); renderMenu(); });
        refreshIcon();
        function renderMenu(){
            const dd = document.querySelector('#favoritesDropdown'); if (!dd) return;
            const ul = dd.querySelector('.dropdown-menu');
            const favs = get();
            dd.style.display = favs.length ? '' : 'none';
            ul.innerHTML = '<li class="dropdown-header">Favorite</li><li><hr class="dropdown-divider"></li>' + (favs.map(x=>`<li><a class="dropdown-item" href="${x.href}"><i class=\\"fas fa-star text-warning\\"></i> ${x.title}</a></li>`).join('') || '<li class="px-3 text-muted small">Nicio pagină favorită încă</li>');
        }
        renderMenu();
    })();

    // 2. Saved Views Module (Filter Presets for GET Forms)
    (function savedViews(){
        const forms = Array.from(document.querySelectorAll('form')).filter(f=> (f.method||'GET').toUpperCase()==='GET' && !/login|logout|password/i.test(f.action||''));
        if (!forms.length) return;
        const container = document.createElement('div');
        container.className = 'd-inline-block ms-2';
        container.innerHTML = '<div class="dropdown d-inline-block">\
            <button class="btn btn-outline-secondary btn-sm dropdown-toggle no-loader" type="button" data-bs-toggle="dropdown">Vederi</button>\
            <div class="dropdown-menu p-2" style="min-width:260px">\
            <div class="d-flex gap-2 mb-2">\
              <input type="text" class="form-control form-control-sm sv-name" placeholder="Nume vedere">\
              <button class="btn btn-sm btn-primary sv-save">Salvează</button>\
            </div>\
            <div class="sv-list small"></div>\
            </div>\
        </div>';
        const toolInsertTarget = document.querySelector('.table-responsive')?.parentElement || document.querySelector('.container');
        if (toolInsertTarget) toolInsertTarget.insertBefore(container, toolInsertTarget.firstChild);
        const key='views:'+location.pathname;
        function get(){ try { return JSON.parse(localStorage.getItem(key)||'[]'); }catch(_){ return [];}}
        function set(v){ try { localStorage.setItem(key, JSON.stringify(v)); }catch(_){ }}
        function capture(){ const data={}; forms.forEach(f=> Array.from(f.elements).forEach(el=>{ if(!el.name) return; if(el.type==='checkbox') data[el.name]=el.checked; else if(el.type==='radio'){ if(el.checked) data[el.name]=el.value; } else if(el.tagName==='SELECT' && el.multiple){ data[el.name]=Array.from(el.selectedOptions).map(o=>o.value);} else { data[el.name]=el.value; } })); return data; }
        function apply(data){ forms.forEach(f=> Array.from(f.elements).forEach(el=>{ if(!el.name) return; if(el.type==='checkbox') el.checked=!!data[el.name]; else if(el.type==='radio'){ el.checked = data[el.name]===el.value; } else if(el.tagName==='SELECT' && el.multiple){ Array.from(el.options).forEach(o=>o.selected=(data[el.name]||[]).includes(o.value)); } else { if(data[el.name]!==undefined) el.value=data[el.name]; } })); }
        function render(){ const list=container.querySelector('.sv-list'); const views=get(); list.innerHTML=''; if(!views.length){ list.textContent='Nu există vederi salvate.'; return;} views.forEach((v,i)=>{ const row=document.createElement('div'); row.className='d-flex justify-content-between align-items-center py-1'; row.innerHTML=`<span>${v.name}</span><span><button class=\\"btn btn-sm btn-outline-secondary me-1\\">Aplică</button><button class=\\"btn btn-sm btn-outline-danger\\">Șterge</button></span>`; const [btnApply, btnDel]=row.querySelectorAll('button'); btnApply.addEventListener('click',()=>{ apply(v.data); forms[0].submit(); }); btnDel.addEventListener('click',()=>{ const vs=get(); vs.splice(i,1); set(vs); render(); }); list.appendChild(row); }); }
        container.querySelector('.sv-save').addEventListener('click',()=>{ const name=container.querySelector('.sv-name').value.trim()||'Vedere'; const vs=get(); vs.unshift({ name, data: capture() }); set(vs.slice(0,20)); render(); });
        render();
    })();

    // 3. Daily Leave Date Validation
    (function dailyLeaveDateValidation() {
        const dateInput = document.getElementById('leave_date');
        if (dateInput) {
            dateInput.addEventListener('input', function(e) {
                const selectedDate = new Date(e.target.value);
                const day = selectedDate.getUTCDay(); // Sunday = 0, Monday = 1, ..., Saturday = 6
                if (day === 0 || day === 5 || day === 6) { // Sunday, Friday, Saturday
                    e.target.setCustomValidity('Învoirile zilnice sunt permise doar de Luni până Joi.');
                    e.target.reportValidity();
                } else {
                    e.target.setCustomValidity('');
                }
            });
        }
    })();

    // 4. Online/Offline indicator (netStatus)
    (function netStatus(){
        function toast(msg, variant){
            const el = document.createElement('div');
            el.className = `toast align-items-center text-bg-${variant||'secondary'} border-0 show`;
            el.setAttribute('role','status'); el.setAttribute('aria-live','polite'); el.setAttribute('aria-atomic','true');
            el.style.position='fixed'; el.style.right='12px'; el.style.bottom='12px'; el.style.zIndex='1060';
            el.innerHTML = `<div class="d-flex"><div class="toast-body">${msg}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div>`;
            document.body.appendChild(el);
            setTimeout(()=>{ try{ el.remove(); }catch(_){ } }, 3000);
        }
        window.addEventListener('online', ()=> toast('Conexiune restabilită', 'success'));
        window.addEventListener('offline', ()=> toast('Ești offline', 'warning'));
    })();

    // 5. Local Reminders (no backend)
    (function localReminders(){
        if (!('Notification' in window)) return;
        const KEY = 'reminders:enabled';
        const debugBar = document.querySelector('.container-fluid .text-muted.small');
        if (debugBar) {
            const btn = document.createElement('button');
            btn.className = 'btn btn-sm btn-outline-secondary no-loader';
            btn.textContent = localStorage.getItem(KEY) === '1' ? 'Remindere: ON' : 'Remindere: OFF';
            btn.addEventListener('click', async ()=>{
                if (localStorage.getItem(KEY) === '1') { localStorage.removeItem(KEY); btn.textContent='Remindere: OFF'; return; }
                const perm = await Notification.requestPermission();
                if (perm === 'granted') { localStorage.setItem(KEY, '1'); btn.textContent='Remindere: ON'; }
            });
            debugBar.parentElement.appendChild(btn);
        }
        if (localStorage.getItem(KEY) !== '1') return;
        const now = Date.now();
        document.querySelectorAll('[data-reminder="true"]').forEach(el => {
            const start = el.getAttribute('data-start');
            const title = el.getAttribute('data-title') || document.title;
            if (!start) return;
            const ts = new Date(start).getTime();
            const delta = ts - now - 5*60*1000; // 5 minutes before
            if (delta > 0 && delta < 24*60*60*1000) {
                setTimeout(()=>{
                    try { new Notification('Reminder', { body: title }); } catch(_){ }
                }, delta);
            }
        });
    })();

    // 6. Form Helpers (date/time quick-fill)
    (function formHelpers() {
        const candidates = Array.from(document.querySelectorAll('input.has-time-helpers'));
        if (!candidates.length) return;
        function getBucharestDateTimeParts() {
            const now = new Date();
            const options = { timeZone: 'Europe/Bucharest', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };
            const formatter = new Intl.DateTimeFormat('sv-SE', options);
            const [datePart, timePart] = formatter.format(now).split(' ');
            return { date: datePart, time: timePart };
        }
        candidates.forEach(input => {
            const container = document.createElement('div');
            container.className = 'd-flex flex-wrap align-items-center gap-2 mt-1';
            const quickHours = ['07:00', '15:00', '22:00'];
            quickHours.forEach(hour => {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-sm btn-outline-info';
                btn.textContent = hour;
                btn.title = `Setează ora la ${hour}`;
                btn.addEventListener('click', () => {
                    if (input.type === 'time') {
                        input.value = hour;
                    } else if (input.type === 'datetime-local') {
                        const currentVal = input.value;
                        const datePart = currentVal ? currentVal.split('T')[0] : getBucharestDateTimeParts().date;
                        input.value = `${datePart}T${hour}`;
                    }
                    input.dispatchEvent(new Event('change', { bubbles: true }));
                });
                container.appendChild(btn);
            });
            const btnNow = document.createElement('button');
            btnNow.type = 'button';
            btnNow.className = 'btn btn-sm btn-outline-secondary';
            btnNow.textContent = 'Acum';
            btnNow.title = 'Setează data și ora curentă';
            btnNow.addEventListener('click', () => {
                const parts = getBucharestDateTimeParts();
                if (input.type === 'time') {
                    input.value = parts.time;
                } else if (input.type === 'datetime-local') {
                    input.value = `${parts.date}T${parts.time}`;
                }
                input.dispatchEvent(new Event('change', { bubbles: true }));
            });
            container.appendChild(btnNow);
            input.parentNode.insertBefore(container, input.nextSibling);
        });
    })();

// === PWA SW Registration, Command Palette already present above ===
});