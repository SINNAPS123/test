// Academy Countdown + Quote of the Day (Bucharest time)
// This runs independent of main.js so it works in both DEBUG and PROD.
(function academyCountdownModule(){
    const badge = document.getElementById('academyCountdown');
    const quoteEl = document.getElementById('quoteOfTheDay');
    const weekendList = document.getElementById('academyWeekendList');
    if (!badge || !quoteEl) return;

    const timeZone = badge.getAttribute('data-tz') || 'Europe/Bucharest';
    let endISO = badge.getAttribute('data-end') || '2026-07-31T23:59:59+03:00';
    let endDate = new Date(endISO);

    if (!/[Zz]|[\+\-]\d{2}:?\d{2}/.test(endISO)) {
        const tzNow = getTZNow(timeZone);
        const [y,m,d] = endISO.split('T')[0].split('-').map(Number);
        const endLocalUTC = Date.UTC(y, m-1, d, 23, 59, 59);
        const offsetMin = tzNow.offsetMinutes;
        endDate = new Date(endLocalUTC - offsetMin * 60 * 1000);
    }

    function getTZNow(tz) {
        const d = new Date();
        const fmt = new Intl.DateTimeFormat('en-US', {
            timeZone: tz,
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false
        });
        const parts = fmt.formatToParts(d);
        const get = (t) => Number(parts.find(p => p.type === t).value);
        const year = get('year'), month = get('month'), day = get('day');
        const hour = get('hour'), minute = get('minute'), second = get('second');
        const tzMillis = Date.UTC(year, month-1, day, hour, minute, second);
        const nowUTC = d.getTime() + d.getTimezoneOffset() * 60 * 1000;
        const offsetMinutes = Math.round((tzMillis - nowUTC) / 60000);
        return { date: new Date(tzMillis - offsetMinutes * 60 * 1000), offsetMinutes };
    }

    function formatDHMS(ms) {
        if (ms <= 0) return '0 zile 00:00:00';
        const sec = Math.floor(ms / 1000);
        const days = Math.floor(sec / 86400);
        const rem = sec % 86400;
        const h = Math.floor(rem / 3600);
        const m = Math.floor((rem % 3600) / 60);
        const s = rem % 60;
        return `${days} zile ${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
    }

    const quotes = [
        '„Disciplină este podul dintre obiective și realizări.” – Jim Rohn',
        '„Succesul este suma micilor eforturi repetate zi de zi.” – Robert Collier',
        '„Curajul nu este absența fricii, ci triumful asupra ei.” – Nelson Mandela',
        '„Nu renunța. Suferința de azi e puterea de mâine.”',
        '„Mai e puțin. Fă încă un pas.”',
        '„Persistența bate talentul când talentul nu muncește.”',
        '„Fii consecvent. Rezultatele vin.”',
        '„Ordinea și disciplina aduc claritate și performanță.”',
        '„În fiecare zi, puțin mai bine.”',
        '„Concentrează-te pe ce poți controla.”',
        '„Când e greu, înseamnă că ești aproape.”',
        '„Motivația te pornește, disciplina te duce la finish.”',
        '„Învață din fiecare zi. Acumularea câștigă.”',
        '„Respectă-ți programul. Rezultatele urmează.”',
        '„Caracterul se construiește în zilele grele.”'
    ];
    function quoteForDate(tzDate) {
        const y = tzDate.getUTCFullYear();
        const m = tzDate.getUTCMonth()+1;
        const d = tzDate.getUTCDate();
        const key = Number(`${y}${String(m).padStart(2,'0')}${String(d).padStart(2,'0')}`);
        const idx = key % quotes.length;
        return quotes[idx];
    }

    function tick() {
        const tzNow = getTZNow(timeZone);
        const remaining = endDate - tzNow.date;
        badge.textContent = `Se termină în: ${formatDHMS(remaining)}`;
        quoteEl.textContent = quoteForDate(tzNow.date);
    }
    tick();
    const timer = setInterval(tick, 1000);

    function renderWeekendSchedule() {
        const tzNow = getTZNow(timeZone).date;
        const items = [];
        const maxItems = 12;
        let cursor = new Date(tzNow.getTime());
        while (cursor.getUTCDay() !== 6) { cursor.setUTCDate(cursor.getUTCDate() + 1); } // Saturday
        while (items.length < maxItems && cursor <= endDate) {
            const saturday = new Date(cursor.getTime());
            const sunday = new Date(cursor.getTime()); sunday.setUTCDate(sunday.getUTCDate() + 1);
            items.push(formatWeekend(saturday, sunday));
            cursor.setUTCDate(cursor.getUTCDate() + 7);
        }
        if (!weekendList) return;
        if (!items.length) {
            weekendList.innerHTML = '<div class="text-muted">Nu mai sunt weekenduri până la final.</div>';
            return;
        }
        weekendList.innerHTML = '<ul class="list-unstyled mb-0">' + items.map(li => `<li class="mb-1">• ${li}</li>`).join('') + '</ul>';
    }
    function formatWeekend(sat, sun) {
        const fmt = new Intl.DateTimeFormat('ro-RO', { timeZone: timeZone, day: '2-digit', month: '2-digit' });
        return `Weekend ${fmt.format(sat)} – ${fmt.format(sun)}`;
    }

    renderWeekendSchedule();
    const toggle = document.getElementById('academyCountdownToggle');
    if (toggle) {
        toggle.addEventListener('shown.bs.dropdown', renderWeekendSchedule);
    }

    // Minimal API
    window.AcademyCountdown = {
        setEnd(iso) { endISO = iso; endDate = new Date(iso); },
        getEnd() { return new Date(endDate.getTime()); }
    };
})();