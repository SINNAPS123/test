<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <title>Student Management Application README</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; padding: 20px; }
        h1, h2, h3 { color: #333; }
        h1 { text-align: center; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        h2 { border-bottom: 1px solid #eee; padding-bottom: 5px; margin-top: 30px; }
        code { background-color: #f4f4f4; padding: 2px 4px; border-radius: 4px; }
        ul, ol { margin-left: 20px; }
        section { margin-bottom: 20px; }
        .container { max-width: 900px; margin: auto; }
        nav#toc { background: #f9f9f9; border: 1px solid #ddd; padding: 15px; border-radius: 5px; margin-bottom: 30px; }
        nav#toc h2 { margin-top: 0; border-bottom: none; }
        nav#toc ul { list-style-type: none; padding-left: 0; }
        nav#toc ul li { margin-bottom: 5px; }
        nav#toc ul li a { text-decoration: none; color: #007bff; }
        nav#toc ul li a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="container">

    <h1>Aplicație pentru Gestiunea Studenților și Activităților Academice</h1>

    <nav id="toc">
        <h2>Cuprins</h2>
        <ul>
            <li><a href="#overview">1. Prezentare Generală</a></li>
            <li><a href="#features">2. Funcționalități Cheie</a>
                <ul>
                    <li><a href="#features-admin">2.1. Administrator</a></li>
                    <li><a href="#features-gradat">2.2. Gradat (Comandant Pluton)</a></li>
                    <li><a href="#features-cc">2.3. Comandant Companie</a></li>
                    <li><a href="#features-cb">2.4. Comandant Batalion</a></li>
                </ul>
            </li>
            <li><a href="#tech-stack">3. Tehnologii Utilizate</a></li>
            <li><a href="#setup">4. Configurare și Instalare</a></li>
            <li><a href="#database">5. Bază de Date</a></li>
            <li><a href="#authentication">6. Autentificare</a></li>
            <li><a href="#user-roles">7. Roluri Utilizatori (Detalii)</a></li>
            <li><a href="#workflows">8. Fluxuri de Lucru Principale</a></li>
            <li><a href="#reporting">9. Raportare</a></li>
            <li><a href="#bulk-operations">10. Operațiuni în Masă</a></li>
            <li><a href="#announcements">11. Anunțuri</a></li>
            <li><a href="#action-logging">12. Jurnalizare Acțiuni</a></li>
            <li><a href="#timezone">13. Fus Orar</a></li>
            <li><a href="#notes">14. Note Dezvoltare</a></li>
        </ul>
    </nav>

    <section id="overview">
        <h2>1. Prezentare Generală</h2>
        <p>Această aplicație web, construită cu Flask, este destinată managementului studenților și activităților asociate într-un context academic militar. Permite gestionarea detaliilor studenților, a învoirilor (permisii, învoiri zilnice, învoiri de weekend), a serviciilor, activităților de voluntariat și generarea de rapoarte specifice. Aplicația suportă multiple roluri de utilizatori, fiecare cu funcționalități și niveluri de acces distincte.</p>
    </section>

    <section id="features">
        <h2>2. Funcționalități Cheie</h2>

        <h3 id="features-admin">2.1. Administrator (<code>admin</code>)</h3>
        <ul>
            <li>Managementul utilizatorilor (creare, resetare coduri, ștergere, editare nume utilizator).</li>
            <li>Setarea directă a codurilor personale pentru utilizatori non-admin.</li>
            <li>Editarea detaliilor oricărui student.</li>
            <li>Vizualizarea listelor complete pentru permisii, învoiri zilnice, învoiri de weekend și servicii la nivel de sistem.</li>
            <li>Acces la jurnalul de acțiuni al sistemului.</li>
            <li>Managementul anunțurilor (creare, editare, ștergere, fixare, vizibilitate).</li>
            <li>Schimbarea propriei parole de administrator.</li>
            <li>Exportul datelor (studenți, permisii, învoiri) în format text și Word.</li>
            <li>Vizualizarea rapoartelor de prezență la nivel general (toți studenții).</li>
        </ul>

        <h3 id="features-gradat">2.2. Gradat (Comandant Pluton) (<code>gradat</code>)</h3>
        <ul>
            <li>Managementul studenților din plutonul arondat (adăugare, editare, ștergere, import bulk din text).</li>
            <li>Gestionarea permisiilor, învoirilor zilnice și învoirilor de weekend pentru studenții proprii (adăugare, editare, anulare, ștergere).</li>
            <li>Importul în masă al permisiilor și învoirilor de weekend din format text (din pagini dedicate).</li>
            <li>Exportul rapoartelor de permisii și învoiri de weekend în format Word pentru plutonul propriu.</li>
            <li>Asignarea serviciilor studenților (individual sau multiplu).</li>
            <li>Managementul activităților de voluntariat (creare activitate, adăugare participanți, acordare puncte).</li>
            <li>Generarea unei liste de studenți propuși pentru voluntariat (bazat pe puncte).</li>
            <li>Vizualizarea unui panou de control (dashboard) cu statistici și situația curentă a prezenței pentru pluton.</li>
            <li>Acces la istoricul învoirilor pentru plutonul propriu, cu opțiuni de filtrare pe perioade.</li>
            <li>Generarea rapoartelor de prezență pentru plutonul propriu (curent, apel de seară, etc.).</li>
        </ul>

        <h3 id="features-cc">2.3. Comandant Companie (<code>comandant_companie</code>)</h3>
        <ul>
            <li>Vizualizarea unui panou de control cu statistici agregate pentru compania sa (prezență la apel, învoiri/servicii curente și pentru ziua respectivă).</li>
            <li>Vizualizarea listelor de permisii, învoiri zilnice, învoiri de weekend și servicii filtrate pentru studenții din compania sa.</li>
            <li>Acces la jurnalul de acțiuni relevant pentru studenții și operațiunile din compania sa.</li>
            <li>Generarea rapoartelor de permisii și învoiri de weekend în format Word, filtrate pentru compania sa.</li>
            <li>Generarea unui raport de prezență în format text pentru compania sa.</li>
            <li>Vizualizarea rapoartelor de prezență pentru compania sa.</li>
        </ul>

        <h3 id="features-cb">2.4. Comandant Batalion (<code>comandant_batalion</code>)</h3>
        <ul>
            <li>Vizualizarea unui panou de control cu statistici agregate pentru batalionul său și sumarizări pe companii.</li>
            <li>Vizualizarea listelor de permisii, învoiri zilnice, învoiri de weekend și servicii filtrate pentru studenții din batalionul său.</li>
            <li>Acces la jurnalul de acțiuni relevant pentru studenții și operațiunile din batalionul său.</li>
            <li>Generarea rapoartelor de permisii și învoiri de weekend în format Word, filtrate pentru batalionul său.</li>
            <li>Generarea unui raport de prezență în format text pentru batalionul său, cu detalii pe companii.</li>
            <li>Vizualizarea rapoartelor de prezență pentru batalionul său.</li>
        </ul>
    </section>

    <section id="tech-stack">
        <h2>3. Tehnologii Utilizate</h2>
        <ul>
            <li><strong>Framework Backend:</strong> Flask</li>
            <li><strong>ORM (Object-Relational Mapper):</strong> Flask-SQLAlchemy</li>
            <li><strong>Bază de Date Implicită:</strong> SQLite</li>
            <li><strong>Autentificare:</strong> Flask-Login</li>
            <li><strong>Hashing Parole:</strong> Werkzeug (<code>generate_password_hash</code>, <code>check_password_hash</code>), bcrypt (pentru codurile personale)</li>
            <li><strong>Generare Documente Word:</strong> <code>python-docx</code></li>
            <li><strong>Framework Frontend:</strong> Bootstrap 5</li>
            <li><strong>Iconițe:</strong> Font Awesome 5</li>
            <li><strong>Motor de Templating:</strong> Jinja2</li>
            <li><strong>Migrații Bază de Date:</strong> Flask-Migrate (necesită configurare manuală inițială)</li>
            <li><strong>Gestionare Fus Orar:</strong> <code>pytz</code></li>
            <li><strong>Normalizare Text (diacritice):</strong> <code>unidecode</code></li>
        </ul>
    </section>

    <section id="setup">
        <h2>4. Configurare și Instalare</h2>
        <ol>
            <li><strong>Clonare Repository:</strong><br>
                <code>git clone &lt;URL_REPOSITORY&gt;</code><br>
                <code>cd &lt;NUME_DIRECTOR_PROIECT&gt;</code>
            </li>
            <li><strong>Creare Mediu Virtual (Recomandat):</strong><br>
                <code>python -m venv venv</code><br>
                Activare:
                <ul>
                    <li>Windows: <code>venv\\Scripts\\activate</code></li>
                    <li>Linux/macOS: <code>source venv/bin/activate</code></li>
                </ul>
            </li>
            <li><strong>Instalare Dependințe:</strong><br>
                <code>pip install -r requirements.txt</code>
            </li>
            <li><strong>Configurare Variabilă de Mediu (Opțional, dar Recomandat pentru Producție):</strong><br>
                Setați <code>FLASK_SECRET_KEY</code> la o valoare unică și puternică. Dacă nu este setată, se va folosi o cheie de fallback pentru dezvoltare.
            </li>
            <li><strong>Inițializare și Migrare Bază de Date (Flask-Migrate):</strong><br>
                Aceste comenzi se rulează în terminal, în directorul proiectului, după activarea mediului virtual și instalarea dependințelor.
                <ul>
                    <li>Dacă directorul <code>migrations</code> nu există: <code>flask db init</code> (se rulează o singură dată per proiect)</li>
                    <li>Pentru a genera o nouă migrare după modificări la modele: <code>flask db migrate -m "descriere modificari"</code></li>
                    <li>Pentru a aplica migrațiile la baza de date: <code>flask db upgrade</code></li>
                </ul>
                <em>Notă: Scriptul <code>app.py</code> include o secțiune la final (în interiorul <code>if __name__ == '__main__':</code>) care încearcă să aplice migrațiile (<code>flask_upgrade()</code>) și să ruleze <code>init_db()</code> la pornire. Aceasta este mai mult pentru conveniența în dezvoltare și ar trebui gestionată cu atenție în producție. <code>init_db()</code> creează tabelele și utilizatorul admin implicit dacă nu există.</em>
            </li>
            <li><strong>Pornire Aplicație:</strong><br>
                <code>python app.py</code><br>
                Sau folosind comanda Flask (după setarea <code>FLASK_APP=app.py</code>):<br>
                <code>flask run --host=0.0.0.0 --port=5001</code> (portul și hostul sunt configurate în <code>app.py</code>)
            </li>
        </ol>
        <p>La prima rulare, fișierul bazei de date <code>site.db</code> va fi creat în directorul rădăcină al proiectului. Utilizatorul administrator implicit este <code>admin</code> cu parola <code>admin123</code> (conform funcției <code>init_db</code>).</p>
    </section>

    <section id="database">
        <h2>5. Bază de Date</h2>
        <p>Aplicația utilizează SQLAlchemy pentru a interacționa cu o bază de date SQLite (<code>site.db</code>). Modelele principale definite în <code>app.py</code> sunt:</p>
        <ul>
            <li><code>User</code>: Informații despre utilizatori și rolurile lor.</li>
            <li><code>Student</code>: Detaliile studenților, inclusiv legătura cu utilizatorul <code>gradat</code> care i-a creat.</li>
            <li><code>Permission</code>: Permisii acordate studenților.</li>
            <li><code>DailyLeave</code>: Învoiri zilnice.</li>
            <li><code>WeekendLeave</code>: Învoiri de weekend.</li>
            <li><code>ServiceAssignment</code>: Servicii asignate studenților.</li>
            <li><code>VolunteerActivity</code>: Activități de voluntariat.</li>
            <li><code>ActivityParticipant</code>: Legătura dintre studenți și activitățile de voluntariat, inclusiv punctele acordate.</li>
            <li><code>ActionLog</code>: Jurnal pentru diverse acțiuni din sistem.</li>
            <li><code>UpdateTopic</code>: Anunțuri/actualizări pentru utilizatori.</li>
        </ul>
        <p>Relațiile dintre modele (ex: un student are multiple permisii) sunt definite folosind facilitățile SQLAlchemy (<code>db.relationship</code>, <code>db.ForeignKey</code>).</p>
    </section>

    <section id="authentication">
        <h2>6. Autentificare</h2>
        <p>Sistemul de autentificare este gestionat de Flask-Login și diferă în funcție de tipul de utilizator:</p>
        <ul>
            <li><strong>Administrator (<code>admin</code>):</strong>
                <ul>
                    <li>Se autentifică folosind un nume de utilizator și o parolă predefinite (<code>admin</code> / <code>admin123</code> la prima inițializare, parola poate fi schimbată din panoul admin).</li>
                    <li>Accesează ruta <code>/admin_login</code>.</li>
                </ul>
            </li>
            <li><strong>Utilizatori Non-Admin (<code>gradat</code>, <code>comandant_companie</code>, <code>comandant_batalion</code>):</strong>
                <ul>
                    <li><strong>Prima Autentificare:</strong> Utilizatorul primește un <strong>cod unic</strong> generat de administrator la crearea contului. Acest cod este introdus la ruta <code>/user_login</code>.</li>
                    <li><strong>Setare Cod Personal:</strong> După autentificarea cu succes cu codul unic, utilizatorul este redirecționat pentru a-și seta un <strong>cod personal</strong> (numeric sau alfanumeric, minim 4 caractere).</li>
                    <li><strong>Autentificări Ulterioare:</strong> Utilizatorul folosește codul personal setat anterior pentru a se loga prin ruta <code>/user_login</code>.</li>
                    <li>Codurile personale sunt stocate folosind hash bcrypt.</li>
                </ul>
            </li>
        </ul>
        <p>Sesiunile sunt gestionate de Flask-Login, iar utilizatorii neautentificați sunt redirecționați către paginile de login corespunzătoare la încercarea de a accesa rute protejate.</p>
    </section>

    <section id="user-roles">
        <h2>7. Roluri Utilizatori (Detalii)</h2>
        <p>Funcționalitățile detaliate pentru fiecare rol sunt descrise pe larg în secțiunea <a href="#features">Funcționalități Cheie</a>.</p>
        <!-- Aici se pot adăuga eventuale detalii suplimentare despre permisiunile specifice ale fiecărui rol, dacă este necesar, dar secțiunea Features acoperă deja acest aspect. -->
    </section>

    <section id="workflows">
        <h2>8. Fluxuri de Lucru Principale</h2>
        <ul>
            <li><strong>Crearea și Gestionarea Studenților (Gradat):</strong>
                <ol>
                    <li>Gradatul se autentifică.</li>
                    <li>Navighează la secțiunea "Studenți".</li>
                    <li>Poate adăuga un student nou manual, completând detaliile acestuia (nume, grad, pluton, etc.).</li>
                    <li>Poate importa studenți în masă folosind un format text specific.</li>
                    <li>Poate edita sau șterge studenții existenți din plutonul său.</li>
                </ol>
            </li>
            <li><strong>Gestionarea Învoirilor (Gradat):</strong>
                <ol>
                    <li>Gradatul selectează tipul de învoire (Permisie, Zilnică, Weekend).</li>
                    <li>Completează formularul specific pentru studentul selectat, datele, orele și alte detalii.</li>
                    <li>Sistemul verifică existența conflictelor cu alte învoiri sau servicii.</li>
                    <li>Învoirea este salvată și devine vizibilă în liste și rapoarte.</li>
                    <li>Gradatul poate anula sau șterge învoirile existente.</li>
                    <li>Pentru permisii și învoiri de weekend, există opțiuni de import în masă din text și export în format Word.</li>
                </ol>
            </li>
            <li><strong>Asignarea Serviciilor (Gradat):</strong>
                <ol>
                    <li>Gradatul accesează secțiunea "Servicii".</li>
                    <li>Poate asigna un serviciu unui student individual sau poate folosi interfața de asignare multiplă pentru un student.</li>
                    <li>Selectează tipul de serviciu, data, orele de început/sfârșit și note (dacă este cazul).</li>
                    <li>Sistemul verifică conflictele cu învoiri sau alte servicii.</li>
                </ol>
            </li>
            <li><strong>Managementul Anunțurilor (Admin):</strong>
                <ol>
                    <li>Administratorul accesează secțiunea "Management Anunțuri".</li>
                    <li>Poate crea anunțuri noi cu titlu, conținut, culoare de status, și opțiuni de fixare/vizibilitate.</li>
                    <li>Poate edita sau șterge anunțurile existente.</li>
                    <li>Anunțurile vizibile sunt afișate pe o pagină publică.</li>
                </ol>
            </li>
            <li><strong>Generarea Rapoartelor (Comandanți/Admin):</strong>
                <ol>
                    <li>Comandanții de companie/batalion accesează panoul lor de control.</li>
                    <li>Au opțiuni pentru a genera rapoarte de prezență (text) și rapoarte de învoiri/permisii (Word) pentru unitatea lor.</li>
                    <li>Administratorul poate genera rapoarte Word la nivel de sistem și exporturi text.</li>
                </ol>
            </li>
        </ul>
    </section>

    <section id="reporting">
        <h2>9. Raportare</h2>
        <p>Aplicația oferă diverse funcționalități de raportare:</p>
        <ul>
            <li><strong>Rapoarte de Prezență (Text):</strong>
                <ul>
                    <li>Disponibile pentru Comandanții de Companie și Batalion.</li>
                    <li>Generează o situație a prezenței (efectiv control, prezenți, absenți, detalii) pentru unitatea respectivă, la un moment standard de apel (ex: apel de seară) sau la un moment custom.</li>
                    <li>Accesibile din panourile de control ale comandanților și printr-o secțiune dedicată "Raport Prezență".</li>
                </ul>
            </li>
            <li><strong>Exporturi Word (.docx):</strong>
                <ul>
                    <li><strong>Permisii:</strong> Gradat, Comandant Companie, Comandant Batalion, Admin. Listează permisiile active/viitoare.</li>
                    <li><strong>Învoiri Weekend:</strong> Gradat, Comandant Companie, Comandant Batalion, Admin. Listează învoirile de weekend active/viitoare.</li>
                    <li>Formate standardizate, cu antet și tabel cu detalii.</li>
                </ul>
            </li>
            <li><strong>Exporturi Text (.txt) (Admin):</strong>
                <ul>
                    <li><strong>Studenți:</strong> Listă completă a studenților cu toate detaliile lor.</li>
                    <li><strong>Permisii:</strong> Listă completă a permisiilor, formatată pentru a fi compatibilă cu importul bulk.</li>
                    <li><strong>Învoiri (Zilnice și Weekend):</strong> Listă combinată a învoirilor, formatată pentru a fi compatibilă cu importurile bulk.</li>
                </ul>
            </li>
            <li><strong>Rapoarte pe Dashboard-uri:</strong>
                <ul>
                    <li>Panourile de control pentru Gradat, Comandant Companie și Comandant Batalion afișează diverse statistici și situații sumare relevante pentru rolul și unitatea lor.</li>
                </ul>
            </li>
             <li><strong>Istoric Învoiri (Gradat):</strong>
                <ul>
                    <li>Permite gradatului să vizualizeze un istoric al tuturor tipurilor de învoiri (zilnice, weekend) pentru studenții din plutonul său, cu opțiuni de filtrare pe diverse perioade de timp (ieri, ultimele 7 zile, custom).</li>
                </ul>
            </li>
        </ul>
    </section>

    <section id="bulk-operations">
        <h2>10. Operațiuni în Masă</h2>
        <p>Pentru a facilita introducerea rapidă a datelor, aplicația suportă următoarele operațiuni de import în masă din text (disponibile pentru rolul <code>gradat</code>):</p>
        <ul>
            <li><strong>Import Studenți:</strong>
                <ul>
                    <li>Format: <code>Grad Nume Prenume Gen Pluton Companie Batalion</code> pe fiecare linie.</li>
                    <li>Exemplu: <code>Sd Popescu Ion M 1 1 1</code></li>
                    <li>Accesibil din pagina "Listă Studenți".</li>
                </ul>
            </li>
            <li><strong>Import Permisii (din pagină dedicată <code>/gradat/import/permissions</code>):</strong>
                <ul>
                    <li>Format per intrare (separate prin linie goală):
                        <ol>
                            <li>Linia 1: Nume Student (ex: <code>Sd Popescu Ion</code> sau <code>M.m.IV Renț Francisc</code>)</li>
                            <li>Linia 2: Interval Datetime (ex: <code>DD.MM.YYYY HH:MM - DD.MM.YYYY HH:MM</code> sau <code>DD.MM.YYYY HH:MM - HH:MM</code> dacă e în aceeași zi)</li>
                            <li>Linia 3: Destinația</li>
                            <li>Linia 4 (Opțional): Mijloc de Transport</li>
                            <li>Linia 5 (Opțional): Motiv / Nr. Auto</li>
                        </ol>
                    </li>
                    <li>Sistemul încearcă să identifice studentul pe baza numelui și gradului (folosind <code>unidecode</code> și potriviri parțiale).</li>
                </ul>
            </li>
            <li><strong>Import Învoiri Zilnice (din modalul de pe pagina "Listă Învoiri Zilnice"):</strong>
                <ul>
                    <li>Format: O listă de nume studenți, fiecare pe o linie nouă. Se aplică o dată comună și un interval orar implicit (15:00-19:00) sau specificat în linie (ex: <code>Popescu Ion Sd 16:00-18:00</code>).</li>
                    <li>Data de aplicare se selectează din formular.</li>
                    <li>Permis doar pentru zilele Luni-Joi.</li>
                </ul>
            </li>
            <li><strong>Import Învoiri Weekend (din pagină dedicată <code>/gradat/import/weekend_leaves</code>):</strong>
                <ul>
                    <li>Format per linie: <code>NumeStudent Grad, DD.MM.YYYY HH:MM-HH:MM, [DD.MM.YYYY HH:MM-HH:MM, ...] [, biserica]</code></li>
                    <li>Exemplu: <code>Sd Popescu Ion, 01.03.2024 14:00-22:00, 02.03.2024 08:00-22:00, biserica</code></li>
                    <li>Permite specificarea mai multor intervale (Vineri, Sâmbătă, Duminică) pentru același student pe o singură linie.</li>
                    <li>Cuvântul cheie "biserica" la final marchează prezența la biserică Duminica (dacă Duminica este selectată ca zi de învoire).</li>
                </ul>
            </li>
            <li><strong>Adăugare Rapidă Învoiri Weekend (Bulk Add):</strong>
                <ul>
                    <li>Interfață în <code>/gradat/weekend_leave/bulk_add</code>.</li>
                    <li>Permite selectarea mai multor studenți dintr-o listă.</li>
                    <li>Se alege o dată de Vineri comună pentru weekend.</li>
                    <li>Se selectează zilele din weekend (V, S, D) și se introduc intervalele orare comune pentru TOȚI studenții selectați pentru acele zile.</li>
                    <li>Se poate adăuga un motiv comun.</li>
                </ul>
            </li>
            <li><strong>Adăugare Rapidă Permisii (Bulk Add):</strong>
                <ul>
                    <li>Interfață în <code>/gradat/permission/bulk_add</code>.</li>
                    <li>Permite selectarea mai multor studenți.</li>
                    <li>Se introduc un interval datetime comun, destinație, mod de transport și motiv pentru TOȚI studenții selectați.</li>
                </ul>
            </li>
        </ul>
        <p>Toate operațiunile de import și adăugare în masă includ validări și verificări de conflicte pentru a minimiza erorile.</p>
    </section>

    <section id="announcements">
        <h2>11. Anunțuri</h2>
        <p>Funcționalitatea de anunțuri (<code>UpdateTopic</code>) este gestionată de Administratori:</p>
        <ul>
            <li><strong>Creare/Editare:</strong> Administratorii pot crea și modifica anunțuri, specificând un titlu, conținut (HTML permis), o culoare de status (opțional, pentru stilizare), și dacă anunțul este fixat (pinned) sau vizibil.</li>
            <li><strong>Vizibilitate:</strong> Anunțurile pot fi marcate ca vizibile sau ascunse. Doar cele vizibile apar pe pagina publică de anunțuri.</li>
            <li><strong>Fixare (Pinning):</strong> Anunțurile fixate apar primele în lista de anunțuri.</li>
            <li><strong>Pagină Publică:</strong> Ruta <code>/updates</code> afișează toate anunțurile vizibile, sortate întâi după statusul de fixare și apoi după data ultimei actualizări (descendent).</li>
        </ul>
    </section>

    <section id="action-logging">
        <h2>12. Jurnalizare Acțiuni</h2>
        <p>Aplicația include un sistem de jurnalizare (<code>ActionLog</code>) care înregistrează majoritatea acțiunilor importante efectuate de utilizatori sau de sistem. Acest jurnal este util pentru audit și depanare.</p>
        <ul>
            <li><strong>Acțiuni Jurnalizate (Exemple):</strong>
                <ul>
                    <li>Autentificări reușite și eșuate (user, admin).</li>
                    <li>Deconectări.</li>
                    <li>Setarea/Resetarea codurilor personale/unice.</li>
                    <li>Crearea, modificarea, ștergerea înregistrărilor principale (Studenți, Permisii, Învoiri, Servicii, Utilizatori, Anunțuri, Activități de voluntariat).</li>
                    <li>Operațiuni bulk.</li>
                </ul>
            </li>
            <li><strong>Detalii Înregistrate:</strong>
                <ul>
                    <li>Utilizatorul care a efectuat acțiunea (dacă este cazul).</li>
                    <li>Timestamp-ul acțiunii.</li>
                    <li>Tipul acțiunii (ex: <code>CREATE_STUDENT</code>, <code>USER_LOGIN_SUCCESS</code>).</li>
                    <li>Modelul și ID-ul țintă (dacă acțiunea vizează o înregistrare specifică).</li>
                    <li>Detalii despre starea înregistrării înainte și după modificare (serializate ca JSON, pentru acțiuni de tip UPDATE).</li>
                    <li>O descriere generală a acțiunii (poate include IP-ul pentru login-uri sau un sumar).</li>
                </ul>
            </li>
            <li><strong>Acces:</strong> Administratorii au acces la o interfață de vizualizare a jurnalului de acțiuni (<code>/admin/action_logs</code>). Comandanții de companie/batalion au acces la un jurnal filtrat pentru unitățile lor.</li>
        </ul>
    </section>

    <section id="timezone">
        <h2>13. Fus Orar</h2>
        <p>Toate operațiunile legate de dată și oră sunt gestionate luând în considerare fusul orar <strong>Europe/Bucharest</strong>. Acest lucru este asigurat prin utilizarea bibliotecii <code>pytz</code>.</p>
        <ul>
            <li>Datele și orele introduse de utilizatori în formulare sunt considerate a fi în ora locală (Europe/Bucharest).</li>
            <li>La afișare, datele și orele sunt formatate corespunzător pentru acest fus orar, folosind filtre Jinja custom (<code>localdatetime</code>, <code>localtime</code>, <code>localdate</code>).</li>
            <li>Timestamp-urile pentru jurnalul de acțiuni (<code>ActionLog.timestamp</code>) și pentru crearea/actualizarea anunțurilor (<code>UpdateTopic.created_at</code>, <code>UpdateTopic.updated_at</code>) sunt stocate în UTC (<code>datetime.utcnow</code>) și convertite la fusul orar local la afișare.</li>
            <li>Pentru calculele de activitate/proximitate (ex: <code>is_active</code>, <code>is_upcoming</code>), se folosește <code>get_localized_now()</code> care returnează ora curentă conștientă de fusul orar Europe/Bucharest.</li>
        </ul>
    </section>

    <section id="notes">
        <h2>14. Note Dezvoltare</h2>
        <ul>
            <li><strong>Structură Monolitică:</strong> Majoritatea logicii backend (rute, modele, funcții helper) este concentrată în fișierul principal <code>app.py</code>. Pentru proiecte mai mari, o structură modulară (ex: Flask Blueprints) ar fi mai indicată.</li>
            <li><strong>Variabile de Mediu:</strong> Pentru o securitate sporită în producție, <code>SECRET_KEY</code> ar trebui setată ca variabilă de mediu și nu hardcodată sau lăsată pe valoarea de fallback.</li>
            <li><strong>Managementul Erorilor:</strong> Există mecanisme de flash messages pentru feedback către utilizator. Jurnalizarea erorilor se face parțial prin <code>app.logger</code> pentru anumite cazuri critice.</li>
            <li><strong>Interfață Utilizator (UI):</strong> Construită cu Bootstrap 5, oferind un design responsiv. Conține și un comutator pentru temă întunecată/luminoasă (dark/light mode) gestionat prin JavaScript și localStorage.</li>
        </ul>
    </section>

</div>
</body>
</html>
