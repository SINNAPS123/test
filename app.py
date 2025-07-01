from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import os
import secrets 
from datetime import datetime, date, time, timedelta 
from sqlalchemy import func, or_
import re 
from unidecode import unidecode

# Inițializare aplicație Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login' # Changed 'login' to 'admin_login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Te rugăm să te autentifici pentru a accesa această pagină."

SERVICE_TYPES = ["GSS", "SVM", "Planton 1", "Planton 2", "Planton 3", "Intervenție", "Altul"]
GENDERS = ["Nespecificat", "M", "F"]
KNOWN_RANK_PATTERNS = [ 
    re.compile(r"^(Mm V)\s+", re.IGNORECASE), re.compile(r"^(Sd cap)\s+", re.IGNORECASE),
    re.compile(r"^(Sg Maj)\s+", re.IGNORECASE), re.compile(r"^(Mm IV)\s+", re.IGNORECASE),
    re.compile(r"^(Sdt\.?)\s+", re.IGNORECASE), re.compile(r"^(Sd\.?)\s+", re.IGNORECASE),
    re.compile(r"^(Cap\.?)\s+", re.IGNORECASE), re.compile(r"^(Sg\.?)\s+", re.IGNORECASE),
    re.compile(r"^(Frt\.?)\s+", re.IGNORECASE), re.compile(r"^(Plt\.? Adj\.?)\s+", re.IGNORECASE), 
    re.compile(r"^(Plt\.? Maj\.?)\s+", re.IGNORECASE), re.compile(r"^(Plt\.?)\s+", re.IGNORECASE),
]
MAX_GRADATI_ACTIVI = 14

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(50), nullable=False)
    unique_code = db.Column(db.String(100), unique=True, nullable=True)
    personal_code_hash = db.Column(db.String(256), nullable=True)
    is_first_login = db.Column(db.Boolean, default=True)
    # Relație către SpecialGradedUser
    special_graded_status = db.relationship('SpecialGradedUser', backref='user', uselist=False, cascade="all, delete-orphan")

    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password) if self.password_hash else False
    def set_personal_code(self, code): self.personal_code_hash = bcrypt.hashpw(code.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'); self.is_first_login = False
    def check_personal_code(self, code): return bcrypt.checkpw(code.encode('utf-8'), self.personal_code_hash.encode('utf-8')) if self.personal_code_hash else False
    def can_login_with_personal_code(self): return self.role != 'admin' and self.personal_code_hash is not None
    def __repr__(self): return f'<User {self.username} ({self.role})>'

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nume = db.Column(db.String(100), nullable=False)
    prenume = db.Column(db.String(100), nullable=False)
    grad_militar = db.Column(db.String(50), nullable=False)
    id_unic_student = db.Column(db.String(50), unique=True, nullable=True)
    pluton = db.Column(db.String(50), nullable=False) 
    companie = db.Column(db.String(50), nullable=False) 
    batalion = db.Column(db.String(50), nullable=False) 
    gender = db.Column(db.String(10), default='Nespecificat', nullable=False) 
    volunteer_points = db.Column(db.Integer, default=0, nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('students_created', lazy=True))
    # Câmpurile este_gradat_activ și pluton_gradat_la au fost eliminate

    def __repr__(self): 
        user_obj = getattr(self, 'creator', None) # User object (creator of student record)
        sgs_info = ""
        if user_obj and user_obj.special_graded_status and user_obj.special_graded_status.is_active:
            sgs_info = f" (SGS Activ la: {user_obj.special_graded_status.assigned_platoon_info or 'N/A'})"
        return f'<Student {self.grad_militar} {self.nume} {self.prenume} - Pl.{self.pluton}{sgs_info}>'

# Model nou pentru Gradați Speciali
class SpecialGradedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    # Stochează informații despre unde își exercită atribuțiile (ex: "Plutonul 1 / Compania 1", "Comandant Compania 2", "Comandant Batalion 1")
    assigned_platoon_info = db.Column(db.String(100), nullable=True) 
    # user = definit prin backref din User.special_graded_status

    def __repr__(self):
        return f'<SpecialGradedUser UserID: {self.user_id} Active: {self.is_active} At: {self.assigned_platoon_info}>'

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='CASCADE'), nullable=False)
    start_datetime = db.Column(db.DateTime, nullable=False)
    end_datetime = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='Aprobată', nullable=False)
    student = db.relationship('Student', backref=db.backref('permissions', lazy=True, cascade="all, delete-orphan"))
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('permissions_created', lazy=True))
    @property
    def is_active(self): now = datetime.now(); return self.start_datetime <= now <= self.end_datetime and self.status == 'Aprobată'
    @property
    def is_upcoming(self): now = datetime.now(); return self.start_datetime > now and self.status == 'Aprobată'
    @property
    def is_past(self): now = datetime.now(); return self.end_datetime < now or self.status == 'Anulată'

class DailyLeave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='CASCADE'), nullable=False)
    leave_date = db.Column(db.Date, nullable=False) 
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='Aprobată', nullable=False)
    student = db.relationship('Student', backref=db.backref('daily_leaves', lazy=True, cascade="all, delete-orphan"))
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('daily_leaves_created', lazy=True))
    @property
    def start_datetime(self): return datetime.combine(self.leave_date, self.start_time)
    @property
    def end_datetime(self):
        effective_end_date = self.leave_date
        if self.end_time < self.start_time: effective_end_date += timedelta(days=1)
        return datetime.combine(effective_end_date, self.end_time)
    @property
    def is_active(self): now = datetime.now(); return self.start_datetime <= now <= self.end_datetime and self.status == 'Aprobată'
    @property
    def is_upcoming(self): now = datetime.now(); return self.start_datetime > now and self.status == 'Aprobată'
    @property
    def is_past(self): now = datetime.now(); return self.end_datetime < now or self.status == 'Anulată'
    @property
    def leave_type_display(self):
        in_program_start, in_program_end = time(7,0), time(14,20)
        out_program_evening_start, out_program_morning_end = time(22,0), time(7,0)
        if in_program_start <= self.start_time <= in_program_end and in_program_start <= self.end_time <= in_program_end and self.start_time < self.end_time: return "În program"
        elif (self.start_time >= out_program_evening_start or self.start_time < out_program_morning_end) and \
             (self.end_time <= out_program_morning_end or self.end_time > self.start_time or self.start_time > self.end_time) and \
             not (in_program_start <= self.start_time <= in_program_end and in_program_start <= self.end_time <= in_program_end):
            return "Afară program"
        return "Nespecificat"

class WeekendLeave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='CASCADE'), nullable=False)
    weekend_start_date = db.Column(db.Date, nullable=False)
    day1_selected = db.Column(db.String(10), nullable=True) 
    day1_date = db.Column(db.Date, nullable=True)
    day1_start_time = db.Column(db.Time, nullable=True)
    day1_end_time = db.Column(db.Time, nullable=True)
    day2_selected = db.Column(db.String(10), nullable=True)
    day2_date = db.Column(db.Date, nullable=True)
    day2_start_time = db.Column(db.Time, nullable=True)
    day2_end_time = db.Column(db.Time, nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='Aprobată', nullable=False)
    student = db.relationship('Student', backref=db.backref('weekend_leaves', lazy=True, cascade="all, delete-orphan"))
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('weekend_leaves_created', lazy=True))
    def get_intervals(self):
        intervals = []
        for d_date, s_time, e_time, d_name in [(self.day1_date, self.day1_start_time, self.day1_end_time, self.day1_selected), (self.day2_date, self.day2_start_time, self.day2_end_time, self.day2_selected)]:
            if d_date and s_time and e_time:
                s_dt, e_dt = datetime.combine(d_date, s_time), datetime.combine(d_date, e_time)
                if e_dt < s_dt: e_dt += timedelta(days=1)
                intervals.append({"day_name": d_name, "start": s_dt, "end": e_dt})
        return sorted(intervals, key=lambda x: x['start'])
    @property
    def is_overall_active_or_upcoming(self):
        if self.status != 'Aprobată': return False; now = datetime.now() 
        return any(interval["end"] >= now for interval in self.get_intervals())
    @property
    def is_any_interval_active_now(self):
        if self.status != 'Aprobată': return False; now = datetime.now() 
        return any(interval["start"] <= now <= interval["end"] for interval in self.get_intervals())
    @property
    def is_overall_past(self): now = datetime.now(); return True if self.status == 'Anulată' else not self.is_overall_active_or_upcoming
    @property
    def display_days_and_times(self): return "; ".join([f"{i['day_name']} ({i['start'].strftime('%d.%m')}) {i['start'].strftime('%H:%M')}-{i['end'].strftime('%H:%M')}" for i in self.get_intervals()]) or "Nespecificat"

class VolunteerActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    activity_date = db.Column(db.Date, nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('volunteer_activities_created', lazy=True))
    participants = db.relationship('ActivityParticipant', backref='activity', lazy='dynamic', cascade="all, delete-orphan")

class ActivityParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('volunteer_activity.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='CASCADE'), nullable=False)
    points_awarded = db.Column(db.Integer, default=0)
    student = db.relationship('Student', backref=db.backref('participations', lazy=True, cascade="all, delete-orphan"))

class ServiceAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='CASCADE'), nullable=False)
    service_type = db.Column(db.String(100), nullable=False) 
    service_date = db.Column(db.Date, nullable=False) 
    start_datetime = db.Column(db.DateTime, nullable=False)
    end_datetime = db.Column(db.DateTime, nullable=False)
    participates_in_roll_call = db.Column(db.Boolean, default=True) 
    notes = db.Column(db.Text, nullable=True)
    student = db.relationship('Student', backref=db.backref('service_assignments', lazy=True, cascade="all, delete-orphan"))
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('service_assignments_created', lazy=True))
    @property
    def is_active(self): now = datetime.now(); return self.start_datetime <= now <= self.end_datetime
    @property
    def is_upcoming(self): now = datetime.now(); return self.start_datetime > now
    @property
    def is_past(self): now = datetime.now(); return self.end_datetime < now

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin', is_first_login=False); admin.set_password('admin123')
            db.session.add(admin); db.session.commit(); print("Admin user created.")
        else: print("Admin user already exists.")
        print("DB initialized.")

def get_next_friday(start_date=None):
    d = start_date if start_date else date.today();
    while d.weekday() != 4: d += timedelta(days=1)
    return d

def validate_daily_leave_times(start_time_obj, end_time_obj, leave_date_obj):
    if leave_date_obj.weekday() > 3: return False, "Învoirile zilnice sunt permise doar de Luni până Joi."
    if start_time_obj == end_time_obj: return False, "Ora de început și de sfârșit nu pot fi identice."
    return True, "Valid"

def get_student_status(student_obj_or_user_obj, datetime_check):
    # Determină dacă obiectul pasat este Student sau User
    # și obține user_id și student_id (dacă e cazul)
    user_id_to_check = None
    student_id_to_check = None
    is_student_object = isinstance(student_obj_or_user_obj, Student)

    if is_student_object:
        student_id_to_check = student_obj_or_user_obj.id
        if student_obj_or_user_obj.creator: # student.creator este obiectul User
             user_id_to_check = student_obj_or_user_obj.creator.id
    elif isinstance(student_obj_or_user_obj, User):
        user_id_to_check = student_obj_or_user_obj.id
        # Încercăm să găsim un student asociat acestui user, dacă e relevant (ex: user e gradat)
        # Dar pentru statusul general, ne bazăm pe User pentru SpecialGradedUser
    else: # Tip necunoscut
        return {"status_code": "unknown", "reason": "Tip obiect necunoscut", "until": None, "details": "Eroare internă"}

    # Prioritățile rămân aceleași, dar verificarea SpecialGradedUser se face pe user_id_to_check
    # Verificările pentru Service, Permission, DailyLeave, WeekendLeave se fac pe student_id_to_check (dacă există)

    if student_id_to_check: # Aceste statusuri sunt specifice studenților
        active_service = ServiceAssignment.query.filter(ServiceAssignment.student_id == student_id_to_check, ServiceAssignment.start_datetime <= datetime_check, ServiceAssignment.end_datetime >= datetime_check).order_by(ServiceAssignment.start_datetime).first()
        if active_service: return {"status_code": "on_duty", "reason": f"Serviciu ({active_service.service_type})", "until": active_service.end_datetime, "details": f"Serviciu: {active_service.service_type}", "object": active_service, "participates_in_roll_call": active_service.participates_in_roll_call }
        
        active_permission = Permission.query.filter(Permission.student_id == student_id_to_check, Permission.status == 'Aprobată', Permission.start_datetime <= datetime_check, Permission.end_datetime >= datetime_check).order_by(Permission.start_datetime).first()
        if active_permission: return {"status_code": "absent_permission", "reason": "Permisie", "until": active_permission.end_datetime, "details": "Permisie", "object": active_permission}
        
        weekend_leaves = WeekendLeave.query.filter(WeekendLeave.student_id == student_id_to_check, WeekendLeave.status == 'Aprobată').all()
        for wl in weekend_leaves:
            for interval in wl.get_intervals():
                if interval['start'] <= datetime_check <= interval['end']: return {"status_code": "absent_weekend_leave", "reason": f"Învoire Weekend ({interval['day_name']})", "until": interval['end'], "details": f"Învoire Weekend: {interval['day_name']}", "object": wl}
        
        daily_leaves = DailyLeave.query.filter(DailyLeave.student_id == student_id_to_check, DailyLeave.status == 'Aprobată').all()
        for dl in daily_leaves:
            if dl.start_datetime <= datetime_check <= dl.end_datetime: return {"status_code": "absent_daily_leave", "reason": f"Învoire Zilnică ({dl.leave_type_display})", "until": dl.end_datetime, "details": f"Învoire Zilnică: {dl.leave_type_display}", "object": dl}

    # Verifică dacă utilizatorul (fie el student.creator sau direct User) este un Gradat Special Activ
    if user_id_to_check:
        sgs = SpecialGradedUser.query.filter_by(user_id=user_id_to_check, is_active=True).first()
        if sgs:
            user_obj_for_sgs = User.query.get(user_id_to_check) # Obținem obiectul User pentru username
            username_sgs = user_obj_for_sgs.username if user_obj_for_sgs else "N/A"
            reason_sgs = f"Gradat Special ({username_sgs})"
            if sgs.assigned_platoon_info:
                reason_sgs += f" - {sgs.assigned_platoon_info}"
            else:
                reason_sgs += " - Activitate Comandă/Gradat"
            
            return {
                "status_code": "special_graded_duty",
                "reason": reason_sgs,
                "until": None, 
                "details": reason_sgs,
                "object": sgs, 
                "assigned_platoon_info": sgs.assigned_platoon_info,
                # Dacă este un student, putem adăuga plutonul lui de bază
                "pluton_baza_student": student_obj_or_user_obj.pluton if is_student_object else None 
            }
            
    # Dacă nu e niciunul de mai sus și e un student, e prezent în formația lui de bază
    if is_student_object:
        return {"status_code": "present", "reason": "Prezent", "until": None, "details": "Prezent", "object": student_obj_or_user_obj}
    
    # Dacă e un User (ex: admin, comandant ne-gradat special) și nu are alt status, nu avem un status de prezență definit aici
    # Acest caz ar trebui gestionat de funcțiile care apelează get_student_status pentru Useri non-student.
    # Sau, returnăm un status neutru.
    return {"status_code": "undefined_for_user_role", "reason": "Status nedefinit pentru acest rol de utilizator fără atribuții de student/gradat special", "until": None, "details": "N/A"}


def parse_student_line(line_text):
    original_line = line_text.strip(); parts = original_line.split()
    grad, nume, prenume, start_hour_interval_str, end_hour_interval_str, end_hour_individual_str = None, None, None, None, None, None
    if not parts: return {'grad': grad, 'nume': nume, 'prenume': prenume, 'start_hour_interval_str': start_hour_interval_str, 'end_hour_interval_str': end_hour_interval_str, 'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}
    time_interval_match = re.match(r"(\d{1,2}:\d{2})-(\d{1,2}:\d{2})", parts[0])
    if time_interval_match:
        try:
            start_h_str, end_h_str = time_interval_match.group(1), time_interval_match.group(2)
            datetime.strptime(start_h_str, '%H:%M'); datetime.strptime(end_h_str, '%H:%M')   
            start_hour_interval_str, end_hour_interval_str = start_h_str, end_h_str; parts = parts[1:] 
        except ValueError: pass 
    if not parts: return {'grad': grad, 'nume': nume, 'prenume': prenume, 'start_hour_interval_str': start_hour_interval_str, 'end_hour_interval_str': end_hour_interval_str, 'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}
    if not start_hour_interval_str and parts: 
        last_part, time_extracted_individual = parts[-1], False
        if ':' in last_part and len(last_part.split(':')[0]) <= 2 and len(last_part.split(':')[-1]) == 2:
            try: datetime.strptime(last_part, '%H:%M'); end_hour_individual_str = last_part; parts = parts[:-1]; time_extracted_individual = True
            except ValueError: pass
        elif len(last_part) == 4 and last_part.isdigit() and not time_extracted_individual: 
            try:
                h, m = last_part[:2], last_part[2:]; datetime.strptime(f"{h}:{m}", '%H:%M'); end_hour_individual_str = f"{h}:{m}"
                parts = parts[:-1]; time_extracted_individual = True
            except ValueError: pass
    if not parts: return {'grad': grad, 'nume': nume, 'prenume': prenume, 'start_hour_interval_str': start_hour_interval_str, 'end_hour_interval_str': end_hour_interval_str, 'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}
    grad_parts_count, temp_grad_candidate = 0, ""
    for i, part in enumerate(parts):
        test_text_for_grad = (temp_grad_candidate + " " + part).strip() if temp_grad_candidate else part
        found_match_for_test_text = False
        for pattern in KNOWN_RANK_PATTERNS:
            if pattern.match(test_text_for_grad + " ") or pattern.fullmatch(test_text_for_grad): found_match_for_test_text = True; break
        if found_match_for_test_text: temp_grad_candidate, grad, grad_parts_count = test_text_for_grad, temp_grad_candidate, i + 1
        else:
            if grad: break
            if not grad: break 
    name_parts_start_index = grad_parts_count; remaining_parts = parts[name_parts_start_index:] if parts else [] 
    if len(remaining_parts) >= 1: nume = remaining_parts[0]
    if len(remaining_parts) >= 2: prenume = " ".join(remaining_parts[1:])
    if not grad and nume and ' ' in nume and not prenume:
        name_parts_split = nume.split(' ', 1); nume = name_parts_split[0]; prenume = name_parts_split[1] if len(name_parts_split) > 1 else None
    return {'grad': grad, 'nume': nume, 'prenume': prenume, 'start_hour_interval_str': start_hour_interval_str, 'end_hour_interval_str': end_hour_interval_str, 'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}

# ... (restul fișierului app.py va fi similar cu versiunea anterioară, dar cu referințe la `student.este_gradat_activ` eliminate/înlocuite)
# ... și funcțiile de dashboard actualizate pentru a folosi noua logică din get_student_status și SpecialGradedUser.

# --- Rute Comune ---
@app.route('/')
def home(): return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin': return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'gradat': return redirect(url_for('gradat_dashboard'))
    elif current_user.role == 'comandant_companie': return redirect(url_for('company_commander_dashboard'))
    elif current_user.role == 'comandant_batalion': return redirect(url_for('battalion_commander_dashboard'))
    return render_template('dashboard.html', name=current_user.username) 

@app.route('/logout')
@login_required
def logout(): logout_user(); flash('Ai fost deconectat.', 'success'); return redirect(url_for('home'))

# --- Autentificare Admin ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.role == 'admin': return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username'), role='admin').first()
        if user and user.check_password(request.form.get('password')):
            login_user(user); flash('Autentificare admin reușită!', 'success'); return redirect(url_for('admin_dashboard'))
        else: flash('Autentificare eșuată.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    # Numărul de gradați activi se va lua acum din tabela SpecialGradedUser
    active_special_graded_count = SpecialGradedUser.query.filter_by(is_active=True).count()
    return render_template('admin_dashboard.html', 
                           users=User.query.filter(User.role != 'admin').all(),
                           active_special_graded_count=active_special_graded_count, # Actualizat
                           max_gradati_activi=MAX_GRADATI_ACTIVI)


@app.route('/admin/create_user', methods=['POST'])
@login_required
def admin_create_user():
    if current_user.role != 'admin': return redirect(url_for('home'))
    username, role = request.form.get('username'), request.form.get('role')
    if not username or not role: flash('Username și rol sunt obligatorii.', 'warning'); return redirect(url_for('admin_dashboard'))
    if User.query.filter_by(username=username).first(): flash(f'Utilizatorul "{username}" există deja.', 'warning'); return redirect(url_for('admin_dashboard'))
    new_user = User(username=username, role=role, unique_code=secrets.token_hex(8), is_first_login=True)
    db.session.add(new_user); db.session.commit()
    flash(f'Utilizatorul "{username}" ({role}) creat cu codul unic: {new_user.unique_code}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_user_code/<int:user_id>', methods=['POST'])
@login_required
def admin_reset_user_code(user_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    user_to_reset = User.query.get_or_404(user_id)
    if user_to_reset.role == 'admin':
        flash('Codul adminului nu poate fi resetat din acest panou.', 'warning')
        return redirect(url_for('admin_dashboard'))

    user_to_reset.unique_code = secrets.token_hex(8)
    user_to_reset.personal_code_hash = None  # Șterge codul personal vechi
    user_to_reset.is_first_login = True    # Forțează setarea unui nou cod personal la login
    db.session.commit()

    flash(f'Codul pentru utilizatorul {user_to_reset.username} a fost resetat. Noul cod unic este: {user_to_reset.unique_code}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash('Nu vă puteți șterge propriul cont de admin.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Verifică dacă utilizatorul este gradat și are studenți asociați
    # Această verificare este importantă din cauza cascade delete pe student și datele asociate
    if user_to_delete.role == 'gradat':
        students_count = Student.query.filter_by(created_by_user_id=user_to_delete.id).count()
        if students_count > 0:
            flash(f'ATENȚIE: Utilizatorul {user_to_delete.username} este gradat și are {students_count} studenți asociați. Ștergerea va elimina și acești studenți și toate datele lor (permisii, învoiri, servicii).', 'warning')
            # Aici s-ar putea adăuga o confirmare suplimentară dacă se dorește, dar onsubmit="confirm(...)" din HTML face deja asta.

    try:
        # Ștergerea utilizatorului va șterge în cascadă și intrarea din SpecialGradedUser (dacă există)
        # și studenții creați de el (dacă e gradat), și datele asociate studenților.
        username_deleted = user_to_delete.username
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'Utilizatorul {username_deleted} și toate datele asociate (dacă este cazul) au fost șterse definitiv.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la ștergerea utilizatorului {user_to_delete.username}: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))

# ... (restul rutelor admin, user, gradat, student management vor fi actualizate pentru a elimina referințele la student.este_gradat_activ)
# ... și pentru a integra logica SpecialGradedUser unde e necesar.
# ... De exemplu, list_students pentru admin nu va mai afișa coloana "Gradat Activ" din Student, ci va trebui să facă un join sau o verificare separată cu SpecialGradedUser.

# --- Rută nouă pentru managementul Gradaților Speciali ---
@app.route('/admin/special_graded_users', methods=['GET', 'POST'])
@login_required
def admin_manage_special_graded():
    if current_user.role != 'admin':
        flash("Acces neautorizat.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        user_id = request.form.get('user_id', type=int)
        action = request.form.get('action')
        assigned_info = request.form.get(f'assigned_platoon_info_{user_id}', '').strip()

        user_to_manage = User.query.get_or_404(user_id)
        sgs_entry = SpecialGradedUser.query.filter_by(user_id=user_id).first()
        active_special_graded_count = SpecialGradedUser.query.filter_by(is_active=True).count()

        if action == 'activate':
            if active_special_graded_count >= MAX_GRADATI_ACTIVI and (not sgs_entry or not sgs_entry.is_active):
                flash(f'Nu se pot activa mai mult de {MAX_GRADATI_ACTIVI} gradați speciali.', 'warning')
            else:
                if not sgs_entry:
                    sgs_entry = SpecialGradedUser(user_id=user_id, is_active=True, assigned_platoon_info=assigned_info if assigned_info else None)
                    db.session.add(sgs_entry)
                else:
                    sgs_entry.is_active = True
                    sgs_entry.assigned_platoon_info = assigned_info if assigned_info else None
                flash(f'Utilizatorul {user_to_manage.username} a fost setat ca Gradat Special Activ.', 'success')
                db.session.commit()
        elif action == 'deactivate':
            if sgs_entry:
                sgs_entry.is_active = False
                # Opțional: sgs_entry.assigned_platoon_info = None
                flash(f'Utilizatorul {user_to_manage.username} a fost dezactivat ca Gradat Special.', 'success')
                db.session.commit()
        elif action == 'update_info': # Doar pentru actualizarea informației, fără a schimba statusul activ
            if sgs_entry:
                sgs_entry.assigned_platoon_info = assigned_info if assigned_info else None
                flash(f'Informațiile pentru Gradatul Special {user_to_manage.username} au fost actualizate.', 'success')
                db.session.commit()
            else:
                flash(f'Utilizatorul {user_to_manage.username} nu este încă în lista de Gradați Speciali. Activați-l întâi.', 'warning')
        
        return redirect(url_for('admin_manage_special_graded'))

    # GET request: Afișează lista
    # Utilizatori eligibili: toți cei care nu sunt 'student' simplu. Sau toți utilizatorii.
    # Vom lua toți utilizatorii și vom afișa statusul lor special.
    users = User.query.order_by(User.username).all()
    active_special_graded_count = SpecialGradedUser.query.filter_by(is_active=True).count()
    
    # Join pentru a obține informațiile SpecialGradedUser pentru fiecare User
    users_with_sgs_status = []
    for u in users:
        sgs = u.special_graded_status # Folosind backref
        users_with_sgs_status.append({
            'user': u,
            'sgs_is_active': sgs.is_active if sgs else False,
            'sgs_assigned_info': sgs.assigned_platoon_info if sgs else ""
        })

    return render_template('admin_manage_special_graded.html', 
                           users_with_sgs_status=users_with_sgs_status,
                           active_special_graded_count=active_special_graded_count,
                           max_gradati_activi=MAX_GRADATI_ACTIVI)


# Se elimină /admin/toggle_gradat_status/<int:student_id> deoarece managementul se face prin noua pagină.
# Se actualizează list_students pentru a nu mai afișa butoane de toggle gradat.

# --- Management Studenți ---
@app.route('/gradat/students') 
@app.route('/admin/students') 
@login_required
def list_students():
    if current_user.role == 'admin':
        page = request.args.get('page', 1, type=int)
        per_page = 25 
        query = Student.query.join(User, Student.created_by_user_id == User.id).options(db.joinedload(Student.creator).joinedload(User.special_graded_status))
        search_term = request.args.get('search', '')
        filter_batalion = request.args.get('batalion', '')
        filter_companie = request.args.get('companie', '')
        filter_pluton = request.args.get('pluton', '')
        if search_term:
            search_pattern = f"%{search_term}%"
            query = query.filter(or_(Student.nume.ilike(search_pattern), Student.prenume.ilike(search_pattern), Student.id_unic_student.ilike(search_pattern)))
        if filter_batalion: query = query.filter(Student.batalion == filter_batalion)
        if filter_companie: query = query.filter(Student.companie == filter_companie)
        if filter_pluton: query = query.filter(Student.pluton == filter_pluton)
        students_pagination = query.order_by(Student.batalion, Student.companie, Student.pluton, Student.nume, Student.prenume).paginate(page=page, per_page=per_page, error_out=False)
        batalioane = sorted([b[0] for b in db.session.query(Student.batalion).distinct().all() if b[0]])
        companii = sorted([c[0] for c in db.session.query(Student.companie).distinct().all() if c[0]])
        plutoane = sorted([p[0] for p in db.session.query(Student.pluton).distinct().all() if p[0]])
        # active_gradati_count nu mai este relevant aici în același mod, se gestionează în pagina dedicată
        return render_template('list_students.html', students_pagination=students_pagination, is_admin_view=True, batalioane=batalioane, companii=companii, plutoane=plutoane, search_term=search_term, filter_batalion=filter_batalion, filter_companie=filter_companie, filter_pluton=filter_pluton)
    elif current_user.role == 'gradat':
        students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume, Student.prenume).all()
        return render_template('list_students.html', students=students, is_admin_view=False)
    else:
        flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))

@app.route('/gradat/students/add', methods=['GET', 'POST']) 
@app.route('/admin/students/add', methods=['GET', 'POST'])  
@login_required
def add_student():
    if current_user.role not in ['admin', 'gradat']:
        flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    if request.method == 'POST':
        form = request.form
        if not all([form.get(k) for k in ['nume', 'prenume', 'grad_militar', 'pluton', 'companie', 'batalion', 'gender']]): flash('Toate câmpurile marcate cu * sunt obligatorii (inclusiv genul).', 'warning')
        elif form.get('id_unic_student') and Student.query.filter_by(id_unic_student=form.get('id_unic_student')).first(): flash(f"ID unic '{form.get('id_unic_student')}' există deja.", 'warning')
        elif form.get('gender') not in GENDERS : flash('Valoare invalidă pentru gen.', 'warning')
        else:
            # Student.creator este User-ul care a creat studentul (gradatul sau adminul)
            # created_by_user_id este ID-ul acestui User.
            s = Student(nume=form.get('nume'), prenume=form.get('prenume'), grad_militar=form.get('grad_militar'), id_unic_student=form.get('id_unic_student') or None, pluton=form.get('pluton'), companie=form.get('companie'), batalion=form.get('batalion'), gender=form.get('gender'), created_by_user_id=current_user.id)
            db.session.add(s); db.session.commit(); flash(f'Studentul {s.grad_militar} {s.nume} {s.prenume} a fost adăugat!', 'success'); return redirect(url_for('list_students'))
    return render_template('add_edit_student.html', form_title="Adăugare Student Nou", student=None, genders=GENDERS, form_data=request.form if request.method == 'POST' else None)

@app.route('/gradat/students/edit/<int:student_id>', methods=['GET', 'POST']) 
@app.route('/admin/students/edit/<int:student_id>', methods=['GET', 'POST'])  
@login_required
def edit_student(student_id):
    s_edit = Student.query.get_or_404(student_id)
    if current_user.role == 'gradat' and s_edit.created_by_user_id != current_user.id:
        flash('Acces neautorizat pentru a edita acest student.', 'danger'); return redirect(url_for('list_students'))
    elif current_user.role not in ['admin', 'gradat']:
        flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    if request.method == 'POST':
        form = request.form
        s_edit.nume, s_edit.prenume, s_edit.grad_militar, s_edit.pluton, s_edit.companie, s_edit.batalion = form.get('nume'), form.get('prenume'), form.get('grad_militar'), form.get('pluton'), form.get('companie'), form.get('batalion')
        s_edit.gender = form.get('gender') 
        new_id_unic = form.get('id_unic_student')
        # Câmpul pluton_gradat_la nu se mai editează aici, ci în pagina de management SpecialGradedUser
        if not all([s_edit.nume, s_edit.prenume, s_edit.grad_militar, s_edit.pluton, s_edit.companie, s_edit.batalion, s_edit.gender]): flash('Toate câmpurile marcate cu * sunt obligatorii (inclusiv genul).', 'warning')
        elif s_edit.gender not in GENDERS: flash('Valoare invalidă pentru gen.', 'warning')
        else:
            if new_id_unic and new_id_unic != s_edit.id_unic_student and Student.query.filter(Student.id_unic_student==new_id_unic, Student.id != s_edit.id).first(): 
                flash(f"Alt student cu ID unic '{new_id_unic}' există deja.", 'warning'); return render_template('add_edit_student.html', form_title="Editare Student", student=s_edit, genders=GENDERS, form_data=form)
            s_edit.id_unic_student = new_id_unic or None
            db.session.commit()
            flash(f'Studentul {s_edit.grad_militar} {s_edit.nume} {s_edit.prenume} a fost actualizat!', 'success')
            return redirect(url_for('list_students'))
    return render_template('add_edit_student.html', form_title="Editare Student", student=s_edit, genders=GENDERS, form_data=request.form if request.method == 'POST' else s_edit)

# ... (restul fișierului, inclusiv delete_student, process_daily_leaves_text, etc. rămâne la fel ca în versiunea anterioară)
# ... Funcțiile de dashboard (situatie_pluton, company_commander_dashboard, battalion_commander_dashboard, presence_report)
# ... vor necesita ajustări pentru a folosi corect noua logică din get_student_status cu SpecialGradedUser.

@app.route('/gradat/daily_leaves/process_text', methods=['POST'])
@login_required
def process_daily_leaves_text():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))
    form_text = request.form.get('leave_list_text')
    apply_date_str = request.form.get('apply_date')
    if not form_text or not apply_date_str:
        flash('Lista de învoiri și data aplicării sunt obligatorii.', 'warning')
        return redirect(url_for('list_daily_leaves', today_str=date.today().isoformat()))
    try:
        apply_date_obj = datetime.strptime(apply_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Format dată invalid pentru aplicare.', 'danger')
        return redirect(url_for('list_daily_leaves', today_str=date.today().isoformat()))
    if apply_date_obj.weekday() > 3: 
        flash('Învoirile din text pot fi procesate doar pentru zilele de Luni până Joi.', 'warning')
        return redirect(url_for('list_daily_leaves', today_str=apply_date_str))
    lines = form_text.strip().splitlines()
    processed_count = 0; skipped_entries = []; success_entries = []
    default_start_processing_time = time(15, 0); default_end_processing_time = time(19, 0)
    all_students_gradat = Student.query.filter_by(created_by_user_id=current_user.id).all()
    students_db_normalized = [{"original": s, "norm_nume": unidecode(s.nume.lower()), "norm_prenume": unidecode(s.prenume.lower()) if s.prenume else ""} for s in all_students_gradat]
    for line_num, line in enumerate(lines):
        original_line_text = line.strip()
        if not original_line_text: continue
        parsed_data = parse_student_line(original_line_text) 
        if not parsed_data['nume'] and not parsed_data['start_hour_interval_str']:
            skipped_entries.append(f"Linia {line_num+1} (format nume incorect sau linie goală): \"{parsed_data['original_line']}\""); continue
        student_found_original_object = None 
        if parsed_data['nume']:
            search_nume_norm = unidecode(parsed_data['nume'].lower()); search_prenume_norm = unidecode(parsed_data['prenume'].lower()) if parsed_data['prenume'] else ""
            if search_prenume_norm: 
                for s_info in students_db_normalized:
                    if (s_info["norm_nume"] == search_nume_norm and s_info["norm_prenume"] == search_prenume_norm) or \
                       (s_info["norm_nume"] == search_prenume_norm and s_info["norm_prenume"] == search_nume_norm): 
                        student_found_original_object = s_info["original"]; break
            if not student_found_original_object: 
                possible_matches_objects = []
                for s_info in students_db_normalized:
                    db_full_name_norm = f"{s_info['norm_nume']} {s_info['norm_prenume']}".strip()
                    cond1 = (s_info["norm_nume"] == search_nume_norm); cond2 = (search_prenume_norm and s_info["norm_prenume"] == search_prenume_norm)
                    cond3 = (not search_prenume_norm and search_nume_norm in db_full_name_norm) ; cond4 = (s_info["norm_nume"] == search_prenume_norm and s_info["norm_prenume"] == search_nume_norm)
                    if cond1 or cond2 or cond3 or cond4: possible_matches_objects.append(s_info["original"])
                if len(possible_matches_objects) == 1: student_found_original_object = possible_matches_objects[0]
                elif len(possible_matches_objects) > 1:
                    strict_matches = []
                    for s_obj in possible_matches_objects:
                        s_obj_norm_nume = unidecode(s_obj.nume.lower()); s_obj_norm_prenume = unidecode(s_obj.prenume.lower()) if s_obj.prenume else ""
                        if search_prenume_norm: 
                            if (s_obj_norm_nume == search_nume_norm and s_obj_norm_prenume == search_prenume_norm) or \
                               (s_obj_norm_nume == search_prenume_norm and s_obj_norm_prenume == search_nume_norm): strict_matches.append(s_obj)
                        else: 
                            if s_obj_norm_nume == search_nume_norm or s_obj_norm_prenume == search_nume_norm : strict_matches.append(s_obj)
                    if len(strict_matches) == 1: student_found_original_object = strict_matches[0]
                    else: skipped_entries.append(f"Numele '{parsed_data['nume']}{' ' + parsed_data['prenume'] if parsed_data['prenume'] else ''}' (normalizat: '{search_nume_norm}{' ' + search_prenume_norm if search_prenume_norm else ''}') este ambiguu. Găsit {len(strict_matches) if strict_matches else len(possible_matches_objects)} potriviri. (Linia: \"{original_line_text}\")"); continue
        if not student_found_original_object: 
            skipped_entries.append(f"Studentul '{parsed_data['nume']}{' ' + parsed_data['prenume'] if parsed_data['prenume'] else ''}' (normalizat: '{unidecode(parsed_data['nume'].lower())}{' ' + unidecode(parsed_data['prenume'].lower()) if parsed_data.get('prenume') else ''}') nu a fost găsit. (Linia: \"{original_line_text}\")"); continue
        student_found = student_found_original_object 
        current_start_time, current_end_time = default_start_processing_time, default_end_processing_time
        if parsed_data['start_hour_interval_str'] and parsed_data['end_hour_interval_str']:
            try: current_start_time, current_end_time = datetime.strptime(parsed_data['start_hour_interval_str'], '%H:%M').time(), datetime.strptime(parsed_data['end_hour_interval_str'], '%H:%M').time()
            except ValueError: skipped_entries.append(f"Interval orar invalid ({parsed_data['start_hour_interval_str']}-{parsed_data['end_hour_interval_str']}) pentru {student_found.nume} {student_found.prenume}. (Linia: \"{original_line_text}\")"); continue
        elif parsed_data['end_hour_individual_str']: 
            try: current_start_time, current_end_time = default_start_processing_time, datetime.strptime(parsed_data['end_hour_individual_str'], '%H:%M').time()
            except ValueError: skipped_entries.append(f"Ora de sfârșit individuală invalidă ({parsed_data['end_hour_individual_str']}) pentru {student_found.nume} {student_found.prenume}. (Linia: \"{original_line_text}\")"); continue
        is_valid_interval, interval_msg = validate_daily_leave_times(current_start_time, current_end_time, apply_date_obj)
        if not is_valid_interval: skipped_entries.append(f"Interval invalid ({current_start_time.strftime('%H:%M')}-{current_end_time.strftime('%H:%M')}) pentru {student_found.nume} {student_found.prenume}: {interval_msg}. (Linia: \"{original_line_text}\")"); continue
        leave_start_dt = datetime.combine(apply_date_obj, current_start_time); effective_end_leave_date = apply_date_obj
        if current_end_time < current_start_time : effective_end_leave_date += timedelta(days=1)
        leave_end_dt = datetime.combine(effective_end_leave_date, current_end_time)
        conflict_msg = check_leave_conflict(student_found.id, leave_start_dt, leave_end_dt, leave_type='daily_leave')
        if conflict_msg: skipped_entries.append(f"Conflict pentru {student_found.nume} {student_found.prenume}: are deja {conflict_msg}. Învoirea nu a fost adăugată. (Linia: \"{original_line_text}\")"); continue
        new_leave = DailyLeave(student_id=student_found.id, leave_date=apply_date_obj, start_time=current_start_time, end_time=current_end_time, reason="Procesat din text", created_by_user_id=current_user.id)
        db.session.add(new_leave); success_entries.append(f"{student_found.grad_militar} {student_found.nume} {student_found.prenume} ({current_start_time.strftime('%H:%M')} - {current_end_time.strftime('%H:%M')})"); processed_count += 1
    try:
        db.session.commit()
        if processed_count > 0: flash(f'{processed_count} învoiri au fost procesate și adăugate cu succes pentru data de {apply_date_obj.strftime("%d-%m-%Y")}.', 'success')
        if not processed_count and not skipped_entries: flash('Nicio linie validă de procesat în textul furnizat.', 'info')
        elif not processed_count and skipped_entries : flash('Nicio învoire nu a putut fi procesată cu succes.', 'warning')
        if skipped_entries:
            flash('Următoarele linii/studenți nu au putut fi procesate:', 'warning')
            for skipped_line in skipped_entries: flash(skipped_line, 'secondary') 
    except Exception as e: db.session.rollback(); flash(f'A apărut o eroare la salvarea învoirilor: {str(e)}', 'danger')
    return redirect(url_for('list_daily_leaves', today_str=apply_date_str))

@app.route('/gradat/services/delete/<int:assignment_id>', methods=['POST']) 
@app.route('/admin/services/delete/<int:assignment_id>', methods=['POST'])  
@login_required
def delete_service_assignment(assignment_id):
    assignment_to_delete = ServiceAssignment.query.get_or_404(assignment_id)
    student_name_for_flash = "N/A"
    if assignment_to_delete.student: student_name_for_flash = f"{assignment_to_delete.student.grad_militar} {assignment_to_delete.student.nume} {assignment_to_delete.student.prenume}"
    can_delete = False
    if current_user.role == 'admin': can_delete = True
    elif current_user.role == 'gradat' and assignment_to_delete.created_by_user_id == current_user.id: can_delete = True
    if not can_delete:
        flash('Acces neautorizat pentru a șterge acest serviciu.', 'danger')
        if current_user.role == 'gradat': return redirect(url_for('list_services'))
        else: return redirect(url_for('dashboard')) 
    try:
        service_type_flash = assignment_to_delete.service_type; service_date_flash = assignment_to_delete.service_date.strftime("%d.%m.%Y")
        db.session.delete(assignment_to_delete); db.session.commit()
        flash(f'Serviciul ({service_type_flash}) pentru {student_name_for_flash} din data de {service_date_flash} a fost șters.', 'success')
    except Exception as e: db.session.rollback(); flash(f'Eroare la ștergerea serviciului: {str(e)}', 'danger')
    if current_user.role == 'admin': return redirect(url_for('list_students')) # Sau o pagină de listare servicii admin
    else: return redirect(url_for('list_services'))

@app.route('/gradat/presence_report', methods=['GET', 'POST'])
@login_required
def presence_report():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    report_data = None; report_time_str = datetime.now().strftime("%Y-%m-%d %H:%M"); report_title = "Raport Prezență Curentă"
    if request.method == 'POST':
        report_type, custom_dt_str = request.form.get('report_type'), request.form.get('custom_datetime')
        dt_check = datetime.now()
        if report_type == 'custom' and custom_dt_str:
            try: dt_check = datetime.strptime(custom_dt_str, '%Y-%m-%dT%H:%M'); report_title = f"Raport Prezență pentru {dt_check.strftime('%d.%m.%Y %H:%M')}"
            except ValueError: flash('Format dată/oră invalid.', 'warning')
        elif report_type == 'evening_roll_call': dt_check = dt_check.replace(hour=20 if dt_check.weekday() < 4 else 22, minute=0, second=0, microsecond=0); report_title = f"Raport Apel Seară ({dt_check.strftime('%d.%m %H:%M')})"
        elif report_type == 'company_report': dt_check = dt_check.replace(hour=14, minute=20, second=0, microsecond=0); report_title = f"Raport Companie ({dt_check.strftime('%d.%m %H:%M')})"
        elif report_type == 'morning_check': dt_check = dt_check.replace(hour=7, minute=0, second=0, microsecond=0); report_title = f"Raport Prezență Dimineață ({dt_check.strftime('%d.%m %H:%M')})"
        else: report_title = f"Raport Prezență pentru {dt_check.strftime('%d.%m.%Y %H:%M')}" 
        report_time_str = dt_check.strftime("%Y-%m-%d %H:%M")
        
        # Pentru raportul gradatului, ne interesează doar studenții lui
        students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume, Student.prenume).all()
        ec = len(students)
        in_formation_count = 0; in_formation_list_details = []; on_duty_list_details = []; absent_list_details = []
        special_graded_list_details = [] # Pentru gradații speciali din plutonul gradatului

        for stud in students:
            s_info = get_student_status(stud, dt_check) # get_student_status ia student ca argument
            if s_info['status_code'] == 'present':
                in_formation_count += 1
                in_formation_list_details.append(f"{stud.grad_militar} {stud.nume} {stud.prenume} - Prezent în formație")
            elif s_info['status_code'] == 'on_duty':
                on_duty_list_details.append(f"{stud.grad_militar} {stud.nume} {stud.prenume} - {s_info['reason']}")
            elif s_info['status_code'] == 'special_graded_duty':
                 # Chiar dacă e gradat special, în raportul plutonului de bază (al gradatului) e considerat prezent
                 # dar cu mențiunea că e gradat special.
                 special_graded_list_details.append(f"{stud.grad_militar} {stud.nume} {stud.prenume} - {s_info['reason']}")
            else: 
                detail = f"{stud.grad_militar} {stud.nume} {stud.prenume} - {s_info['reason']}"
                if s_info['until']: detail += f" (până la {s_info['until'].strftime('%d.%m %H:%M')})"
                absent_list_details.append(detail)
        
        efectiv_prezent_total = in_formation_count + len(on_duty_list_details) + len(special_graded_list_details)
        efectiv_absent_count = ec - efectiv_prezent_total
        
        # Combinăm on_duty cu special_graded pentru afișare simplificată în raportul gradatului
        combined_on_duty_special_list = sorted(on_duty_list_details + special_graded_list_details)

        report_data = {
            "title": report_title, "datetime_checked": report_time_str, "efectiv_control": ec, 
            "efectiv_prezent_total": efectiv_prezent_total, "in_formation_count": in_formation_count,
            "in_formation_list": sorted(in_formation_list_details), 
            "on_duty_list": combined_on_duty_special_list, 
            "efectiv_absent_count": efectiv_absent_count, "efectiv_absent_list": sorted(absent_list_details)
        }
    return render_template('presence_report.html', report_data=report_data, current_datetime_str=datetime.now().strftime("%Y-%m-%dT%H:%M"))


def get_aggregated_presence_data(target_students_query, datetime_check, unit_type="pluton", unit_id_str=None):
    # unit_type poate fi "pluton", "companie", "batalion"
    # unit_id_str este ID-ul unității evaluate (ex: pluton_id, companie_id)
    
    students_list = target_students_query.all()
    efectiv_control = len(students_list)
    
    in_formation_count = 0
    on_duty_count = 0 # Servicii clasice
    special_graded_present_count = 0 # Gradați speciali prezenți în unitate (nu neapărat în formație)
    
    in_formation_students_details = []
    on_duty_students_details = []
    absent_students_details = []
    special_graded_details = [] # Listă pentru toți gradații speciali din unitatea evaluată

    for student_obj in students_list: # Iterăm peste obiectele Student
        user_obj = student_obj.creator # Userul care a creat studentul (gradat, admin)
        # Obținem statusul pentru student (care va verifica și User-ul asociat pentru SpecialGradedUser)
        status_info = get_student_status(student_obj, datetime_check) 
        
        student_display_info = f"{student_obj.grad_militar} {student_obj.nume} {student_obj.prenume} (Pl.Bază: {student_obj.pluton})"

        if status_info['status_code'] == 'present':
            in_formation_count += 1
            in_formation_students_details.append(f"{student_display_info} - Prezent în formație")
        elif status_info['status_code'] == 'on_duty':
            on_duty_count += 1
            detail = f"{student_display_info} - {status_info['reason']}"
            if status_info.get('until'): detail += f" (până la {status_info['until'].strftime('%d.%m %H:%M')})"
            on_duty_students_details.append(detail)
        elif status_info['status_code'] == 'special_graded_duty':
            special_graded_present_count +=1
            # Verificăm dacă gradatul special activează în unitatea curentă (pluton/companie)
            # Această logică e importantă pentru a decide dacă e "în formație" sau doar "prezent în unitate"
            # `assigned_platoon_info` poate fi "Plutonul X / Compania Y" sau "Comandant Compania Z"
            # Trebuie o metodă de a verifica apartenența la unit_id_str
            
            # Simplificare pentru moment: Dacă unit_type e 'pluton' și assigned_platoon_info menționează plutonul, e în formație.
            # Altfel, e doar prezent în unitate.
            # Pentru comandanți de companie/batalion, ei sunt în formația unității lor.
            is_in_formation_here = False
            if unit_type == "pluton" and unit_id_str and status_info.get('assigned_platoon_info') and unit_id_str in status_info.get('assigned_platoon_info'):
                is_in_formation_here = True
            elif user_obj.role == 'comandant_companie' and unit_type == 'companie' and unit_id_str == student_obj.companie : # Comandantul e in formatia companiei lui
                 is_in_formation_here = True
            elif user_obj.role == 'comandant_batalion' and unit_type == 'batalion' and unit_id_str == student_obj.batalion : # Comandantul e in formatia batalionului lui
                 is_in_formation_here = True
            # Ar mai fi cazul studentului gradat special la plutonul X, care e și plutonul lui de bază.
            elif is_student_object and student_obj.pluton == unit_id_str and (not status_info.get('assigned_platoon_info') or unit_id_str in status_info.get('assigned_platoon_info')):
                 is_in_formation_here = True


            if is_in_formation_here:
                in_formation_count += 1
                in_formation_students_details.append(f"{student_display_info} - {status_info['reason']} (În Formație Aici)")
            else:
                # Este prezent în unitatea mai mare, dar nu în formația specifică (dacă unit_id_str e un pluton specific)
                # Sau e un gradat special la nivel de companie/batalion, pur și simplu prezent.
                special_graded_details.append(f"{student_display_info} - {status_info['reason']}")
        else: # Absențe
            absent_detail = f"{student_display_info} - {status_info['reason']}"
            if status_info.get('until'): absent_detail += f" (până la {status_info['until'].strftime('%d.%m %H:%M')})"
            absent_students_details.append(absent_detail)

    efectiv_prezent_total = in_formation_count + on_duty_count + len(special_graded_details) 
    # Am eliminat special_graded_present_count din suma Ep, deoarece gradații sunt fie în formație, fie în special_graded_details
    # `in_formation_count` include acum și gradații speciali care sunt în formație în unitatea evaluată.
    # `special_graded_details` îi conține pe cei prezenți în unitate dar nu în formația specifică (ex: gradat la alt pluton).
    
    efectiv_absent_total = len(absent_students_details)
    # Asigurare consistență EC = EP + EA
    efectiv_prezent_total = efectiv_control - efectiv_absent_total


    return {
        "efectiv_control": efectiv_control,
        "efectiv_prezent_total": efectiv_prezent_total,
        "in_formation_count": in_formation_count, # Include și gradații speciali în formația unității evaluate
        "in_formation_students_details": sorted(in_formation_students_details),
        "on_duty_count": on_duty_count, 
        "on_duty_students_details": sorted(on_duty_students_details),
        "special_graded_details": sorted(special_graded_details), # Gradați speciali prezenți, dar nu neapărat în formație
        "efectiv_absent_total": efectiv_absent_total,
        "absent_students_details": sorted(absent_students_details) 
    }

@app.route('/comandant/companie/dashboard')
@login_required
def company_commander_dashboard():
    if current_user.role != 'comandant_companie': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    match = re.match(r"CmdC(\d+)", current_user.username) # Presupunem că username-ul comandantului conține ID-ul companiei
    if not match: flash('Format username invalid pentru comandant companie.', 'danger'); return redirect(url_for('home'))
    company_id_str = match.group(1)
    
    now = datetime.now()
    roll_call_time = now.replace(hour=20 if now.weekday() < 4 else 22, minute=0, second=0, microsecond=0)
    
    platoons_data = {}
    all_students_in_company = Student.query.filter_by(companie=company_id_str).all()
    
    students_by_platoon = {}
    for student in all_students_in_company:
        if student.pluton not in students_by_platoon: students_by_platoon[student.pluton] = []
        students_by_platoon[student.pluton].append(student)

    distinct_platoon_ids = sorted(students_by_platoon.keys())

    for platoon_id_str_loop in distinct_platoon_ids:
        # Trecem lista de studenți direct, nu un query object
        # students_in_platoon_list = students_by_platoon[platoon_id_str_loop]
        # get_aggregated_presence_data așteaptă un query, deci refacem query-ul
        current_platoon_student_ids = [s.id for s in students_by_platoon[platoon_id_str_loop]]
        students_in_platoon_query = Student.query.filter(Student.id.in_(current_platoon_student_ids))
        platoons_data[f"Plutonul {platoon_id_str_loop}"] = get_aggregated_presence_data(students_in_platoon_query, roll_call_time, unit_type="pluton", unit_id_str=platoon_id_str_loop)
        
    total_company_presence = get_aggregated_presence_data(Student.query.filter_by(companie=company_id_str), roll_call_time, unit_type="companie", unit_id_str=company_id_str)

    return render_template('company_commander_dashboard.html', 
                           company_id=company_id_str,
                           platoons_data=platoons_data,
                           total_company_presence=total_company_presence,
                           roll_call_time_str=roll_call_time.strftime('%d.%m.%Y %H:%M'))

@app.route('/comandant/batalion/dashboard')
@login_required
def battalion_commander_dashboard():
    if current_user.role != 'comandant_batalion': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    match = re.search(r"CmdB(\d+)", current_user.username)
    if not match: flash(f'Format username invalid ({current_user.username}) pentru comandant batalion.', 'danger'); return redirect(url_for('home'))
    battalion_id_str = match.group(1)
    now = datetime.now()
    roll_call_time = now.replace(hour=20 if now.weekday() < 4 else 22, minute=0, second=0, microsecond=0)
    
    companies_data = {}
    all_students_in_battalion = Student.query.filter_by(batalion=battalion_id_str).all()
    students_by_company = {}
    for student in all_students_in_battalion:
        if student.companie not in students_by_company: students_by_company[student.companie] = []
        students_by_company[student.companie].append(student)
    distinct_company_ids = sorted(students_by_company.keys())

    for company_id_str_loop in distinct_company_ids:
        current_company_student_ids = [s.id for s in students_by_company[company_id_str_loop]]
        students_in_company_query = Student.query.filter(Student.id.in_(current_company_student_ids))
        companies_data[f"Compania {company_id_str_loop}"] = get_aggregated_presence_data(students_in_company_query, roll_call_time, unit_type="companie", unit_id_str=company_id_str_loop)

    total_battalion_presence = get_aggregated_presence_data(Student.query.filter_by(batalion=battalion_id_str), roll_call_time, unit_type="batalion", unit_id_str=battalion_id_str)

    return render_template('battalion_commander_dashboard.html',
                           battalion_id=battalion_id_str,
                           companies_data=companies_data, 
                           total_battalion_presence=total_battalion_presence,
                           roll_call_time_str=roll_call_time.strftime('%d.%m.%Y %H:%M'))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=False)
