from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import os
import secrets 
from datetime import datetime, date, time, timedelta 
from sqlalchemy import func, or_
import re # Pentru extragerea ID-ului din username comandant
from unidecode import unidecode # <--- IMPORT ADĂUGAT AICI

# Inițializare aplicație Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inițializare extensii
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Te rugăm să te autentifici pentru a accesa această pagină."

# Constante
SERVICE_TYPES = ["GSS", "SVM", "Planton 1", "Planton 2", "Planton 3", "Intervenție", "Altul"]
GENDERS = ["Nespecificat", "M", "F"]
KNOWN_RANK_PATTERNS = [ # Mutat aici pentru a fi global
    re.compile(r"^(Mm V)\s+", re.IGNORECASE), re.compile(r"^(Sd cap)\s+", re.IGNORECASE),
    re.compile(r"^(Sg Maj)\s+", re.IGNORECASE), re.compile(r"^(Mm IV)\s+", re.IGNORECASE),
    re.compile(r"^(Sdt\.?)\s+", re.IGNORECASE), re.compile(r"^(Sd\.?)\s+", re.IGNORECASE),
    re.compile(r"^(Cap\.?)\s+", re.IGNORECASE), re.compile(r"^(Sg\.?)\s+", re.IGNORECASE),
    re.compile(r"^(Frt\.?)\s+", re.IGNORECASE), re.compile(r"^(Plt\.? Adj\.?)\s+", re.IGNORECASE), 
    re.compile(r"^(Plt\.? Maj\.?)\s+", re.IGNORECASE), re.compile(r"^(Plt\.?)\s+", re.IGNORECASE),
]

# Modelul User
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(50), nullable=False)
    unique_code = db.Column(db.String(100), unique=True, nullable=True)
    personal_code_hash = db.Column(db.String(256), nullable=True)
    is_first_login = db.Column(db.Boolean, default=True)

    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password) if self.password_hash else False
    def set_personal_code(self, code): self.personal_code_hash = bcrypt.hashpw(code.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'); self.is_first_login = False
    def check_personal_code(self, code): return bcrypt.checkpw(code.encode('utf-8'), self.personal_code_hash.encode('utf-8')) if self.personal_code_hash else False
    def can_login_with_personal_code(self): return self.role != 'admin' and self.personal_code_hash is not None
    def __repr__(self): return f'<User {self.username} ({self.role})>'

# Modelul Student
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
    def __repr__(self): return f'<Student {self.grad_militar} {self.nume} {self.prenume} - Pluton {self.pluton}>'

# Modelul Permission
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
    def __repr__(self): return f'<Permission {self.id} pentru {self.student.nume if self.student else "N/A"} de la {self.start_datetime} la {self.end_datetime}>'
    @property
    def is_active(self): now = datetime.now(); return self.start_datetime <= now <= self.end_datetime and self.status == 'Aprobată'
    @property
    def is_upcoming(self): now = datetime.now(); return self.start_datetime > now and self.status == 'Aprobată'
    @property
    def is_past(self): now = datetime.now(); return self.end_datetime < now or self.status == 'Anulată'

# Modelul DailyLeave
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
    def __repr__(self): return f'<DailyLeave {self.id} pentru {self.student.nume if self.student else "N/A"} pe {self.leave_date.strftime("%d-%m-%Y")} de la {self.start_time.strftime("%H:%M")} la {self.end_time.strftime("%H:%M")}>'
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

# Modelul WeekendLeave
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
    def __repr__(self): return f'<WeekendLeave {self.id} pentru {self.student.nume if self.student else "N/A"} în weekend-ul {self.weekend_start_date.strftime("%d-%m-%Y")}>'
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
        if self.status != 'Aprobată': return False
        now = datetime.now() # Definim 'now' în scope-ul proprietății
        return any(interval["end"] >= now for interval in self.get_intervals())
    @property
    def is_any_interval_active_now(self):
        if self.status != 'Aprobată': return False
        now = datetime.now() # Definim 'now' în scope-ul proprietății
        return any(interval["start"] <= now <= interval["end"] for interval in self.get_intervals())
    @property
    def is_overall_past(self): # Și aici, deși nu a cauzat eroarea directă, e bine să fie explicit
        now = datetime.now() # Definim 'now'
        return True if self.status == 'Anulată' else not self.is_overall_active_or_upcoming
    @property
    def display_days_and_times(self):
        return "; ".join([f"{i['day_name']} ({i['start'].strftime('%d.%m')}) {i['start'].strftime('%H:%M')}-{i['end'].strftime('%H:%M')}" for i in self.get_intervals()]) or "Nespecificat"

# Modelul VolunteerActivity
class VolunteerActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    activity_date = db.Column(db.Date, nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('volunteer_activities_created', lazy=True))
    participants = db.relationship('ActivityParticipant', backref='activity', lazy='dynamic', cascade="all, delete-orphan")
    def __repr__(self): return f'<VolunteerActivity {self.name} on {self.activity_date.strftime("%d-%m-%Y")}>'

# Modelul ActivityParticipant
class ActivityParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('volunteer_activity.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='CASCADE'), nullable=False)
    points_awarded = db.Column(db.Integer, default=0)
    student = db.relationship('Student', backref=db.backref('participations', lazy=True, cascade="all, delete-orphan"))
    def __repr__(self): return f'<ActivityParticipant StudentID: {self.student_id} ActivityID: {self.activity_id} Points: {self.points_awarded}>'

# Modelul ServiceAssignment
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
    def __repr__(self): return f'<ServiceAssignment {self.id} - {self.student.nume if self.student else ""} - {self.service_type} on {self.service_date.strftime("%d-%m-%Y")}>'
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

# --- Funcții Helper Globale ---
def get_next_friday(start_date=None):
    d = start_date if start_date else date.today()
    while d.weekday() != 4: # Vineri = 4
        d += timedelta(days=1)
    return d

def validate_daily_leave_times(start_time_obj, end_time_obj, leave_date_obj):
    if leave_date_obj.weekday() > 3: # 0-Luni, ..., 3-Joi
        return False, "Învoirile zilnice sunt permise doar de Luni până Joi."
    # ... (restul logicii de validare rămâne neschimbată)
    if start_time_obj == end_time_obj:
        return False, "Ora de început și de sfârșit nu pot fi identice."
    return True, "Valid"

def get_student_status(student, datetime_check):
    # ... (logica rămâne neschimbată)
    # Prioritatea 1: Serviciu
    active_service = ServiceAssignment.query.filter(
        ServiceAssignment.student_id == student.id,
        ServiceAssignment.start_datetime <= datetime_check,
        ServiceAssignment.end_datetime >= datetime_check
    ).order_by(ServiceAssignment.start_datetime).first()
    if active_service:
        return {
            "status_code": "on_duty", 
            "reason": f"Serviciu ({active_service.service_type})",
            "until": active_service.end_datetime,
            "details": f"Serviciu: {active_service.service_type}",
            "object": active_service,
            "participates_in_roll_call": active_service.participates_in_roll_call 
        }
    # Prioritatea 2: Permisie
    active_permission = Permission.query.filter(
        Permission.student_id == student.id, Permission.status == 'Aprobată',
        Permission.start_datetime <= datetime_check, Permission.end_datetime >= datetime_check
    ).order_by(Permission.start_datetime).first()
    if active_permission:
        return {
            "status_code": "absent_permission", "reason": "Permisie", "until": active_permission.end_datetime,
            "details": "Permisie", "object": active_permission
        }
    # Prioritatea 3: Învoire Weekend
    weekend_leaves = WeekendLeave.query.filter(WeekendLeave.student_id == student.id, WeekendLeave.status == 'Aprobată').all()
    for wl in weekend_leaves:
        for interval in wl.get_intervals():
            if interval['start'] <= datetime_check <= interval['end']:
                return {
                    "status_code": "absent_weekend_leave", "reason": f"Învoire Weekend ({interval['day_name']})", 
                    "until": interval['end'], "details": f"Învoire Weekend: {interval['day_name']}", "object": wl
                }
    # Prioritatea 4: Învoire Zilnică
    daily_leaves = DailyLeave.query.filter(DailyLeave.student_id == student.id, DailyLeave.status == 'Aprobată').all()
    for dl in daily_leaves:
        if dl.start_datetime <= datetime_check <= dl.end_datetime:
             return {
                "status_code": "absent_daily_leave", "reason": f"Învoire Zilnică ({dl.leave_type_display})", 
                "until": dl.end_datetime, "details": f"Învoire Zilnică: {dl.leave_type_display}", "object": dl
            }
    return {"status_code": "present", "reason": "Prezent", "until": None, "details": "Prezent", "object": None}


# Funcție de parsare a liniei pentru învoiri, îmbunătățită
def parse_student_line(line_text):
    # ... (logica rămâne neschimbată)
    original_line = line_text.strip()
    parts = original_line.split()

    grad = None
    nume = None
    prenume = None
    start_hour_interval_str = None
    end_hour_interval_str = None
    end_hour_individual_str = None

    if not parts:
        return {'grad': grad, 'nume': nume, 'prenume': prenume,
                'start_hour_interval_str': start_hour_interval_str,
                'end_hour_interval_str': end_hour_interval_str,
                'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}

    # 1. Verifică interval HH:MM-HH:MM la început
    time_interval_match = re.match(r"(\d{1,2}:\d{2})-(\d{1,2}:\d{2})", parts[0])
    if time_interval_match:
        try:
            start_h_str = time_interval_match.group(1)
            end_h_str = time_interval_match.group(2)
            datetime.strptime(start_h_str, '%H:%M')
            datetime.strptime(end_h_str, '%H:%M')
            start_hour_interval_str = start_h_str
            end_hour_interval_str = end_h_str
            parts = parts[1:]
        except ValueError:
            pass

    if not parts:
        return {'grad': grad, 'nume': nume, 'prenume': prenume,
                'start_hour_interval_str': start_hour_interval_str,
                'end_hour_interval_str': end_hour_interval_str,
                'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}

    # 2. Verifică ora individuală la sfârșit
    if not start_hour_interval_str and parts:
        last_part = parts[-1]
        time_extracted_individual = False
        if ':' in last_part and len(last_part.split(':')[0]) <= 2 and len(last_part.split(':')[-1]) == 2:
            try:
                datetime.strptime(last_part, '%H:%M')
                end_hour_individual_str = last_part
                parts = parts[:-1]
                time_extracted_individual = True
            except ValueError:
                pass
        elif len(last_part) == 4 and last_part.isdigit() and not time_extracted_individual:
            try:
                h = last_part[:2]
                m = last_part[2:]
                datetime.strptime(f"{h}:{m}", '%H:%M')
                end_hour_individual_str = f"{h}:{m}"
                parts = parts[:-1]
                time_extracted_individual = True
            except ValueError:
                pass

    if not parts:
         return {'grad': grad, 'nume': nume, 'prenume': prenume,
                'start_hour_interval_str': start_hour_interval_str,
                'end_hour_interval_str': end_hour_interval_str,
                'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}

    # 3. Extrage Grad, Nume, Prenume
    grad_parts_count = 0
    temp_grad_candidate = ""
    for i, part in enumerate(parts):
        test_text_for_grad = (temp_grad_candidate + " " + part).strip() if temp_grad_candidate else part
        found_match_for_test_text = False
        for pattern in KNOWN_RANK_PATTERNS:
            if pattern.match(test_text_for_grad + " ") or pattern.fullmatch(test_text_for_grad):
                found_match_for_test_text = True
                break
        if found_match_for_test_text:
            temp_grad_candidate = test_text_for_grad
            grad = temp_grad_candidate
            grad_parts_count = i + 1
        else:
            if grad: break
            if not grad: break

    name_parts_start_index = grad_parts_count
    remaining_parts = parts[name_parts_start_index:] if parts else []

    if len(remaining_parts) >= 1:
        nume = remaining_parts[0]
    if len(remaining_parts) >= 2:
        prenume = " ".join(remaining_parts[1:])
    if not grad and nume and ' ' in nume and not prenume:
        name_parts_split = nume.split(' ', 1)
        nume = name_parts_split[0]
        prenume = name_parts_split[1] if len(name_parts_split) > 1 else None

    return {'grad': grad, 'nume': nume, 'prenume': prenume,
            'start_hour_interval_str': start_hour_interval_str,
            'end_hour_interval_str': end_hour_interval_str,
            'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}


def check_leave_conflict(student_id, leave_start_dt, leave_end_dt, existing_leave_id=None, leave_type=None):
    # ... (logica rămâne neschimbată)
    query_services = ServiceAssignment.query.filter(
        ServiceAssignment.student_id == student_id,
        or_(ServiceAssignment.service_type == 'GSS', ServiceAssignment.service_type == 'Intervenție'),
        ServiceAssignment.start_datetime < leave_end_dt, ServiceAssignment.end_datetime > leave_start_dt
    )
    conflicting_service = query_services.first()
    if conflicting_service: return f"serviciu ({conflicting_service.service_type}) pe {conflicting_service.service_date.strftime('%d-%m-%Y')}"
    query_permissions = Permission.query.filter(Permission.student_id == student_id, Permission.status == 'Aprobată', Permission.start_datetime < leave_end_dt, Permission.end_datetime > leave_start_dt)
    if leave_type == 'permission' and existing_leave_id: query_permissions = query_permissions.filter(Permission.id != existing_leave_id)
    if query_permissions.first() and leave_type != 'permission' : return "o permisie existentă"
    if query_permissions.count() > (0 if leave_type == 'permission' and existing_leave_id else 0) and leave_type == 'permission' and not existing_leave_id : return "o permisie existentă"
    daily_leaves = DailyLeave.query.filter(DailyLeave.student_id == student_id, DailyLeave.status == 'Aprobată').all()
    for dl in daily_leaves:
        if leave_type == 'daily_leave' and existing_leave_id and dl.id == existing_leave_id: continue
        if dl.start_datetime < leave_end_dt and dl.end_datetime > leave_start_dt: return f"o învoire zilnică pe {dl.leave_date.strftime('%d.%m')}"
    weekend_leaves = WeekendLeave.query.filter(WeekendLeave.student_id == student_id, WeekendLeave.status == 'Aprobată').all()
    for wl in weekend_leaves:
        if leave_type == 'weekend_leave' and existing_leave_id and wl.id == existing_leave_id: continue
        for interval in wl.get_intervals():
            if interval['start'] < leave_end_dt and interval['end'] > leave_start_dt: return f"o învoire de weekend ({interval['day_name']})"
    return None

def check_service_conflict_for_student(student_id, service_start_dt, service_end_dt, service_type, current_service_id=None):
    # ... (logica rămâne neschimbată)
    conflicting_permission = Permission.query.filter(Permission.student_id == student_id, Permission.status == 'Aprobată', Permission.start_datetime < service_end_dt, Permission.end_datetime > service_start_dt).first()
    if conflicting_permission: return f"permisie ({conflicting_permission.start_datetime.strftime('%d.%m %H:%M')} - {conflicting_permission.end_datetime.strftime('%d.%m %H:%M')})"
    daily_leaves = DailyLeave.query.filter(DailyLeave.student_id == student_id, DailyLeave.status == 'Aprobată').all()
    for dl in daily_leaves:
        if dl.start_datetime < service_end_dt and dl.end_datetime > service_start_dt: return f"învoire zilnică ({dl.leave_date.strftime('%d.%m')} {dl.start_time.strftime('%H:%M')}-{dl.end_time.strftime('%H:%M')})"
    weekend_leaves = WeekendLeave.query.filter(WeekendLeave.student_id == student_id, WeekendLeave.status == 'Aprobată').all()
    for wl in weekend_leaves:
        for interval in wl.get_intervals():
            if interval['start'] < service_end_dt and interval['end'] > service_start_dt: return f"învoire de weekend ({interval['day_name']} {interval['start'].strftime('%H:%M')}-{interval['end'].strftime('%H:%M')})"
    query_other_services = ServiceAssignment.query.filter(ServiceAssignment.student_id == student_id, ServiceAssignment.start_datetime < service_end_dt, ServiceAssignment.end_datetime > service_start_dt)
    if current_service_id: query_other_services = query_other_services.filter(ServiceAssignment.id != current_service_id)
    conflicting_other_service = query_other_services.first()
    if conflicting_other_service: return f"alt serviciu ({conflicting_other_service.service_type} pe {conflicting_other_service.service_date.strftime('%d.%m')})"
    return None

# --- Rute Comune ---
# ... (restul rutelor rămân neschimbate până la process_daily_leaves_text) ...

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

    if apply_date_obj.weekday() > 3: # Luni=0, ..., Joi=3
        flash('Învoirile din text pot fi procesate doar pentru zilele de Luni până Joi.', 'warning')
        return redirect(url_for('list_daily_leaves', today_str=apply_date_str))

    lines = form_text.strip().splitlines()
    processed_count = 0
    skipped_entries = [] 
    success_entries = []

    default_start_processing_time = time(15, 0)
    default_end_processing_time = time(19, 0)

    all_students_gradat = Student.query.filter_by(created_by_user_id=current_user.id).all()
    # Pre-procesează numele studenților din DB pentru căutare fără diacritice
    students_db_normalized = [
        {
            "original": s, # Păstrăm obiectul student original
            "norm_nume": unidecode(s.nume.lower()),
            "norm_prenume": unidecode(s.prenume.lower()) if s.prenume else ""
        } for s in all_students_gradat
    ]

    for line_num, line in enumerate(lines):
        original_line_text = line.strip()
        if not original_line_text:
            continue

        parsed_data = parse_student_line(original_line_text)

        if not parsed_data['nume'] and not parsed_data['start_hour_interval_str']:
            skipped_entries.append(f"Linia {line_num+1} (format nume incorect sau linie goală): \"{parsed_data['original_line']}\"")
            continue
        
        student_found_original_object = None
        if parsed_data['nume']:
            search_nume_norm = unidecode(parsed_data['nume'].lower())
            search_prenume_norm = unidecode(parsed_data['prenume'].lower()) if parsed_data['prenume'] else ""

            # Căutare exactă Nume+Prenume (normalizat)
            if search_prenume_norm:
                for s_info in students_db_normalized:
                    if (s_info["norm_nume"] == search_nume_norm and s_info["norm_prenume"] == search_prenume_norm) or \
                       (s_info["norm_nume"] == search_prenume_norm and s_info["norm_prenume"] == search_nume_norm):
                        student_found_original_object = s_info["original"]
                        break

            if not student_found_original_object: # Căutare mai largă
                possible_matches_objects = []
                for s_info in students_db_normalized:
                    db_full_name_norm = f"{s_info['norm_nume']} {s_info['norm_prenume']}".strip()
                    # Potrivire pe nume SAU prenume (dacă prenumele e dat)
                    # Sau potrivire a numelui dat în numele complet din DB (dacă prenumele nu e dat)
                    cond1 = (s_info["norm_nume"] == search_nume_norm)
                    cond2 = (search_prenume_norm and s_info["norm_prenume"] == search_prenume_norm)
                    cond3 = (not search_prenume_norm and search_nume_norm in db_full_name_norm) # Caută doar numele în numele complet
                    # Caz inversat: Numele din input e prenumele din DB și invers
                    cond4 = (s_info["norm_nume"] == search_prenume_norm and s_info["norm_prenume"] == search_nume_norm)


                    if cond1 or cond2 or cond3 or cond4:
                        possible_matches_objects.append(s_info["original"])

                if len(possible_matches_objects) == 1:
                    student_found_original_object = possible_matches_objects[0]
                elif len(possible_matches_objects) > 1:
                    # Încercare de rafinare mai strictă pentru ambiguități
                    strict_matches = []
                    for s_obj in possible_matches_objects:
                        s_obj_norm_nume = unidecode(s_obj.nume.lower())
                        s_obj_norm_prenume = unidecode(s_obj.prenume.lower()) if s_obj.prenume else ""
                        if search_prenume_norm: # Avem Nume și Prenume din input
                            if (s_obj_norm_nume == search_nume_norm and s_obj_norm_prenume == search_prenume_norm) or \
                               (s_obj_norm_nume == search_prenume_norm and s_obj_norm_prenume == search_nume_norm):
                                strict_matches.append(s_obj)
                        else: # Avem doar Nume din input
                            if s_obj_norm_nume == search_nume_norm or s_obj_norm_prenume == search_nume_norm : # Numele din input e fie nume fie prenume in DB
                                strict_matches.append(s_obj)

                    if len(strict_matches) == 1:
                        student_found_original_object = strict_matches[0]
                    else:
                        skipped_entries.append(f"Numele '{parsed_data['nume']}{' ' + parsed_data['prenume'] if parsed_data['prenume'] else ''}' (normalizat: '{search_nume_norm}{' ' + search_prenume_norm if search_prenume_norm else ''}') este ambiguu. Găsit {len(strict_matches) if strict_matches else len(possible_matches_objects)} potriviri. (Linia: \"{original_line_text}\")")
                        continue

        if not student_found_original_object:
            skipped_entries.append(f"Studentul '{parsed_data['nume']}{' ' + parsed_data['prenume'] if parsed_data['prenume'] else ''}' (normalizat: '{unidecode(parsed_data['nume'].lower())}{' ' + unidecode(parsed_data['prenume'].lower() if parsed_data.get('prenume') else '')}') nu a fost găsit. (Linia: \"{original_line_text}\")")
            continue

        student_found = student_found_original_object
        # Restul funcției (stabilire ore, verificare conflicte, adăugare învoire) rămâne la fel
        current_start_time = default_start_processing_time
        current_end_time = default_end_processing_time

        if parsed_data['start_hour_interval_str'] and parsed_data['end_hour_interval_str']:
            try:
                current_start_time = datetime.strptime(parsed_data['start_hour_interval_str'], '%H:%M').time()
                current_end_time = datetime.strptime(parsed_data['end_hour_interval_str'], '%H:%M').time()
            except ValueError:
                skipped_entries.append(f"Interval orar invalid ({parsed_data['start_hour_interval_str']}-{parsed_data['end_hour_interval_str']}) pentru {student_found.nume} {student_found.prenume}. (Linia: \"{original_line_text}\")")
                continue
        elif parsed_data['end_hour_individual_str']:
            try:
                current_start_time = default_start_processing_time
                current_end_time = datetime.strptime(parsed_data['end_hour_individual_str'], '%H:%M').time()
            except ValueError:
                skipped_entries.append(f"Ora de sfârșit individuală invalidă ({parsed_data['end_hour_individual_str']}) pentru {student_found.nume} {student_found.prenume}. (Linia: \"{original_line_text}\")")
                continue

        is_valid_interval, interval_msg = validate_daily_leave_times(current_start_time, current_end_time, apply_date_obj)
        if not is_valid_interval:
            skipped_entries.append(f"Interval invalid ({current_start_time.strftime('%H:%M')}-{current_end_time.strftime('%H:%M')}) pentru {student_found.nume} {student_found.prenume}: {interval_msg}. (Linia: \"{original_line_text}\")")
            continue

        leave_start_dt = datetime.combine(apply_date_obj, current_start_time)
        effective_end_leave_date = apply_date_obj
        if current_end_time < current_start_time : effective_end_leave_date += timedelta(days=1)
        leave_end_dt = datetime.combine(effective_end_leave_date, current_end_time)
        
        conflict_msg = check_leave_conflict(student_found.id, leave_start_dt, leave_end_dt, leave_type='daily_leave')
        if conflict_msg:
            skipped_entries.append(f"Conflict pentru {student_found.nume} {student_found.prenume}: are deja {conflict_msg}. Învoirea nu a fost adăugată. (Linia: \"{original_line_text}\")")
            continue

        new_leave = DailyLeave(student_id=student_found.id, leave_date=apply_date_obj, start_time=current_start_time, end_time=current_end_time, reason="Procesat din text", created_by_user_id=current_user.id)
        db.session.add(new_leave)
        success_entries.append(f"{student_found.grad_militar} {student_found.nume} {student_found.prenume} ({current_start_time.strftime('%H:%M')} - {current_end_time.strftime('%H:%M')})")
        processed_count += 1
    
    try:
        db.session.commit()
        if processed_count > 0: flash(f'{processed_count} învoiri au fost procesate și adăugate cu succes pentru data de {apply_date_obj.strftime("%d-%m-%Y")}.', 'success')
        if not processed_count and not skipped_entries: flash('Nicio linie validă de procesat în textul furnizat.', 'info')
        elif not processed_count and skipped_entries : flash('Nicio învoire nu a putut fi procesată cu succes.', 'warning')

        if skipped_entries:
            flash('Următoarele linii/studenți nu au putut fi procesate:', 'warning')
            for skipped_line in skipped_entries:
                flash(skipped_line, 'secondary') 
    except Exception as e:
        db.session.rollback()
        flash(f'A apărut o eroare la salvarea învoirilor: {str(e)}', 'danger')

    return redirect(url_for('list_daily_leaves', today_str=apply_date_str))

# ... (restul fișierului app.py rămâne neschimbat) ...

# Duplicat pentru a asigura că este la sfârșit
@app.route('/comandant/batalion/dashboard')
@login_required
def battalion_commander_dashboard():
    if current_user.role != 'comandant_batalion': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    match = re.search(r"CmdB(\d+)", current_user.username)
    if not match: flash(f'Format username invalid ({current_user.username}) pentru comandant batalion. Așteptat un format care conține CmdB<ID>.', 'danger'); return redirect(url_for('home'))
    battalion_id_str = match.group(1)
    now = datetime.now()
    roll_call_time = now.replace(hour=20 if now.weekday() < 4 else 22, minute=0, second=0, microsecond=0)
    
    companies_data = {}
    distinct_companies = db.session.query(Student.companie).filter(Student.batalion == battalion_id_str).distinct().all()
    for comp_tuple in distinct_companies:
        company_id_str = comp_tuple[0]
        students_in_company = Student.query.filter_by(batalion=battalion_id_str, companie=company_id_str)
        companies_data[f"Compania {company_id_str}"] = get_aggregated_presence_data(students_in_company, roll_call_time)

    total_battalion_presence = get_aggregated_presence_data(Student.query.filter_by(batalion=battalion_id_str), roll_call_time)

    return render_template('battalion_commander_dashboard.html',
                           battalion_id=battalion_id_str,
                           companies_data=companies_data, 
                           total_battalion_presence=total_battalion_presence,
                           roll_call_time_str=roll_call_time.strftime('%d.%m.%Y %H:%M'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=False)
