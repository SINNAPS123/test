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
from unidecode import unidecode

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
KNOWN_RANK_PATTERNS = [ 
    re.compile(r"^(Mm V)\s+", re.IGNORECASE), re.compile(r"^(Sd cap)\s+", re.IGNORECASE),
    re.compile(r"^(Sg Maj)\s+", re.IGNORECASE), re.compile(r"^(Mm IV)\s+", re.IGNORECASE),
    re.compile(r"^(Sdt\.?)\s+", re.IGNORECASE), re.compile(r"^(Sd\.?)\s+", re.IGNORECASE),
    re.compile(r"^(Cap\.?)\s+", re.IGNORECASE), re.compile(r"^(Sg\.?)\s+", re.IGNORECASE),
    re.compile(r"^(Frt\.?)\s+", re.IGNORECASE), re.compile(r"^(Plt\.? Adj\.?)\s+", re.IGNORECASE), 
    re.compile(r"^(Plt\.? Maj\.?)\s+", re.IGNORECASE), re.compile(r"^(Plt\.?)\s+", re.IGNORECASE),
]
MAX_GRADATI_ACTIVI = 14

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
    este_gradat_activ = db.Column(db.Boolean, default=False, nullable=False)
    pluton_gradat_la = db.Column(db.String(50), nullable=True) 

    def __repr__(self): 
        gradat_info = ""
        if self.este_gradat_activ:
            gradat_info = f" (Gradat Activ{' la Pl.' + self.pluton_gradat_la if self.pluton_gradat_la else ''})"
        return f'<Student {self.grad_militar} {self.nume} {self.prenume} - Pluton {self.pluton}{gradat_info}>'

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
        if self.status != 'Aprobată': return False
        now = datetime.now() 
        return any(interval["end"] >= now for interval in self.get_intervals())
    @property
    def is_any_interval_active_now(self):
        if self.status != 'Aprobată': return False
        now = datetime.now() 
        return any(interval["start"] <= now <= interval["end"] for interval in self.get_intervals())
    @property
    def is_overall_past(self): 
        now = datetime.now() 
        return True if self.status == 'Anulată' else not self.is_overall_active_or_upcoming
    @property
    def display_days_and_times(self):
        return "; ".join([f"{i['day_name']} ({i['start'].strftime('%d.%m')}) {i['start'].strftime('%H:%M')}-{i['end'].strftime('%H:%M')}" for i in self.get_intervals()]) or "Nespecificat"

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
    d = start_date if start_date else date.today()
    while d.weekday() != 4: d += timedelta(days=1)
    return d

def validate_daily_leave_times(start_time_obj, end_time_obj, leave_date_obj):
    if leave_date_obj.weekday() > 3: 
        return False, "Învoirile zilnice sunt permise doar de Luni până Joi."
    if start_time_obj == end_time_obj: 
        return False, "Ora de început și de sfârșit nu pot fi identice."
    return True, "Valid"

def get_student_status(student, datetime_check):
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
                    "status_code": "absent_weekend_leave", 
                    "reason": f"Învoire Weekend ({interval['day_name']})", 
                    "until": interval['end'], 
                    "details": f"Învoire Weekend: {interval['day_name']}", 
                    "object": wl
                }
    # Prioritatea 4: Învoire Zilnică
    daily_leaves = DailyLeave.query.filter(DailyLeave.student_id == student.id, DailyLeave.status == 'Aprobată').all()
    for dl in daily_leaves:
        if dl.start_datetime <= datetime_check <= dl.end_datetime:
             return {
                "status_code": "absent_daily_leave", 
                "reason": f"Învoire Zilnică ({dl.leave_type_display})", 
                "until": dl.end_datetime, 
                "details": f"Învoire Zilnică: {dl.leave_type_display}", 
                "object": dl
            }
    
    # Prioritatea 5: Status Gradat Activ
    if student.este_gradat_activ:
        pluton_unde_activeaza = student.pluton_gradat_la if student.pluton_gradat_la else student.pluton
        return {
            "status_code": "active_duty_gradat",
            "reason": f"Gradat Activ la Pl. {pluton_unde_activeaza}",
            "until": None, # Gradații sunt activi pe termen nedefinit în acest context
            "details": f"Gradat Activ la Plutonul {pluton_unde_activeaza}",
            "object": student, # Putem returna studentul pentru referință
            "pluton_activitate_gradat": pluton_unde_activeaza, # Adăugăm explicit unde activează
            "pluton_baza": student.pluton # Și plutonul lui de bază
        }

    return {"status_code": "present", "reason": "Prezent", "until": None, "details": "Prezent", "object": None}


def parse_student_line(line_text):
    original_line = line_text.strip()
    parts = original_line.split()
    grad = None; nume = None; prenume = None
    start_hour_interval_str = None; end_hour_interval_str = None; end_hour_individual_str = None

    if not parts: return {'grad': grad, 'nume': nume, 'prenume': prenume, 'start_hour_interval_str': start_hour_interval_str, 'end_hour_interval_str': end_hour_interval_str, 'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}

    time_interval_match = re.match(r"(\d{1,2}:\d{2})-(\d{1,2}:\d{2})", parts[0])
    if time_interval_match:
        try:
            start_h_str = time_interval_match.group(1); end_h_str = time_interval_match.group(2)
            datetime.strptime(start_h_str, '%H:%M'); datetime.strptime(end_h_str, '%H:%M')   
            start_hour_interval_str = start_h_str; end_hour_interval_str = end_h_str
            parts = parts[1:] 
        except ValueError: pass 

    if not parts: return {'grad': grad, 'nume': nume, 'prenume': prenume, 'start_hour_interval_str': start_hour_interval_str, 'end_hour_interval_str': end_hour_interval_str, 'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}

    if not start_hour_interval_str and parts: 
        last_part = parts[-1]; time_extracted_individual = False
        if ':' in last_part and len(last_part.split(':')[0]) <= 2 and len(last_part.split(':')[-1]) == 2:
            try:
                datetime.strptime(last_part, '%H:%M'); end_hour_individual_str = last_part
                parts = parts[:-1]; time_extracted_individual = True
            except ValueError: pass
        elif len(last_part) == 4 and last_part.isdigit() and not time_extracted_individual: 
            try:
                h = last_part[:2]; m = last_part[2:]
                datetime.strptime(f"{h}:{m}", '%H:%M'); end_hour_individual_str = f"{h}:{m}"
                parts = parts[:-1]; time_extracted_individual = True
            except ValueError: pass

    if not parts: return {'grad': grad, 'nume': nume, 'prenume': prenume, 'start_hour_interval_str': start_hour_interval_str, 'end_hour_interval_str': end_hour_interval_str, 'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}

    grad_parts_count = 0; temp_grad_candidate = ""
    for i, part in enumerate(parts):
        test_text_for_grad = (temp_grad_candidate + " " + part).strip() if temp_grad_candidate else part
        found_match_for_test_text = False
        for pattern in KNOWN_RANK_PATTERNS:
            if pattern.match(test_text_for_grad + " ") or pattern.fullmatch(test_text_for_grad):
                found_match_for_test_text = True; break
        if found_match_for_test_text:
            temp_grad_candidate = test_text_for_grad; grad = temp_grad_candidate 
            grad_parts_count = i + 1
        else:
            if grad: break
            if not grad: break 
    name_parts_start_index = grad_parts_count
    remaining_parts = parts[name_parts_start_index:] if parts else [] 
    if len(remaining_parts) >= 1: nume = remaining_parts[0]
    if len(remaining_parts) >= 2: prenume = " ".join(remaining_parts[1:])
    if not grad and nume and ' ' in nume and not prenume:
        name_parts_split = nume.split(' ', 1)
        nume = name_parts_split[0]; prenume = name_parts_split[1] if len(name_parts_split) > 1 else None
    return {'grad': grad, 'nume': nume, 'prenume': prenume, 'start_hour_interval_str': start_hour_interval_str, 'end_hour_interval_str': end_hour_interval_str, 'end_hour_individual_str': end_hour_individual_str, 'original_line': original_line}

def check_leave_conflict(student_id, leave_start_dt, leave_end_dt, existing_leave_id=None, leave_type=None):
    query_services = ServiceAssignment.query.filter(ServiceAssignment.student_id == student_id, or_(ServiceAssignment.service_type == 'GSS', ServiceAssignment.service_type == 'Intervenție'), ServiceAssignment.start_datetime < leave_end_dt, ServiceAssignment.end_datetime > leave_start_dt)
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
# ...
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
    active_gradati_count = Student.query.filter_by(este_gradat_activ=True).count()
    return render_template('admin_dashboard.html', 
                           users=User.query.filter(User.role != 'admin').all(),
                           active_gradati_count=active_gradati_count,
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
    if current_user.role != 'admin': return redirect(url_for('home'))
    user_to_reset = User.query.get_or_404(user_id)
    if user_to_reset.role == 'admin': flash('Nu se poate reseta codul pentru un admin.', 'warning'); return redirect(url_for('admin_dashboard'))
    user_to_reset.unique_code = secrets.token_hex(8); user_to_reset.personal_code_hash = None; user_to_reset.is_first_login = True
    db.session.commit()
    flash(f'Codul pentru {user_to_reset.username} a fost resetat. Noul cod unic este: {user_to_reset.unique_code}', 'success')
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
    if user_to_delete.role == 'admin':
        flash('Nu se poate șterge un alt administrator prin această interfață.', 'warning')
        return redirect(url_for('admin_dashboard'))
    username_deleted = user_to_delete.username
    role_deleted = user_to_delete.role
    if role_deleted == 'gradat':
        students_to_delete = Student.query.filter_by(created_by_user_id=user_id).all()
        for student in students_to_delete:
            db.session.delete(student)
        flash(f'Studenții și toate datele asociate gradatului {username_deleted} au fost șterse.', 'info')
    VolunteerActivity.query.filter_by(created_by_user_id=user_id).delete(synchronize_session=False)
    ServiceAssignment.query.filter_by(created_by_user_id=user_id).delete(synchronize_session=False)
    Permission.query.filter_by(created_by_user_id=user_id).delete(synchronize_session=False) 
    DailyLeave.query.filter_by(created_by_user_id=user_id).delete(synchronize_session=False)
    WeekendLeave.query.filter_by(created_by_user_id=user_id).delete(synchronize_session=False)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'Utilizatorul {username_deleted} ({role_deleted}) a fost șters cu succes.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- Autentificare Utilizator ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        login_code = request.form.get('login_code')
        user_by_unique_code = User.query.filter_by(unique_code=login_code, is_first_login=True).first()
        if user_by_unique_code:
            login_user(user_by_unique_code); flash('Cod unic valid. Setează-ți codul personal.', 'info'); return redirect(url_for('set_personal_code'))
        else:
            found_user = next((u for u in User.query.filter(User.role != 'admin').all() if u.can_login_with_personal_code() and u.check_personal_code(login_code)), None)
            if found_user: login_user(found_user); flash('Autentificare reușită!', 'success'); return redirect(url_for('dashboard'))
            else: flash('Cod de autentificare invalid.', 'danger')
    return render_template('login.html')

@app.route('/set_personal_code', methods=['GET', 'POST'])
@login_required
def set_personal_code():
    if not current_user.is_first_login: flash('Codul personal a fost deja setat.', 'info'); return redirect(url_for('dashboard'))
    if request.method == 'POST':
        p_code, c_p_code = request.form.get('personal_code'), request.form.get('confirm_personal_code')
        if not p_code or len(p_code) < 4: flash('Codul personal trebuie să aibă cel puțin 4 caractere.', 'warning')
        elif p_code != c_p_code: flash('Codurile personale nu se potrivesc.', 'warning')
        else:
            current_user.set_personal_code(p_code); current_user.unique_code = None; db.session.commit()
            flash('Codul personal a fost setat! Te poți autentifica acum cu noul cod.', 'success'); logout_user(); return redirect(url_for('login'))
    return render_template('set_personal_code.html')

# --- Rute Gradat ---
@app.route('/gradat/dashboard')
@login_required
def gradat_dashboard():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    s_count = Student.query.filter_by(created_by_user_id=current_user.id).count()
    active_p_count = Permission.query.join(Student).filter(Student.created_by_user_id == current_user.id, Permission.status == 'Aprobată', Permission.start_datetime <= datetime.now(), Permission.end_datetime >= datetime.now()).count()
    active_dl_q = DailyLeave.query.join(Student).filter(Student.created_by_user_id == current_user.id, DailyLeave.status == 'Aprobată').all()
    active_dl_count = sum(1 for dl in active_dl_q if dl.is_active)
    active_wl_q = WeekendLeave.query.join(Student).filter(Student.created_by_user_id == current_user.id, WeekendLeave.status == 'Aprobată').all()
    active_wl_count = sum(1 for wl in active_wl_q if wl.is_any_interval_active_now)
    total_volunteer_activities = VolunteerActivity.query.filter_by(created_by_user_id=current_user.id).count()
    active_services_count = ServiceAssignment.query.join(Student).filter(Student.created_by_user_id == current_user.id, ServiceAssignment.start_datetime <= datetime.now(), ServiceAssignment.end_datetime >= datetime.now()).count()
    return render_template('gradat_dashboard.html', student_count=s_count, active_permissions_count=active_p_count, 
                           active_daily_leaves_count=active_dl_count, active_weekend_leaves_count=active_wl_count,
                           total_volunteer_activities=total_volunteer_activities, active_services_count=active_services_count)

@app.route('/gradat/situatie_pluton')
@login_required
def situatie_pluton():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))
    now = datetime.now()
    today = date.today()
    tomorrow = today + timedelta(days=1)
    day_after_tomorrow = today + timedelta(days=2) 
    next_48h_limit = now + timedelta(hours=48)
    students_platoon = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume, Student.prenume).all()
    efectiv_control_now = len(students_platoon)
    efectiv_prezent_total_now = 0 
    in_formation_now = 0
    on_duty_now_list = [] 
    absent_now_list = []  
    gradati_activi_alt_pluton_list = [] # Nou: listă pentru gradați activi la alt pluton

    for student in students_platoon:
        status_info = get_student_status(student, now) 
        
        if status_info['status_code'] == 'present':
            in_formation_now += 1
            efectiv_prezent_total_now +=1
        elif status_info['status_code'] == 'on_duty': 
            efectiv_prezent_total_now +=1 
            on_duty_now_list.append(f"{student.grad_militar} {student.nume} {student.prenume} - {status_info['reason']}")
        elif status_info['status_code'] == 'active_duty_gradat':
            efectiv_prezent_total_now +=1 # Și gradații sunt prezenți
            # Verificăm dacă activează în plutonul curent (al gradatului care vizualizează)
            # Presupunem că plutonul gradatului este dat de `student.pluton` pentru studenții din `students_platoon`
            pluton_evaluat = student.pluton 
            pluton_activitate_gradat = status_info.get('pluton_activitate_gradat', student.pluton)

            if pluton_activitate_gradat == pluton_evaluat:
                in_formation_now +=1 # Gradatul e în formație în acest pluton
            else:
                # Gradatul este activ, dar la alt pluton decât cel evaluat (plutonul de bază al studentului)
                gradati_activi_alt_pluton_list.append(f"{student.grad_militar} {student.nume} {student.prenume} - {status_info['reason']}")
        else: # Absențe (permisie, învoiri)
            absent_now_list.append(f"{student.grad_militar} {student.nume} {student.prenume} - {status_info['reason']} (până la {status_info['until'].strftime('%d.%m %H:%M') if status_info['until'] else 'N/A'})")
    
    efectiv_absent_now_count = len(absent_now_list)

    services_today = ServiceAssignment.query.join(Student).filter(ServiceAssignment.created_by_user_id == current_user.id, Student.id == ServiceAssignment.student_id, ServiceAssignment.service_date == today).order_by(ServiceAssignment.start_datetime).all()
    services_tomorrow = ServiceAssignment.query.join(Student).filter(ServiceAssignment.created_by_user_id == current_user.id, Student.id == ServiceAssignment.student_id, ServiceAssignment.service_date == tomorrow).order_by(ServiceAssignment.start_datetime).all()
    services_day_after = ServiceAssignment.query.join(Student).filter(ServiceAssignment.created_by_user_id == current_user.id, Student.id == ServiceAssignment.student_id, ServiceAssignment.service_date == day_after_tomorrow).order_by(ServiceAssignment.start_datetime).all()
    
    upcoming_leaves_list = []
    permissions_upcoming = Permission.query.join(Student).filter(Permission.created_by_user_id == current_user.id, Permission.status == 'Aprobată', Student.id == Permission.student_id, Permission.start_datetime > now, Permission.start_datetime <= next_48h_limit).order_by(Permission.start_datetime).all()
    for p_up in permissions_upcoming: upcoming_leaves_list.append(f"Permisie: {p_up.student.grad_militar} {p_up.student.nume} {p_up.student.prenume} (de la {p_up.start_datetime.strftime('%d.%m %H:%M')} până la {p_up.end_datetime.strftime('%d.%m %H:%M')})")
    daily_leaves_upcoming_q = DailyLeave.query.join(Student).filter(DailyLeave.created_by_user_id == current_user.id, DailyLeave.status == 'Aprobată', Student.id == DailyLeave.student_id).order_by(DailyLeave.leave_date, DailyLeave.start_time).all() 
    for dl_up in daily_leaves_upcoming_q: 
        if now < dl_up.start_datetime <= next_48h_limit : upcoming_leaves_list.append(f"Învoire Zilnică: {dl_up.student.grad_militar} {dl_up.student.nume} {dl_up.student.prenume} ({dl_up.leave_date.strftime('%d.%m')} {dl_up.start_time.strftime('%H:%M')}-{dl_up.end_time.strftime('%H:%M')})")
    weekend_leaves_upcoming_q = WeekendLeave.query.join(Student).filter(WeekendLeave.created_by_user_id == current_user.id, WeekendLeave.status == 'Aprobată', Student.id == WeekendLeave.student_id).order_by(WeekendLeave.weekend_start_date).all() 
    for wl_up in weekend_leaves_upcoming_q: 
        for interval in wl_up.get_intervals():
            if now < interval['start'] <= next_48h_limit: upcoming_leaves_list.append(f"Învoire Weekend ({interval['day_name']}): {wl_up.student.grad_militar} {wl_up.student.nume} {wl_up.student.prenume} ({interval['start'].strftime('%d.%m %H:%M')}-{interval['end'].strftime('%H:%M')})")
    
    next_roll_call_dt = now.replace(hour=20 if now.weekday() < 4 else 22, minute=0, second=0, microsecond=0)
    if next_roll_call_dt < now: 
        next_roll_call_dt += timedelta(days=1)
        next_roll_call_dt = next_roll_call_dt.replace(hour=20 if next_roll_call_dt.weekday() < 4 else 22, minute=0, second=0, microsecond=0)
    
    ep_next_roll_call, in_formation_next_roll_call = 0, 0
    on_duty_next_roll_call_list, absent_next_roll_call_list, gradati_alt_pl_next_roll_call_list = [], [], []
    for student in students_platoon:
        status_info = get_student_status(student, next_roll_call_dt)
        if status_info['status_code'] == 'present': 
            in_formation_next_roll_call +=1; ep_next_roll_call +=1
        elif status_info['status_code'] == 'on_duty': 
            ep_next_roll_call +=1
            on_duty_next_roll_call_list.append(f"{student.grad_militar} {student.nume} {student.prenume} - {status_info['reason']}")
        elif status_info['status_code'] == 'active_duty_gradat':
            ep_next_roll_call +=1
            pluton_evaluat = student.pluton
            pluton_activitate_gradat = status_info.get('pluton_activitate_gradat', student.pluton)
            if pluton_activitate_gradat == pluton_evaluat:
                in_formation_next_roll_call +=1
            else:
                gradati_alt_pl_next_roll_call_list.append(f"{student.grad_militar} {student.nume} {student.prenume} - {status_info['reason']}")
        else: 
            absent_next_roll_call_list.append(f"{student.grad_militar} {student.nume} {student.prenume} - {status_info['reason']} (până la {status_info['until'].strftime('%d.%m %H:%M') if status_info['until'] else 'N/A'})")
    
    next_report_info = {
        "time": next_roll_call_dt.strftime('%d.%m.%Y %H:%M'), "type": "Apel Seară", "ec": efectiv_control_now,
        "ep": ep_next_roll_call, "ea_count": len(absent_next_roll_call_list),
        "in_formation": in_formation_next_roll_call, 
        "on_duty_list": sorted(on_duty_next_roll_call_list),
        "absent_list": sorted(absent_next_roll_call_list),
        "gradati_alt_pluton_list": sorted(gradati_alt_pl_next_roll_call_list) # Adăugat pentru previziune
    }
    return render_template('situatie_pluton.html', 
                           efectiv_control_now=efectiv_control_now,
                           efectiv_prezent_total_now=efectiv_prezent_total_now,
                           in_formation_now=in_formation_now, 
                           on_duty_now_list=sorted(on_duty_now_list), 
                           absent_now_list=sorted(absent_now_list),
                           gradati_activi_alt_pluton_list=sorted(gradati_activi_alt_pluton_list), # Adăugat
                           efectiv_absent_now_count=efectiv_absent_now_count, 
                           services_today=services_today, 
                           services_tomorrow=services_tomorrow,
                           services_day_after=services_day_after, 
                           upcoming_leaves_list=sorted(upcoming_leaves_list), 
                           next_report_info=next_report_info,
                           current_time_str=now.strftime('%d.%m.%Y %H:%M'),
                           today=today, tomorrow=tomorrow, day_after_tomorrow=day_after_tomorrow) 

# --- Management Studenți ---
@app.route('/gradat/students') 
@app.route('/admin/students') 
@login_required
def list_students():
    if current_user.role == 'admin':
        page = request.args.get('page', 1, type=int)
        per_page = 25 
        query = Student.query
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
        active_gradati_count = Student.query.filter_by(este_gradat_activ=True).count()
        return render_template('list_students.html', students_pagination=students_pagination, is_admin_view=True, batalioane=batalioane, companii=companii, plutoane=plutoane, search_term=search_term, filter_batalion=filter_batalion, filter_companie=filter_companie, filter_pluton=filter_pluton, active_gradati_count=active_gradati_count, max_gradati_activi=MAX_GRADATI_ACTIVI)
    elif current_user.role == 'gradat':
        students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume, Student.prenume).all()
        return render_template('list_students.html', students=students, is_admin_view=False)
    else:
        flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))

@app.route('/admin/toggle_gradat_status/<int:student_id>', methods=['POST'])
@login_required
def admin_toggle_gradat_status(student_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    student = Student.query.get_or_404(student_id)
    active_gradati_count = Student.query.filter_by(este_gradat_activ=True).count()
    if not student.este_gradat_activ:
        if active_gradati_count >= MAX_GRADATI_ACTIVI:
            flash(f'Nu se pot activa mai mult de {MAX_GRADATI_ACTIVI} gradați. Dezactivați alt gradat întâi.', 'warning')
            return redirect(url_for('list_students'))
        student.este_gradat_activ = True
        if not student.pluton_gradat_la: student.pluton_gradat_la = student.pluton
        flash(f'Studentul {student.nume} {student.prenume} a fost setat ca gradat activ.', 'success')
    else:
        student.este_gradat_activ = False
        flash(f'Studentul {student.nume} {student.prenume} a fost dezactivat ca gradat.', 'success')
    db.session.commit()
    return redirect(url_for('list_students'))

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
        if current_user.role == 'admin':
            s_edit.pluton_gradat_la = form.get('pluton_gradat_la') if form.get('pluton_gradat_la') else None
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

@app.route('/gradat/students/delete/<int:student_id>', methods=['POST']) 
@app.route('/admin/students/delete/<int:student_id>', methods=['POST'])  
@login_required
def delete_student(student_id):
    s_del = Student.query.get_or_404(student_id)
    if current_user.role == 'gradat' and s_del.created_by_user_id != current_user.id:
        flash('Acces neautorizat pentru a șterge acest student.', 'danger'); return redirect(url_for('list_students'))
    elif current_user.role not in ['admin', 'gradat']:
        flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    msg = f'Studentul {s_del.grad_militar} {s_del.nume} {s_del.prenume} și înregistrările asociate au fost șterse.'
    db.session.delete(s_del); db.session.commit(); flash(msg, 'success')
    if current_user.role == 'admin': return redirect(url_for('list_students')) 
    else: return redirect(url_for('list_students'))

# ... (restul fișierului, inclusiv process_daily_leaves_text și celelalte rute, rămâne identic cu versiunea anterioară)

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
    processed_count = 0
    skipped_entries = [] 
    success_entries = []
    default_start_processing_time = time(15, 0)
    default_end_processing_time = time(19, 0)
    all_students_gradat = Student.query.filter_by(created_by_user_id=current_user.id).all()
    students_db_normalized = [{"original": s, "norm_nume": unidecode(s.nume.lower()), "norm_prenume": unidecode(s.prenume.lower()) if s.prenume else ""} for s in all_students_gradat]
    for line_num, line in enumerate(lines):
        original_line_text = line.strip()
        if not original_line_text: continue
        parsed_data = parse_student_line(original_line_text) 
        if not parsed_data['nume'] and not parsed_data['start_hour_interval_str']:
            skipped_entries.append(f"Linia {line_num+1} (format nume incorect sau linie goală): \"{parsed_data['original_line']}\"")
            continue
        student_found_original_object = None 
        if parsed_data['nume']:
            search_nume_norm = unidecode(parsed_data['nume'].lower())
            search_prenume_norm = unidecode(parsed_data['prenume'].lower()) if parsed_data['prenume'] else ""
            if search_prenume_norm: 
                for s_info in students_db_normalized:
                    if (s_info["norm_nume"] == search_nume_norm and s_info["norm_prenume"] == search_prenume_norm) or \
                       (s_info["norm_nume"] == search_prenume_norm and s_info["norm_prenume"] == search_nume_norm): 
                        student_found_original_object = s_info["original"]
                        break
            if not student_found_original_object: 
                possible_matches_objects = []
                for s_info in students_db_normalized:
                    db_full_name_norm = f"{s_info['norm_nume']} {s_info['norm_prenume']}".strip()
                    cond1 = (s_info["norm_nume"] == search_nume_norm)
                    cond2 = (search_prenume_norm and s_info["norm_prenume"] == search_prenume_norm)
                    cond3 = (not search_prenume_norm and search_nume_norm in db_full_name_norm) 
                    cond4 = (s_info["norm_nume"] == search_prenume_norm and s_info["norm_prenume"] == search_nume_norm)
                    if cond1 or cond2 or cond3 or cond4:
                        possible_matches_objects.append(s_info["original"])
                if len(possible_matches_objects) == 1:
                    student_found_original_object = possible_matches_objects[0]
                elif len(possible_matches_objects) > 1:
                    strict_matches = []
                    for s_obj in possible_matches_objects:
                        s_obj_norm_nume = unidecode(s_obj.nume.lower())
                        s_obj_norm_prenume = unidecode(s_obj.prenume.lower()) if s_obj.prenume else ""
                        if search_prenume_norm: 
                            if (s_obj_norm_nume == search_nume_norm and s_obj_norm_prenume == search_prenume_norm) or \
                               (s_obj_norm_nume == search_prenume_norm and s_obj_norm_prenume == search_nume_norm):
                                strict_matches.append(s_obj)
                        else: 
                            if s_obj_norm_nume == search_nume_norm or s_obj_norm_prenume == search_nume_norm : 
                                strict_matches.append(s_obj)
                    if len(strict_matches) == 1:
                        student_found_original_object = strict_matches[0]
                    else:
                        skipped_entries.append(f"Numele '{parsed_data['nume']}{' ' + parsed_data['prenume'] if parsed_data['prenume'] else ''}' (normalizat: '{search_nume_norm}{' ' + search_prenume_norm if search_prenume_norm else ''}') este ambiguu. Găsit {len(strict_matches) if strict_matches else len(possible_matches_objects)} potriviri. (Linia: \"{original_line_text}\")")
                        continue
        if not student_found_original_object: 
            skipped_entries.append(f"Studentul '{parsed_data['nume']}{' ' + parsed_data['prenume'] if parsed_data['prenume'] else ''}' (normalizat: '{unidecode(parsed_data['nume'].lower())}{' ' + unidecode(parsed_data['prenume'].lower()) if parsed_data.get('prenume') else ''}') nu a fost găsit. (Linia: \"{original_line_text}\")")
            continue
        student_found = student_found_original_object 
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

@app.route('/gradat/services/delete/<int:assignment_id>', methods=['POST']) 
@app.route('/admin/services/delete/<int:assignment_id>', methods=['POST'])  
@login_required
def delete_service_assignment(assignment_id):
    assignment_to_delete = ServiceAssignment.query.get_or_404(assignment_id)
    student_name_for_flash = "N/A"
    if assignment_to_delete.student: 
        student_name_for_flash = f"{assignment_to_delete.student.grad_militar} {assignment_to_delete.student.nume} {assignment_to_delete.student.prenume}"
    can_delete = False
    if current_user.role == 'admin': can_delete = True
    elif current_user.role == 'gradat' and assignment_to_delete.created_by_user_id == current_user.id: can_delete = True
    if not can_delete:
        flash('Acces neautorizat pentru a șterge acest serviciu.', 'danger')
        if current_user.role == 'gradat': return redirect(url_for('list_services'))
        else: return redirect(url_for('dashboard')) 
    try:
        service_type_flash = assignment_to_delete.service_type
        service_date_flash = assignment_to_delete.service_date.strftime("%d.%m.%Y")
        db.session.delete(assignment_to_delete)
        db.session.commit()
        flash(f'Serviciul ({service_type_flash}) pentru {student_name_for_flash} din data de {service_date_flash} a fost șters.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la ștergerea serviciului: {str(e)}', 'danger')
    if current_user.role == 'admin': return redirect(url_for('list_students')) 
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
        else: report_title = f"Raport Prezență pentru {dt_check.strftime('%d.%m.%Y %H:%M')}" # Curent
        report_time_str = dt_check.strftime("%Y-%m-%d %H:%M")
        students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume, Student.prenume).all()
        ec = len(students)
        in_formation_count = 0; in_formation_list_details = []; on_duty_list_details = []; absent_list_details = []
        for stud in students:
            s_info = get_student_status(stud, dt_check)
            if s_info['status_code'] == 'present':
                in_formation_count += 1
                in_formation_list_details.append(f"{stud.grad_militar} {stud.nume} {stud.prenume} - Prezent în formație")
            elif s_info['status_code'] == 'on_duty':
                on_duty_list_details.append(f"{stud.grad_militar} {stud.nume} {stud.prenume} - {s_info['reason']}")
            elif s_info['status_code'] == 'active_duty_gradat': # Adăugat pentru gradat
                 # Într-un raport general de pluton, gradatul e considerat "prezent" dar nu neapărat "în formație" aici
                 # Această listă poate fi afișată separat sau adăugată la "on_duty_list" cu o descriere specifică
                 on_duty_list_details.append(f"{stud.grad_militar} {stud.nume} {stud.prenume} - {s_info['reason']}")
            else: 
                detail = f"{stud.grad_militar} {stud.nume} {stud.prenume} - {s_info['reason']}"
                if s_info['until']: detail += f" (până la {s_info['until'].strftime('%d.%m %H:%M')})"
                absent_list_details.append(detail)
        efectiv_prezent_total = in_formation_count + len(on_duty_list_details) # Gradații activi sunt prezenți
        # Dacă gradații activi nu sunt în formație, dar sunt prezenți, in_formation_count nu îi include.
        # Acest calcul trebuie revizuit în funcție de cum se dorește afișarea.
        # Pentru simplificare, momentan îi considerăm parte din on_duty_list_details dacă nu sunt 'present'.
        efectiv_absent_count = ec - efectiv_prezent_total
        report_data = {
            "title": report_title, "datetime_checked": report_time_str, "efectiv_control": ec, 
            "efectiv_prezent_total": efectiv_prezent_total, "in_formation_count": in_formation_count,
            "in_formation_list": sorted(in_formation_list_details), 
            "on_duty_list": sorted(on_duty_list_details), # Include și gradații activi la alte plutoane
            "efectiv_absent_count": efectiv_absent_count, "efectiv_absent_list": sorted(absent_list_details)
        }
    return render_template('presence_report.html', report_data=report_data, current_datetime_str=datetime.now().strftime("%Y-%m-%dT%H:%M"))

def get_aggregated_presence_data(students_query, datetime_check, for_pluton_id=None):
    students_list = students_query.order_by(Student.nume, Student.prenume).all() 
    efectiv_control = len(students_list)
    in_formation_count = 0; on_duty_count = 0
    in_formation_students_details = []; on_duty_students_details = []; absent_students_details = []
    gradati_activi_in_pluton_evaluat_details = [] # Gradați care activează în acest pluton
    gradati_activi_din_pluton_la_alt_pluton_details = [] # Gradați din acest pluton, dar activi la altul

    for student in students_list:
        status_info = get_student_status(student, datetime_check)
        student_display_info = f"{student.grad_militar} {student.nume} {student.prenume} (Pl.Bază: {student.pluton})"

        if status_info['status_code'] == 'present':
            # Dacă se evaluează un pluton specific și studentul e din acel pluton, e în formație
            # Sau dacă nu se evaluează un pluton specific (total companie/batalion), e în formație
            if for_pluton_id is None or student.pluton == for_pluton_id:
                 in_formation_count += 1
                 in_formation_students_details.append(f"{student_display_info} - Prezent în formație")
            # else: studentul e din alt pluton, nu e relevant pentru formația plutonului curent (dacă for_pluton_id e setat)
            
        elif status_info['status_code'] == 'on_duty':
            on_duty_count += 1
            detail_serviciu = f"{student_display_info} - {status_info['reason']}"
            if status_info.get('until'): detail_serviciu += f" (până la {status_info['until'].strftime('%d.%m %H:%M')})"
            on_duty_students_details.append(detail_serviciu)

        elif status_info['status_code'] == 'active_duty_gradat':
            pluton_activitate_gradat = status_info.get('pluton_activitate_gradat', student.pluton)
            
            # Dacă evaluăm un pluton specific (ex: dashboard companie, detaliu pe pluton)
            if for_pluton_id:
                if pluton_activitate_gradat == for_pluton_id: # Gradatul activează în plutonul evaluat
                    in_formation_count += 1 # Este în formație în acest pluton
                    gradati_activi_in_pluton_evaluat_details.append(f"{student_display_info} - Gradat Activ aici")
                elif student.pluton == for_pluton_id: # Studentul e din acest pluton, dar gradat la altul
                    gradati_activi_din_pluton_la_alt_pluton_details.append(f"{student_display_info} - Gradat la Pl. {pluton_activitate_gradat}")
            else: # Evaluare generală (total companie/batalion) - îl considerăm prezent, detaliile sunt informative
                 # Adăugăm la o listă generală de gradați activi pentru afișare, dacă e necesar la nivel de companie/batalion
                 # Momentan, `on_duty_students_details` poate fi folosit generic pentru "nu în formație, dar prezent"
                 on_duty_students_details.append(f"{student_display_info} - {status_info['reason']}")
                 on_duty_count +=1 # Contribuie la cei "la datorie/activitate" dar nu neapărat formație

        else: # absent_permission, absent_daily_leave, absent_weekend_leave
            absent_detail = f"{student_display_info} - {status_info['reason']}"
            if status_info.get('until'): absent_detail += f" (până la {status_info['until'].strftime('%d.%m %H:%M')})"
            absent_students_details.append(absent_detail)

    efectiv_prezent_total = in_formation_count + on_duty_count + len(gradati_activi_din_pluton_la_alt_pluton_details)
    # Dacă `for_pluton_id` este setat, gradații din acel pluton dar activi la alt pluton sunt totuși prezenți în unitate.
    # Trebuie să ne asigurăm că nu sunt numărați de două ori dacă `active_duty_gradat` îi pune în `on_duty_list` la nivel general.
    # Refactorizăm:
    if for_pluton_id:
        # La nivel de pluton, Ep = în formație (include gradați activi în acel pluton) + la servicii (din acel pluton) + absenți motivat (din acel pluton)
        # Cei din pluton, dar gradați la alt pluton, sunt prezenți în companie/batalion, dar nu în formația plutonului de bază.
        # Să îi considerăm ca o categorie separată la nivel de pluton pentru claritate.
        efectiv_prezent_total = in_formation_count + on_duty_count # Cei efectiv în pluton + cei la servicii din pluton
                                                                # Gradații din pluton dar la alt pluton sunt "extra" prezenței plutonului.
    else: # Nivel companie/batalion
        efectiv_prezent_total = in_formation_count + on_duty_count # Include și gradații activi puși în on_duty_list


    efectiv_absent_total = len(absent_students_details)
    
    # Recalculare EC pentru a se potrivi cu EP + EA
    # Aceasta este o problemă dacă EC inițial nu corespunde sumei.
    # Ar trebui ca EC să fie fix, iar EP și EA să derive din el.
    # Efectiv_control este dat de students_list.count()
    # EP = in_formation + on_duty + gradati_din_pluton_activi_altundeva (dacă îi numărăm la prezenți)
    # EA = lista de absenți
    # EC = EP + EA
    # Să ajustăm EP pentru a include toți cei care nu sunt "absent_..."
    efectiv_prezent_total = efectiv_control - efectiv_absent_total


    return {
        "efectiv_control": efectiv_control,
        "efectiv_prezent_total": efectiv_prezent_total,
        "in_formation_count": in_formation_count,
        "in_formation_students_details": sorted(in_formation_students_details),
        "on_duty_count": on_duty_count, # Cei la servicii clasice
        "on_duty_students_details": sorted(on_duty_students_details),
        "gradati_activi_in_pluton_evaluat_details": sorted(gradati_activi_in_pluton_evaluat_details), # Nou
        "gradati_activi_din_pluton_la_alt_pluton_details": sorted(gradati_activi_din_pluton_la_alt_pluton_details), # Nou
        "efectiv_absent_total": efectiv_absent_total,
        "absent_students_details": sorted(absent_students_details) 
    }

@app.route('/comandant/companie/dashboard')
@login_required
def company_commander_dashboard():
    if current_user.role != 'comandant_companie': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    match = re.match(r"CmdC(\d+)", current_user.username)
    if not match: flash('Format username invalid pentru comandant companie.', 'danger'); return redirect(url_for('home'))
    company_id_str = match.group(1)
    
    now = datetime.now()
    roll_call_time = now.replace(hour=20 if now.weekday() < 4 else 22, minute=0, second=0, microsecond=0)
    
    platoons_data = {}
    # Selectăm toți studenții din companie o singură dată
    all_students_in_company = Student.query.filter_by(companie=company_id_str).all()
    
    # Grupăm studenții pe plutoane manual
    students_by_platoon = {}
    for student in all_students_in_company:
        if student.pluton not in students_by_platoon:
            students_by_platoon[student.pluton] = []
        students_by_platoon[student.pluton].append(student)

    distinct_platoon_ids = sorted(students_by_platoon.keys())

    for platoon_id_str in distinct_platoon_ids:
        # Creăm un mock query object pentru get_aggregated_presence_data
        # Aceasta este o limitare, ideal ar fi ca get_aggregated_presence_data să ia o listă
        # Dar pentru a minimiza modificările, vom filtra lista existentă
        # Acest query nu este eficient, dar păstrăm structura existentă a get_aggregated_presence_data
        students_in_platoon_query = Student.query.filter(Student.id.in_([s.id for s in students_by_platoon[platoon_id_str]]))
        platoons_data[f"Plutonul {platoon_id_str}"] = get_aggregated_presence_data(students_in_platoon_query, roll_call_time, for_pluton_id=platoon_id_str)
        
    total_company_presence = get_aggregated_presence_data(Student.query.filter_by(companie=company_id_str), roll_call_time) # Fără for_pluton_id pentru total

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
    if not match: flash(f'Format username invalid ({current_user.username}) pentru comandant batalion. Așteptat un format care conține CmdB<ID>.', 'danger'); return redirect(url_for('home'))
    battalion_id_str = match.group(1)
    now = datetime.now()
    roll_call_time = now.replace(hour=20 if now.weekday() < 4 else 22, minute=0, second=0, microsecond=0)
    
    companies_data = {}
    # Selectăm toți studenții din batalion o singură dată
    all_students_in_battalion = Student.query.filter_by(batalion=battalion_id_str).all()

    # Grupăm studenții pe companii manual
    students_by_company = {}
    for student in all_students_in_battalion:
        if student.companie not in students_by_company:
            students_by_company[student.companie] = []
        students_by_company[student.companie].append(student)

    distinct_company_ids = sorted(students_by_company.keys())

    for company_id_str_loop in distinct_company_ids:
        # Acest query nu este eficient, dar păstrăm structura existentă a get_aggregated_presence_data
        students_in_company_query = Student.query.filter(Student.id.in_([s.id for s in students_by_company[company_id_str_loop]]))
        companies_data[f"Compania {company_id_str_loop}"] = get_aggregated_presence_data(students_in_company_query, roll_call_time) # Nu pasăm for_pluton_id aici

    total_battalion_presence = get_aggregated_presence_data(Student.query.filter_by(batalion=battalion_id_str), roll_call_time)

    return render_template('battalion_commander_dashboard.html',
                           battalion_id=battalion_id_str,
                           companies_data=companies_data, 
                           total_battalion_presence=total_battalion_presence,
                           roll_call_time_str=roll_call_time.strftime('%d.%m.%Y %H:%M'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=False)
