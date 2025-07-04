from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate # Added for database migrations
from sqlalchemy.orm import joinedload
import io
from docx import Document
from docx.shared import Pt, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import os
import secrets 
from datetime import datetime, date, time, timedelta 
from sqlalchemy import func, or_, and_
import re 
from unidecode import unidecode
import json
from sqlalchemy import inspect
import pytz # Adăugat pentru fusuri orare

# Inițializare aplicație Flask
app = Flask(__name__)

# Definire fus orar pentru România
EUROPE_BUCHAREST = pytz.timezone('Europe/Bucharest')

# Funcție helper pentru a obține ora curentă localizată
def get_localized_now():
    return datetime.now(EUROPE_BUCHAREST)

# Filtru Jinja pentru a formata datetime-uri cu fusul orar local
@app.template_filter('localdatetime')
def localdatetime_filter(dt, fmt='%d-%m-%Y %H:%M:%S'):
    if not dt:
        return ""
    if dt.tzinfo is None:
        localized_dt = EUROPE_BUCHAREST.localize(dt, is_dst=None) 
    else:
        localized_dt = dt.astimezone(EUROPE_BUCHAREST)
    return localized_dt.strftime(fmt)

@app.template_filter('localtime')
def localtime_filter(t, fmt='%H:%M'):
    if not t:
        return ""
    return t.strftime(fmt)

@app.template_filter('localdate')
def localdate_filter(d, fmt='%d-%m-%Y'):
    if not d:
        return ""
    return d.strftime(fmt)

@app.context_processor
def inject_global_vars():
    return dict(get_localized_now=get_localized_now)

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev_fallback_super_secret_key_123!@#')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30) 

db = SQLAlchemy(app)
migrate = Migrate(app, db) 
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'
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
    is_platoon_graded_duty = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self): 
        graded_duty_info = " (Gradat Pluton)" if self.is_platoon_graded_duty else ""
        return f'<Student {self.grad_militar} {self.nume} {self.prenume} - Pl.{self.pluton}{graded_duty_info}>'

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='CASCADE'), nullable=False)
    start_datetime = db.Column(db.DateTime, nullable=False)
    end_datetime = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='Aprobată', nullable=False)
    destination = db.Column(db.String(255), nullable=True)
    transport_mode = db.Column(db.String(100), nullable=True)
    student = db.relationship('Student', backref=db.backref('permissions', lazy=True, cascade="all, delete-orphan"))
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('permissions_created', lazy=True))
    @property
    def is_active(self):
        now = get_localized_now()
        start_dt_aware = EUROPE_BUCHAREST.localize(self.start_datetime) if self.start_datetime.tzinfo is None else self.start_datetime.astimezone(EUROPE_BUCHAREST)
        end_dt_aware = EUROPE_BUCHAREST.localize(self.end_datetime) if self.end_datetime.tzinfo is None else self.end_datetime.astimezone(EUROPE_BUCHAREST)
        return start_dt_aware <= now <= end_dt_aware and self.status == 'Aprobată'
    @property
    def is_upcoming(self):
        now = get_localized_now()
        start_dt_aware = EUROPE_BUCHAREST.localize(self.start_datetime) if self.start_datetime.tzinfo is None else self.start_datetime.astimezone(EUROPE_BUCHAREST)
        return start_dt_aware > now and self.status == 'Aprobată'
    @property
    def is_past(self):
        now = get_localized_now()
        end_dt_aware = EUROPE_BUCHAREST.localize(self.end_datetime) if self.end_datetime.tzinfo is None else self.end_datetime.astimezone(EUROPE_BUCHAREST)
        return end_dt_aware < now or self.status == 'Anulată'

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
    def is_active(self):
        now = get_localized_now()
        start_dt_aware = EUROPE_BUCHAREST.localize(self.start_datetime)
        end_dt_aware = EUROPE_BUCHAREST.localize(self.end_datetime)
        return start_dt_aware <= now <= end_dt_aware and self.status == 'Aprobată'
    @property
    def is_upcoming(self):
        now = get_localized_now()
        start_dt_aware = EUROPE_BUCHAREST.localize(self.start_datetime)
        return start_dt_aware > now and self.status == 'Aprobată'
    @property
    def is_past(self):
        now = get_localized_now()
        end_dt_aware = EUROPE_BUCHAREST.localize(self.end_datetime)
        return end_dt_aware < now or self.status == 'Anulată'
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
    day3_selected = db.Column(db.String(10), nullable=True)
    day3_date = db.Column(db.Date, nullable=True)
    day3_start_time = db.Column(db.Time, nullable=True)
    day3_end_time = db.Column(db.Time, nullable=True)
    duminica_biserica = db.Column(db.Boolean, default=False, nullable=False) 
    reason = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='Aprobată', nullable=False)
    student = db.relationship('Student', backref=db.backref('weekend_leaves', lazy=True, cascade="all, delete-orphan"))
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('weekend_leaves_created', lazy=True))
    def get_intervals(self):
        intervals = []
        days_info = [
            (self.day1_date, self.day1_start_time, self.day1_end_time, self.day1_selected),
            (self.day2_date, self.day2_start_time, self.day2_end_time, self.day2_selected),
            (self.day3_date, self.day3_start_time, self.day3_end_time, self.day3_selected)
        ]
        for d_date, s_time, e_time, d_name in days_info:
            if d_date and s_time and e_time:
                s_dt_naive = datetime.combine(d_date, s_time)
                e_dt_naive = datetime.combine(d_date, e_time)
                if e_dt_naive < s_dt_naive: 
                    e_dt_naive += timedelta(days=1)
                s_dt_aware = EUROPE_BUCHAREST.localize(s_dt_naive)
                e_dt_aware = EUROPE_BUCHAREST.localize(e_dt_naive)
                intervals.append({"day_name": d_name, "start": s_dt_aware, "end": e_dt_aware})
        return sorted(intervals, key=lambda x: x['start'])
    @property
    def is_overall_active_or_upcoming(self):
        now = get_localized_now()
        if self.status != 'Aprobată': return False
        return any(interval["end"] >= now for interval in self.get_intervals())
    @property
    def is_any_interval_active_now(self):
        if self.status != 'Aprobată':
            return False
        now = get_localized_now()
        return any(interval["start"] <= now <= interval["end"] for interval in self.get_intervals())
    @property
    def is_overall_past(self): now = get_localized_now(); return True if self.status == 'Anulată' else not self.is_overall_active_or_upcoming
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
    def is_active(self):
        now = get_localized_now()
        start_dt_aware = EUROPE_BUCHAREST.localize(self.start_datetime) if self.start_datetime.tzinfo is None else self.start_datetime.astimezone(EUROPE_BUCHAREST)
        end_dt_aware = EUROPE_BUCHAREST.localize(self.end_datetime) if self.end_datetime.tzinfo is None else self.end_datetime.astimezone(EUROPE_BUCHAREST)
        return start_dt_aware <= now <= end_dt_aware
    @property
    def is_upcoming(self):
        now = get_localized_now()
        start_dt_aware = EUROPE_BUCHAREST.localize(self.start_datetime) if self.start_datetime.tzinfo is None else self.start_datetime.astimezone(EUROPE_BUCHAREST)
        return start_dt_aware > now
    @property
    def is_past(self):
        now = get_localized_now()
        end_dt_aware = EUROPE_BUCHAREST.localize(self.end_datetime) if self.end_datetime.tzinfo is None else self.end_datetime.astimezone(EUROPE_BUCHAREST)
        return end_dt_aware < now

class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    action_type = db.Column(db.String(50), nullable=False) 
    target_model = db.Column(db.String(100), nullable=True) 
    target_id = db.Column(db.Integer, nullable=True) 
    details_before = db.Column(db.Text, nullable=True) 
    details_after = db.Column(db.Text, nullable=True)  
    description = db.Column(db.Text, nullable=True) 
    user = db.relationship('User', backref=db.backref('action_logs', lazy='dynamic')) 

    def __repr__(self):
        user_desc = f"User {self.user_id}" if self.user_id else "System/UnknownUser"
        target_desc = f" on {self.target_model}({self.target_id})" if self.target_model and self.target_id else ""
        description_desc = f" - {self.description[:50]}..." if self.description else ""
        return f'<ActionLog {self.timestamp.strftime("%Y-%m-%d %H:%M:%S")} - {user_desc} - {self.action_type}{target_desc}{description_desc}>'

class UpdateTopic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('update_topics_authored', lazy=True))
    is_pinned = db.Column(db.Boolean, default=False, nullable=False)
    status_color = db.Column(db.String(20), nullable=True)
    is_visible = db.Column(db.Boolean, default=True, nullable=False) 

    def __repr__(self):
        return f'<UpdateTopic {self.id}: {self.title[:50]}>'

@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))

def init_db():
    with app.app_context():
        db.create_all() 
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin', is_first_login=False); admin.set_password('admin123')
            db.session.add(admin); db.session.commit(); print("Admin user created.")
        else: print("Admin user already exists.")
        print("DB initialized.")

def get_next_friday(start_date=None):
    d = start_date if start_date else get_localized_now().date() 
    while d.weekday() != 4: d += timedelta(days=1)
    return d

def get_upcoming_fridays(num_fridays=5):
    fridays_list = []
    today = get_localized_now().date() 
    days_from_friday = today.weekday() - 4 
    initial_friday = today - timedelta(days=days_from_friday)
    for i in range(num_fridays):
        loop_friday = initial_friday + timedelta(weeks=i)
        fridays_list.append({
            'value': loop_friday.strftime('%Y-%m-%d'),
            'display': loop_friday.strftime('%d %B %Y') + f" (Vineri)"
        })
    if today.weekday() < 3: 
        previous_friday = initial_friday - timedelta(weeks=1)
        if not any(f['value'] == previous_friday.strftime('%Y-%m-%d') for f in fridays_list):
            fridays_list.insert(0, {
                'value': previous_friday.strftime('%Y-%m-%d'),
                'display': previous_friday.strftime('%d %B %Y') + f" (Vineri)"
            })
            if len(fridays_list) > num_fridays: 
                fridays_list.pop()
    return fridays_list

def validate_daily_leave_times(start_time_obj, end_time_obj, leave_date_obj):
    if leave_date_obj.weekday() > 3: return False, "Învoirile zilnice sunt permise doar de Luni până Joi."
    if start_time_obj == end_time_obj: return False, "Ora de început și de sfârșit nu pot fi identice."
    return True, "Valid"

def check_leave_conflict(student_id, leave_start_dt, leave_end_dt, existing_leave_id=None, leave_type=None):
    blocking_services = ['GSS', 'Intervenție']
    conflicting_service = ServiceAssignment.query.filter(
        ServiceAssignment.student_id == student_id,
        ServiceAssignment.service_type.in_(blocking_services),
        ServiceAssignment.start_datetime < leave_end_dt,
        ServiceAssignment.end_datetime > leave_start_dt
    ).first()
    if conflicting_service:
        return f"serviciu ({conflicting_service.service_type}) pe {conflicting_service.service_date.strftime('%d-%m-%Y')}"
    query_permissions = Permission.query.filter(
        Permission.student_id == student_id, Permission.status == 'Aprobată',
        Permission.start_datetime < leave_end_dt, Permission.end_datetime > leave_start_dt
    )
    if leave_type == 'permission' and existing_leave_id:
        query_permissions = query_permissions.filter(Permission.id != existing_leave_id)
    if query_permissions.first():
        if not (leave_type == 'permission' and existing_leave_id): return "o permisie existentă"
    daily_leaves_query = DailyLeave.query.filter(DailyLeave.student_id == student_id, DailyLeave.status == 'Aprobată')
    if leave_type == 'daily_leave' and existing_leave_id:
        daily_leaves_query = daily_leaves_query.filter(DailyLeave.id != existing_leave_id)
    for dl in daily_leaves_query.all():
        if dl.start_datetime < leave_end_dt and dl.end_datetime > leave_start_dt:
            if not (leave_type == 'daily_leave' and existing_leave_id and dl.id == existing_leave_id): return f"o învoire zilnică pe {dl.leave_date.strftime('%d.%m')}"
    weekend_leaves_query = WeekendLeave.query.filter(WeekendLeave.student_id == student_id, WeekendLeave.status == 'Aprobată')
    if leave_type == 'weekend_leave' and existing_leave_id:
        weekend_leaves_query = weekend_leaves_query.filter(WeekendLeave.id != existing_leave_id)
    for wl in weekend_leaves_query.all():
        for interval in wl.get_intervals():
            if interval['start'] < leave_end_dt and interval['end'] > leave_start_dt:
                if not (leave_type == 'weekend_leave' and existing_leave_id and wl.id == existing_leave_id): return f"o învoire de weekend ({interval['day_name']})"
    return None

def check_service_conflict_for_student(student_id, service_start_dt, service_end_dt, service_type, current_service_id=None):
    if service_type in ['Intervenție', 'GSS']:
        conflicting_permission = Permission.query.filter(
            Permission.student_id == student_id, Permission.status == 'Aprobată',
            Permission.start_datetime < service_end_dt, Permission.end_datetime > service_start_dt
        ).first()
        if conflicting_permission: return f"permisie ({conflicting_permission.start_datetime.strftime('%d.%m %H:%M')} - {conflicting_permission.end_datetime.strftime('%d.%m %H:%M')})"
        daily_leaves = DailyLeave.query.filter(DailyLeave.student_id == student_id, DailyLeave.status == 'Aprobată').all()
        for dl in daily_leaves:
            if dl.start_datetime < service_end_dt and dl.end_datetime > service_start_dt: return f"învoire zilnică ({dl.leave_date.strftime('%d.%m')} {dl.start_time.strftime('%H:%M')}-{dl.end_time.strftime('%H:%M')})"
        weekend_leaves = WeekendLeave.query.filter(WeekendLeave.student_id == student_id, WeekendLeave.status == 'Aprobată').all()
        for wl in weekend_leaves:
            for interval in wl.get_intervals():
                if interval['start'] < service_end_dt and interval['end'] > service_start_dt: return f"învoire de weekend ({interval['day_name']} {interval['start'].strftime('%H:%M')}-{interval['end'].strftime('%H:%M')})"
    query_other_services = ServiceAssignment.query.filter(
        ServiceAssignment.student_id == student_id,
        ServiceAssignment.start_datetime < service_end_dt, ServiceAssignment.end_datetime > service_start_dt
    )
    if current_service_id: query_other_services = query_other_services.filter(ServiceAssignment.id != current_service_id)
    conflicting_other_service = query_other_services.first()
    if conflicting_other_service: return f"alt serviciu ({conflicting_other_service.service_type} pe {conflicting_other_service.service_date.strftime('%d.%m')})"
    return None

def model_to_dict(instance, exclude_fields=None):
    if not instance:
        return {}
    default_exclude = ['_sa_instance_state', 'password_hash', 'personal_code_hash', 'unique_code'] 
    fields_to_exclude = set(default_exclude)
    if exclude_fields:
        fields_to_exclude.update(exclude_fields)
    data = {}
    for c in inspect(instance).mapper.column_attrs:
        if c.key not in fields_to_exclude:
            val = getattr(instance, c.key)
            if isinstance(val, (datetime, date, time)):
                data[c.key] = val.isoformat()
            else:
                data[c.key] = val
    return data

def log_action(action_type, target_model_name=None, target_id=None, details_before_dict=None, details_after_dict=None, description=None, user_override=None):
    try:
        log = ActionLog(action_type=action_type)
        acting_user = user_override
        if not acting_user and hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            acting_user = current_user
        if acting_user:
            log.user_id = acting_user.id
        log.target_model = target_model_name
        log.target_id = int(target_id) if target_id is not None else None 
        if details_before_dict:
            log.details_before = json.dumps(details_before_dict, ensure_ascii=False, default=str)
        if details_after_dict:
            log.details_after = json.dumps(details_after_dict, ensure_ascii=False, default=str)
        log.description = description
        db.session.add(log)
    except Exception as e:
        app.logger.error(f"AUDIT LOGGING FAILED for action '{action_type}': {str(e)}")

@app.route('/')
def home():
    total_students = 0; total_users = 0; total_volunteer_activities = 0
    try:
        total_students = Student.query.count()
        total_users = User.query.filter(User.role != 'admin').count()
        total_volunteer_activities = VolunteerActivity.query.count()
    except Exception as e: pass
    return render_template('home.html', total_students=total_students, total_users=total_users, total_volunteer_activities=total_volunteer_activities)

@app.route('/updates')
@login_required 
def public_updates_page():
    page = request.args.get('page', 1, type=int)
    per_page = 10 
    updates_pagination = UpdateTopic.query.filter_by(is_visible=True)\
        .order_by(UpdateTopic.is_pinned.desc(), UpdateTopic.updated_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    return render_template('public_updates.html', updates_pagination=updates_pagination, title="Anunțuri")

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        login_code = request.form.get('login_code')
        user_by_unique_code = User.query.filter_by(unique_code=login_code).first()
        if user_by_unique_code:
            if user_by_unique_code.is_first_login:
                login_user(user_by_unique_code, remember=True)
                log_action("USER_FIRST_LOGIN_SUCCESS", target_model_name="User", target_id=user_by_unique_code.id,
                           description=f"User {user_by_unique_code.username} first login with unique code. IP: {request.remote_addr}",
                           user_override=user_by_unique_code)
                db.session.commit()
                flash('Autentificare reușită! Setează-ți codul personal.', 'info')
                return redirect(url_for('set_personal_code'))
            else:
                log_action("USER_LOGIN_FAIL_UNIQUE_CODE_USED", target_model_name="User", target_id=user_by_unique_code.id,
                           description=f"Attempt to use already used unique code for user {user_by_unique_code.username}. IP: {request.remote_addr}")
                db.session.commit()
                flash('Acest cod unic a fost deja folosit pentru prima autentificare. Te rugăm folosește codul personal setat.', 'warning')
                return redirect(url_for('user_login'))
        users_non_admin = User.query.filter(User.role != 'admin').all()
        user_by_personal_code = next((u for u in users_non_admin if u.personal_code_hash and u.check_personal_code(login_code)), None)
        if user_by_personal_code:
            if user_by_personal_code.is_first_login: 
                log_action("USER_LOGIN_FAIL_CONFIG_ERROR", target_model_name="User", target_id=user_by_personal_code.id,
                           description=f"User {user_by_personal_code.username} attempted login with personal code but is_first_login is true. IP: {request.remote_addr}")
                db.session.commit()
                flash('Eroare de configurare cont. Contactează administratorul.', 'danger')
                return redirect(url_for('user_login'))
            login_user(user_by_personal_code, remember=True)
            log_action("USER_LOGIN_SUCCESS", target_model_name="User", target_id=user_by_personal_code.id,
                       description=f"User {user_by_personal_code.username} login with personal code. IP: {request.remote_addr}",
                       user_override=user_by_personal_code)
            db.session.commit()
            flash('Autentificare reușită!', 'success')
            return redirect(url_for('dashboard'))
        log_action("USER_LOGIN_FAIL_INVALID_CODE", description=f"Invalid/Expired login code provided: '{login_code[:20]}...'. IP: {request.remote_addr}")
        db.session.commit()
        flash('Cod de autentificare invalid sau expirat.', 'danger')
        return redirect(url_for('user_login'))
    return render_template('user_login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, role='admin').first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            log_action("ADMIN_LOGIN_SUCCESS", target_model_name="User", target_id=user.id,
                       description=f"Admin user {user.username} logged in. IP: {request.remote_addr}",
                       user_override=user)
            db.session.commit()
            flash('Autentificare admin reușită!', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_action("ADMIN_LOGIN_FAIL", description=f"Failed admin login attempt for username '{username}'. IP: {request.remote_addr}")
            db.session.commit()
            flash('Nume de utilizator sau parolă admin incorecte.', 'danger')
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/logout')
@login_required
def logout():
    user_id_logged_out = current_user.id
    username_logged_out = current_user.username
    logout_user()
    log_action("USER_LOGOUT", target_model_name="User", target_id=user_id_logged_out,
               description=f"User {username_logged_out} logged out. IP: {request.remote_addr}")
    db.session.commit()
    flash('Ai fost deconectat.', 'success')
    return redirect(url_for('home'))

@app.route('/set_personal_code', methods=['GET', 'POST'])
@login_required
def set_personal_code():
    if not current_user.is_first_login:
        flash('Codul personal a fost deja setat.', 'info')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        personal_code = request.form.get('personal_code')
        confirm_personal_code = request.form.get('confirm_personal_code')
        if not personal_code or len(personal_code) < 4:
            flash('Codul personal trebuie să aibă minim 4 caractere.', 'warning')
            return redirect(url_for('set_personal_code'))
        if personal_code != confirm_personal_code:
            flash('Codurile personale nu se potrivesc.', 'warning')
            return redirect(url_for('set_personal_code'))
        try:
            details_before = {"is_first_login": current_user.is_first_login, "personal_code_hash_exists": current_user.personal_code_hash is not None}
            current_user.set_personal_code(personal_code) 
            details_after = model_to_dict(current_user, exclude_fields=['password_hash', 'unique_code']) 
            details_after["personal_code_hash_exists"] = True 
            log_action("USER_SET_PERSONAL_CODE_SUCCESS", target_model_name="User", target_id=current_user.id,
                       details_before_dict=details_before, details_after_dict=details_after,
                       description=f"User {current_user.username} set personal code. IP: {request.remote_addr}")
            db.session.commit() 
            flash_message = 'Codul personal a fost setat cu succes. Te rugăm să te autentifici din nou folosind noul cod.'
            user_id_logged_out = current_user.id 
            username_logged_out = current_user.username
            logout_user()
            log_action("USER_LOGOUT_POST_SET_CODE", target_model_name="User", target_id=user_id_logged_out,
                       description=f"User {username_logged_out} automatically logged out after setting personal code. IP: {request.remote_addr}")
            db.session.commit() 
            flash(flash_message, 'success')
            return redirect(url_for('user_login'))
        except Exception as e:
            db.session.rollback()
            flash_msg = f'A apărut o eroare la setarea codului personal: {str(e)}'
            flash(flash_msg, 'danger')
            try:
                log_action("USER_SET_PERSONAL_CODE_FAIL", target_model_name="User", target_id=current_user.id,
                           description=f"Failed to set personal code for user {current_user.username}. Error: {str(e)}. IP: {request.remote_addr}")
                db.session.commit()
            except Exception as log_e:
                app.logger.error(f"CRITICAL: Failed to commit failure log for USER_SET_PERSONAL_CODE_FAIL: {str(log_e)}")
            return redirect(url_for('set_personal_code'))
    return render_template('set_personal_code.html')

# --- Management Studenți ---
@app.route('/gradat/students')
@app.route('/admin/students')
@login_required
def list_students():
    is_admin_view = current_user.role == 'admin' and request.path.startswith('/admin/')
    page = request.args.get('page', 1, type=int)
    per_page = 15

    students_query = Student.query
    batalioane, companii, plutoane = [], [], []
    if is_admin_view or current_user.role in ['comandant_companie', 'comandant_batalion']:
        all_students_for_filters_q = Student.query
        if current_user.role == 'comandant_companie':
            company_id = _get_commander_unit_id(current_user.username, "CmdC")
            if company_id: all_students_for_filters_q = all_students_for_filters_q.filter(Student.companie == company_id)
        elif current_user.role == 'comandant_batalion':
            battalion_id = _get_commander_unit_id(current_user.username, "CmdB")
            if battalion_id: all_students_for_filters_q = all_students_for_filters_q.filter(Student.batalion == battalion_id)

        all_students_for_filters = all_students_for_filters_q.with_entities(Student.batalion, Student.companie, Student.pluton).distinct().all()
        batalioane = sorted(list(set(s.batalion for s in all_students_for_filters if s.batalion)))
        companii = sorted(list(set(s.companie for s in all_students_for_filters if s.companie)))
        plutoane = sorted(list(set(s.pluton for s in all_students_for_filters if s.pluton)))

    search_term = request.args.get('search', '').strip()
    filter_batalion = request.args.get('batalion', '').strip()
    filter_companie = request.args.get('companie', '').strip()
    filter_pluton = request.args.get('pluton', '').strip()

    if is_admin_view:
        students_query = students_query.options(joinedload(Student.creator)) 
        if filter_batalion: students_query = students_query.filter(Student.batalion == filter_batalion)
        if filter_companie: students_query = students_query.filter(Student.companie == filter_companie)
        if filter_pluton: students_query = students_query.filter(Student.pluton == filter_pluton)
        students_query = students_query.order_by(Student.batalion, Student.companie, Student.pluton, Student.nume, Student.prenume)
    elif current_user.role == 'gradat':
        students_query = students_query.filter_by(created_by_user_id=current_user.id)
        students_query = students_query.order_by(Student.nume, Student.prenume)
    elif current_user.role == 'comandant_companie':
        company_id = _get_commander_unit_id(current_user.username, "CmdC")
        if company_id:
            students_query = students_query.filter(Student.companie == company_id)
            if filter_pluton: students_query = students_query.filter(Student.pluton == filter_pluton) 
            students_query = students_query.order_by(Student.pluton, Student.nume, Student.prenume)
        else:
            flash('ID Companie nevalid pentru comandant.', 'danger')
            students_query = students_query.filter(Student.id == -1) 
    elif current_user.role == 'comandant_batalion':
        battalion_id = _get_commander_unit_id(current_user.username, "CmdB")
        if battalion_id:
            students_query = students_query.filter(Student.batalion == battalion_id)
            if filter_companie: students_query = students_query.filter(Student.companie == filter_companie) 
            if filter_pluton: students_query = students_query.filter(Student.pluton == filter_pluton)       
            students_query = students_query.order_by(Student.companie, Student.pluton, Student.nume, Student.prenume)
        else:
            flash('ID Batalion nevalid pentru comandant.', 'danger')
            students_query = students_query.filter(Student.id == -1) 
    else: 
        flash('Rol utilizator necunoscut pentru listarea studenților.', 'danger')
        return redirect(url_for('dashboard'))

    if search_term:
        processed_search_term = unidecode(search_term.lower())
        search_pattern = f"%{processed_search_term}%"
        students_query = students_query.filter(or_(
            func.lower(Student.nume).ilike(search_pattern),
            func.lower(Student.prenume).ilike(search_pattern),
            func.lower(Student.id_unic_student).ilike(search_pattern)
        ))

    students_pagination = students_query.paginate(page=page, per_page=per_page, error_out=False)
    students_list = students_pagination.items

    view_title = "Listă Studenți"
    if is_admin_view: view_title = "Listă Generală Studenți (Admin)"
    elif current_user.role == 'gradat': view_title = "Listă Studenți Gestionați"
    elif current_user.role == 'comandant_companie': view_title = f"Listă Studenți Compania {_get_commander_unit_id(current_user.username, 'CmdC') or 'N/A'}"
    elif current_user.role == 'comandant_batalion': view_title = f"Listă Studenți Batalionul {_get_commander_unit_id(current_user.username, 'CmdB') or 'N/A'}"

    return render_template('list_students.html',
                           students=students_list,
                           students_pagination=students_pagination,
                           is_admin_view=is_admin_view, 
                           search_term=search_term,
                           filter_batalion=filter_batalion,
                           filter_companie=filter_companie,
                           filter_pluton=filter_pluton,
                           batalioane=batalioane,
                           companii=companii,
                           plutoane=plutoane,
                           title=view_title)

@app.route('/gradat/student/add', methods=['GET', 'POST'])
@login_required
def add_student():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        form = request.form
        nume = form.get('nume','').strip()
        prenume = form.get('prenume','').strip()
        grad_militar = form.get('grad_militar','').strip()
        id_unic_student_form = form.get('id_unic_student','').strip() or None
        gender = form.get('gender')
        pluton = form.get('pluton','').strip()
        companie = form.get('companie','').strip()
        batalion = form.get('batalion','').strip()
        is_platoon_graded_duty_val = 'is_platoon_graded_duty' in request.form

        if not all([nume, prenume, grad_militar, gender, pluton, companie, batalion]):
            flash('Toate câmpurile marcate cu * sunt obligatorii (inclusiv genul).', 'warning')
            return render_template('add_edit_student.html', form_title="Adăugare Student Nou", student=None, genders=GENDERS, form_data=request.form)

        if id_unic_student_form and Student.query.filter_by(id_unic_student=id_unic_student_form).first():
            flash(f"ID unic student '{id_unic_student_form}' există deja.", 'warning')
            return render_template('add_edit_student.html', form_title="Adăugare Student Nou", student=None, genders=GENDERS, form_data=request.form)

        if gender not in GENDERS:
            flash('Valoare invalidă pentru gen.', 'warning')
            return render_template('add_edit_student.html', form_title="Adăugare Student Nou", student=None, genders=GENDERS, form_data=request.form)

        new_student = Student(
            nume=nume,
            prenume=prenume,
            grad_militar=grad_militar,
            id_unic_student=id_unic_student_form,
            gender=gender,
            pluton=pluton,
            companie=companie,
            batalion=batalion,
            is_platoon_graded_duty=is_platoon_graded_duty_val,
            created_by_user_id=current_user.id
        )
        db.session.add(new_student)
        try:
            db.session.flush() 
            log_action("CREATE_STUDENT_SUCCESS", target_model_name="Student", target_id=new_student.id,
                       details_after_dict=model_to_dict(new_student),
                       description=f"User {current_user.username} added student {new_student.grad_militar} {new_student.nume} {new_student.prenume}.")
            db.session.commit()
            flash(f'Studentul {new_student.grad_militar} {new_student.nume} {new_student.prenume} a fost adăugat!', 'success')
            return redirect(url_for('list_students'))
        except Exception as e:
            db.session.rollback()
            flash_msg = f'Eroare la salvarea studentului: {str(e)}'
            flash(flash_msg, 'danger')
            try:
                attempted_data = {
                    "nume": nume, "prenume": prenume, "grad_militar": grad_militar,
                    "id_unic_student": id_unic_student_form, "gender": gender, "pluton": pluton,
                    "companie": companie, "batalion": batalion,
                    "is_platoon_graded_duty": is_platoon_graded_duty_val,
                    "created_by_user_id": current_user.id
                }
                log_action("CREATE_STUDENT_FAIL", target_model_name="Student",
                           description=f"User {current_user.username} failed to add student. Error: {str(e)}",
                           details_after_dict=attempted_data) 
                db.session.commit()
            except Exception as log_e:
                app.logger.error(f"CRITICAL: Failed to commit failure log for CREATE_STUDENT_FAIL: {str(log_e)}")
            return render_template('add_edit_student.html', form_title="Adăugare Student Nou", student=None, genders=GENDERS, form_data=request.form)

    return render_template('add_edit_student.html', form_title="Adăugare Student Nou", student=None, genders=GENDERS, form_data=None)

@app.route('/gradat/students/edit/<int:student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    s_edit = Student.query.filter_by(id=student_id, created_by_user_id=current_user.id).first_or_404()
    details_before_edit = model_to_dict(s_edit) 

    if request.method == 'POST':
        form = request.form
        s_edit.nume = form.get('nume','').strip()
        s_edit.prenume = form.get('prenume','').strip()
        s_edit.grad_militar = form.get('grad_militar','').strip()
        s_edit.pluton = form.get('pluton','').strip()
        s_edit.companie = form.get('companie','').strip()
        s_edit.batalion = form.get('batalion','').strip()
        s_edit.gender = form.get('gender')
        s_edit.is_platoon_graded_duty = 'is_platoon_graded_duty' in request.form
        new_id_unic = form.get('id_unic_student','').strip() or None

        if not all([s_edit.nume, s_edit.prenume, s_edit.grad_militar, s_edit.pluton, s_edit.companie, s_edit.batalion, s_edit.gender]):
            flash('Toate câmpurile marcate cu * sunt obligatorii (inclusiv genul).', 'warning')
            return render_template('add_edit_student.html', form_title=f"Editare Student: {details_before_edit.get('grad_militar','')} {details_before_edit.get('nume','')}", student=s_edit, genders=GENDERS, form_data=request.form)

        if s_edit.gender not in GENDERS:
            flash('Valoare invalidă pentru gen.', 'warning')
            return render_template('add_edit_student.html', form_title=f"Editare Student: {details_before_edit.get('grad_militar','')} {details_before_edit.get('nume','')}", student=s_edit, genders=GENDERS, form_data=request.form)

        if new_id_unic and new_id_unic != s_edit.id_unic_student and Student.query.filter(Student.id_unic_student==new_id_unic, Student.id != s_edit.id).first():
            flash(f"Alt student cu ID unic '{new_id_unic}' există deja.", 'warning')
            return render_template('add_edit_student.html', form_title=f"Editare Student: {details_before_edit.get('grad_militar','')} {details_before_edit.get('nume','')}", student=s_edit, genders=GENDERS, form_data=request.form)

        s_edit.id_unic_student = new_id_unic

        try:
            details_after_edit = model_to_dict(s_edit)
            log_action("UPDATE_STUDENT_SUCCESS", target_model_name="Student", target_id=s_edit.id,
                       details_before_dict=details_before_edit, details_after_dict=details_after_edit,
                       description=f"User {current_user.username} updated student {s_edit.grad_militar} {s_edit.nume} {s_edit.prenume}.")
            db.session.commit()
            flash(f'Studentul {s_edit.grad_militar} {s_edit.nume} {s_edit.prenume} a fost actualizat!', 'success')
            return redirect(url_for('list_students'))
        except Exception as e:
            db.session.rollback()
            flash_msg = f'Eroare la actualizarea studentului: {str(e)}'
            flash(flash_msg, 'danger')
            try:
                log_action("UPDATE_STUDENT_FAIL", target_model_name="Student", target_id=student_id,
                           details_before_dict=details_before_edit, 
                           description=f"User {current_user.username} failed to update student ID {student_id}. Error: {str(e)}")
                db.session.commit()
            except Exception as log_e:
                app.logger.error(f"CRITICAL: Failed to commit failure log for UPDATE_STUDENT_FAIL: {str(log_e)}")
            return render_template('add_edit_student.html', form_title=f"Editare Student: {details_before_edit.get('grad_militar','')} {details_before_edit.get('nume','')} {details_before_edit.get('prenume','')}", student=s_edit, genders=GENDERS, form_data=request.form)

    return render_template('add_edit_student.html', form_title=f"Editare Student: {s_edit.grad_militar} {s_edit.nume} {s_edit.prenume}", student=s_edit, genders=GENDERS, form_data=s_edit)

@app.route('/gradat/students/bulk_import', methods=['POST'], endpoint='gradat_bulk_import_students')
@login_required
def bulk_import_students():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('list_students'))

    student_bulk_data = request.form.get('student_bulk_data', '').strip()
    if not student_bulk_data:
        flash('Nu au fost furnizate date pentru import.', 'warning')
        return redirect(url_for('list_students'))

    lines = student_bulk_data.splitlines()
    added_count = 0
    error_count = 0
    error_details = []

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 7: 
            error_details.append(f"Linia {i+1} ('{line}'): Format incorect - prea puține câmpuri.")
            error_count += 1
            continue
        try:
            batalion = parts[-1]
            companie = parts[-2]
            pluton = parts[-3]
            gender_input_original = parts[-4]
            gender_input_upper = gender_input_original.upper()

            gender_db_val = None
            if gender_input_upper == "M":
                gender_db_val = "M"
            elif gender_input_upper == "F":
                gender_db_val = "F"
            elif gender_input_upper in [g.upper() for g in GENDERS]:
                gender_db_val = next(g_val for g_val in GENDERS if g_val.upper() == gender_input_upper)
            else:
                error_details.append(f"Linia {i+1} ('{line}'): Gen '{gender_input_original}' invalid. Folosiți M, F sau Nespecificat.")
                error_count += 1
                continue
            name_rank_parts = parts[:-4]
            if len(name_rank_parts) < 3: 
                error_details.append(f"Linia {i+1} ('{line}'): Format insuficient pentru Grad, Nume, Prenume.")
                error_count += 1
                continue

            prenume = name_rank_parts[-1]
            nume = name_rank_parts[-2]
            grad_militar = " ".join(name_rank_parts[:-2])

            if not all([grad_militar, nume, prenume, pluton, companie, batalion]):
                error_details.append(f"Linia {i+1} ('{line}'): Unul sau mai multe câmpuri obligatorii lipsesc după parsare.")
                error_count += 1
                continue
            existing_student_check = Student.query.filter_by(
                nume=nume, prenume=prenume, grad_militar=grad_militar,
                pluton=pluton, companie=companie, batalion=batalion,
                created_by_user_id=current_user.id
            ).first()

            if existing_student_check:
                error_details.append(f"Linia {i+1} ('{line}'): Student similar există deja (verificare nume, grad, unitate).")
                error_count += 1
                continue
            new_student = Student(
                grad_militar=grad_militar,
                nume=nume,
                prenume=prenume,
                gender=gender_db_val,
                pluton=pluton,
                companie=companie,
                batalion=batalion,
                created_by_user_id=current_user.id,
                is_platoon_graded_duty=False 
            )
            db.session.add(new_student)
            added_count += 1
        except IndexError:
            error_details.append(f"Linia {i+1} ('{line}'): Format incorect - eroare la extragerea câmpurilor.")
            error_count += 1
            continue
        except Exception as e:
            error_details.append(f"Linia {i+1} ('{line}'): Eroare neașteptată la procesare - {str(e)}.")
            error_count += 1
            db.session.rollback() 
            continue

    if added_count > 0:
        try:
            db.session.commit()
            flash(f'{added_count} studenți au fost adăugați cu succes.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la salvarea studenților în baza de date: {str(e)}', 'danger')
            error_count += added_count 
            added_count = 0

    if error_count > 0:
        flash(f'{error_count} linii nu au putut fi procesate sau au generat erori.', 'danger')
        if error_details:
            flash_detail_msg = "Detalii erori:<br>" + "<br>".join(error_details)
            if len(flash_detail_msg) > 500: 
                flash_detail_msg = flash_detail_msg[:497] + "..."
            flash(flash_detail_msg, 'warning')

    return redirect(url_for('list_students'))

@app.route('/gradat/delete_student/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if current_user.role not in ['admin', 'gradat']: flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    student_to_delete = Student.query.get_or_404(student_id)
    if current_user.role == 'gradat' and student_to_delete.created_by_user_id != current_user.id:
        flash('Nu puteți șterge studenți care nu vă sunt arondați.', 'danger')
        return redirect(url_for('list_students'))

    if current_user.role == 'admin' and hasattr(student_to_delete, 'creator') and student_to_delete.creator and student_to_delete.creator.username != current_user.username :
        flash(f'Atenție: Ștergeți un student ({student_to_delete.nume} {student_to_delete.prenume}) care aparține gradatului {student_to_delete.creator.username}.', 'warning')

    details_before_delete = model_to_dict(student_to_delete)
    student_name_for_flash = f"{student_to_delete.grad_militar} {student_to_delete.nume} {student_to_delete.prenume}"

    try:
        db.session.delete(student_to_delete)
        log_action("DELETE_STUDENT_SUCCESS", target_model_name="Student", target_id=student_id, 
                   details_before_dict=details_before_delete,
                   description=f"User {current_user.username} deleted student {student_name_for_flash} (ID: {student_id}).")
        db.session.commit()
        flash(f'Studentul {student_name_for_flash} și toate datele asociate au fost șterse.', 'success')
    except Exception as e:
        db.session.rollback()
        flash_msg = f'Eroare la ștergerea studentului: {str(e)}'
        flash(flash_msg, 'danger')
        try:
            log_action("DELETE_STUDENT_FAIL", target_model_name="Student", target_id=student_id,
                       details_before_dict=details_before_delete,
                       description=f"User {current_user.username} failed to delete student {student_name_for_flash} (ID: {student_id}). Error: {str(e)}")
            db.session.commit()
        except Exception as log_e:
            app.logger.error(f"CRITICAL: Failed to commit failure log for DELETE_STUDENT_FAIL: {str(log_e)}")

    return redirect(url_for('list_students'))

# --- Rute pentru Permisii ---
@app.route('/gradat/permissions')
@login_required
def list_permissions():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    student_id_tuples = db.session.query(Student.id).filter_by(created_by_user_id=current_user.id).all()
    student_ids_managed_by_gradat = [s[0] for s in student_id_tuples]
    if not student_ids_managed_by_gradat:
        return render_template('list_permissions.html', active_permissions=[], upcoming_permissions=[], past_permissions=[], title="Listă Permisii")

    now = get_localized_now() 
    base_query = Permission.query.options(joinedload(Permission.student)).filter(Permission.student_id.in_(student_ids_managed_by_gradat))

    active_permissions = base_query.filter(
        Permission.status == 'Aprobată',
        Permission.start_datetime <= now,
        Permission.end_datetime >= now
    ).order_by(Permission.start_datetime).all()

    upcoming_permissions = base_query.filter(
        Permission.status == 'Aprobată',
        Permission.start_datetime > now
    ).order_by(Permission.start_datetime).all()
    
    active_upcoming_ids = [p.id for p in active_permissions] + [p.id for p in upcoming_permissions]

    past_permissions_query = Permission.query.options(joinedload(Permission.student)).filter(Permission.student_id.in_(student_ids_managed_by_gradat))
    if active_upcoming_ids:
        past_permissions_query = past_permissions_query.filter(Permission.id.notin_(active_upcoming_ids))

    past_permissions = past_permissions_query.order_by(Permission.end_datetime.desc(), Permission.start_datetime.desc()).limit(30).all()

    return render_template('list_permissions.html', active_permissions=active_permissions, upcoming_permissions=upcoming_permissions, past_permissions=past_permissions, title="Listă Permisii")

@app.route('/gradat/permission/add', methods=['GET', 'POST'])
@app.route('/gradat/permission/edit/<int:permission_id>', methods=['GET', 'POST'])
@login_required
def add_edit_permission(permission_id=None):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    form_title = "Adaugă Permisie Nouă"; permission = None
    if permission_id:
        permission = Permission.query.get_or_404(permission_id)
        student_of_permission = Student.query.get(permission.student_id)
        if not student_of_permission or student_of_permission.created_by_user_id != current_user.id: flash('Acces neautorizat la această permisie.', 'danger'); return redirect(url_for('list_permissions'))
        form_title = f"Editare Permisie: {student_of_permission.grad_militar} {student_of_permission.nume} {student_of_permission.prenume}"
    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        start_datetime_str = request.form.get('start_datetime')
        end_datetime_str = request.form.get('end_datetime')
        destination = request.form.get('destination', '').strip()
        transport_mode = request.form.get('transport_mode', '').strip()
        reason = request.form.get('reason', '').strip()

        current_form_data_post = request.form 

        if not student_id or not start_datetime_str or not end_datetime_str:
            flash('Studentul, data de început și data de sfârșit sunt obligatorii.', 'warning')
            return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)
        try:
            start_dt = datetime.strptime(start_datetime_str, '%Y-%m-%dT%H:%M')
            end_dt = datetime.strptime(end_datetime_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Format dată/oră invalid.', 'danger')
            return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)

        if end_dt <= start_dt:
            flash('Data de sfârșit trebuie să fie după data de început.', 'warning')
            return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)

        student_to_check = db.session.get(Student, int(student_id)) 
        if not student_to_check or student_to_check.created_by_user_id != current_user.id:
            flash('Student invalid sau nu vă aparține.', 'danger')
            return render_template('add_edit_permission.html', form_title=form_title, permission=None, students=students_managed, form_data=current_form_data_post)

        conflicting_service = ServiceAssignment.query.filter(ServiceAssignment.student_id == student_id, ServiceAssignment.service_type == 'Intervenție', ServiceAssignment.start_datetime < end_dt, ServiceAssignment.end_datetime > start_dt).first()
        if conflicting_service:
            flash(f'Studentul {student_to_check.nume} {student_to_check.prenume} este în serviciu de "Intervenție" și nu poate primi permisie.', 'danger')
            return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)

        general_conflict_msg = check_leave_conflict(student_id, start_dt, end_dt, 'permission', permission.id if permission else None)
        if general_conflict_msg:
            flash(f"Conflict detectat: Studentul are deja {general_conflict_msg}.", 'danger')
            return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)

        action_description_prefix = f"User {current_user.username}"
        log_details_before = None
        original_student_name_for_log = student_to_check.nume + " " + student_to_check.prenume

        if permission: 
            log_details_before = model_to_dict(permission)
            permission.student_id = int(student_id)
            permission.start_datetime = start_dt
            permission.end_datetime = end_dt
            permission.destination = destination
            permission.transport_mode = transport_mode
            permission.reason = reason
            action_type = "UPDATE_PERMISSION_SUCCESS"
            flash_msg_text = 'Permisie actualizată cu succes!'
            log_description = f"{action_description_prefix} updated permission for {original_student_name_for_log}."
        else: 
            permission = Permission(student_id=int(student_id), start_datetime=start_dt, end_datetime=end_dt,
                                   destination=destination, transport_mode=transport_mode, reason=reason,
                                   status='Aprobată', created_by_user_id=current_user.id)
            db.session.add(permission)
            action_type = "CREATE_PERMISSION_SUCCESS"
            flash_msg_text = 'Permisie adăugată cu succes!'
            log_description = f"{action_description_prefix} created permission for {original_student_name_for_log}."
        try:
            db.session.flush() 
            log_details_after = model_to_dict(permission)
            log_action(action_type, target_model_name="Permission", target_id=permission.id,
                       details_before_dict=log_details_before, details_after_dict=log_details_after,
                       description=log_description)
            db.session.commit()
            flash(flash_msg_text, 'success')
        except Exception as e:
            db.session.rollback()
            flash_msg_fail = f'Eroare la salvarea permisiei: {str(e)}'
            flash(flash_msg_fail, 'danger')
            try:
                fail_action_type = "UPDATE_PERMISSION_FAIL" if permission_id else "CREATE_PERMISSION_FAIL"
                target_id_for_fail_log = permission.id if permission and permission.id else None
                attempted_data_on_fail = model_to_dict(permission) if permission else current_form_data_post
                log_action(fail_action_type, target_model_name="Permission", target_id=target_id_for_fail_log,
                           details_before_dict=log_details_before if permission_id else None,
                           details_after_dict=attempted_data_on_fail if not permission_id else model_to_dict(permission), 
                           description=f"{action_description_prefix} failed to {action_type.split('_')[0].lower()} permission for {original_student_name_for_log}. Error: {str(e)}")
                db.session.commit()
            except Exception as log_e:
                app.logger.error(f"CRITICAL: Failed to commit failure log for {fail_action_type}: {str(log_e)}")
            return render_template('add_edit_permission.html', form_title=form_title, permission=permission if permission_id else None, students=students_managed, form_data=current_form_data_post)
        return redirect(url_for('list_permissions'))
    form_data_on_get = {} 
    if permission: 
        form_data_on_get = {
            'student_id': str(permission.student_id),
            'start_datetime': permission.start_datetime.strftime('%Y-%m-%dT%H:%M') if permission.start_datetime else '',
            'end_datetime': permission.end_datetime.strftime('%Y-%m-%dT%H:%M') if permission.end_datetime else '',
            'destination': permission.destination or '',
            'transport_mode': permission.transport_mode or '',
            'reason': permission.reason or ''
        }
    return render_template('add_edit_permission.html',
                           form_title=form_title,
                           permission=permission, 
                           students=students_managed,
                           form_data=form_data_on_get if request.method == 'GET' and permission else request.form if request.method == 'POST' else {})

def find_student_for_bulk_import(name_line, gradat_id):
    name_line_norm = unidecode(name_line.lower().strip())
    if not name_line_norm:
        return None, "Linie nume goală."
    students_managed = Student.query.filter_by(created_by_user_id=gradat_id).all()
    if not students_managed:
        return None, "Niciun student gestionat de acest gradat."
    parsed_grad_bulk = None
    student_name_str_bulk = name_line 
    for pattern in KNOWN_RANK_PATTERNS: 
        match = pattern.match(name_line)
        if match:
            parsed_grad_bulk = match.group(0).strip()
            student_name_str_bulk = pattern.sub("", name_line).strip()
            break
    normalized_search_name_bulk = unidecode(student_name_str_bulk.lower())
    matched_students = []
    for s in students_managed:
        s_fullname_norm = unidecode(f"{s.nume} {s.prenume}".lower())
        s_grad_norm = unidecode(s.grad_militar.lower())
        if parsed_grad_bulk:
            parsed_grad_bulk_norm = unidecode(parsed_grad_bulk.lower())
            if normalized_search_name_bulk == s_fullname_norm and parsed_grad_bulk_norm == s_grad_norm:
                matched_students.append(s)
        else: 
            if normalized_search_name_bulk == s_fullname_norm:
                 matched_students.append(s)
    if len(matched_students) == 1: return matched_students[0], None
    if len(matched_students) > 1: return None, f"Potriviri multiple exacte pentru '{name_line}'"
    if not matched_students: 
        potential_matches = []
        for s in students_managed:
            s_fullname_norm = unidecode(f"{s.nume} {s.prenume}".lower())
            s_fullname_reversed_norm = unidecode(f"{s.prenume} {s.nume}".lower())
            s_grad_norm = unidecode(s.grad_militar.lower())
            name_match_direct = (normalized_search_name_bulk == s_fullname_norm)
            name_match_reversed = (normalized_search_name_bulk == s_fullname_reversed_norm)
            if name_match_direct or name_match_reversed:
                if parsed_grad_bulk: 
                    parsed_grad_bulk_norm = unidecode(parsed_grad_bulk.lower())
                    if parsed_grad_bulk_norm in s_grad_norm or s_grad_norm in parsed_grad_bulk_norm:
                        potential_matches.append(s)
                else: 
                    potential_matches.append(s)
        if len(potential_matches) == 1:
            return potential_matches[0], None 
        elif len(potential_matches) > 1:
            student_names_found = [f"{s.grad_militar} {s.nume} {s.prenume}" for s in potential_matches]
            return None, f"Potriviri multiple pentru '{name_line}': {', '.join(student_names_found)}. Clarificați gradul sau numele."
    if not matched_students and not potential_matches: 
         return None, f"Studentul '{name_line}' nu a fost găsit. Verificați numele și gradul."
    elif len(matched_students) > 1 : 
         return None, f"Potriviri multiple exacte pentru '{name_line}'. Clarificați."
    return None, f"Studentul '{name_line}' nu a fost găsit sau potrivirea este ambiguă (situație neașteptată)."

@app.route('/gradat/permissions/bulk_import', methods=['POST'], endpoint='gradat_bulk_import_permissions')
@login_required
def bulk_import_permissions():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('list_permissions'))
    permission_bulk_data = request.form.get('permission_bulk_data', '').strip()
    if not permission_bulk_data:
        flash('Nu au fost furnizate date pentru import.', 'warning')
        return redirect(url_for('list_permissions'))
    lines = permission_bulk_data.splitlines()
    added_count = 0
    error_count = 0
    error_details = []
    i = 0
    while i < len(lines):
        name_line = lines[i].strip()
        if not name_line: 
            i += 1
            continue
        lines_for_this_entry = []
        temp_i = i
        while temp_i < len(lines) and lines[temp_i].strip():
            lines_for_this_entry.append(lines[temp_i].strip())
            temp_i += 1
        num_actual_lines_for_entry = len(lines_for_this_entry)
        if num_actual_lines_for_entry < 3:
            if num_actual_lines_for_entry > 0: 
                 error_details.append(f"Intrare incompletă începând cu '{lines_for_this_entry[0]}'. Necesită cel puțin Nume, Interval, Destinație.")
                 error_count += 1
            i = temp_i 
            if num_actual_lines_for_entry > 0 : i+=1 
            continue
        name_line = lines_for_this_entry[0]
        datetime_line = lines_for_this_entry[1]
        destination_line = lines_for_this_entry[2]
        transport_mode_line = lines_for_this_entry[3] if num_actual_lines_for_entry > 3 else ""
        reason_car_plate_line = lines_for_this_entry[4] if num_actual_lines_for_entry > 4 else ""
        i = temp_i
        if temp_i < len(lines) and not lines[temp_i].strip(): 
            i += 1
        student_obj, student_error = find_student_for_bulk_import(name_line, current_user.id)
        if student_error:
            error_details.append(f"Linia '{name_line}': {student_error}")
            error_count += 1
            continue
        try:
            dt_match = re.search(
                r"(\d{1,2}\.\d{1,2}\.\d{4})\s+(\d{1,2}:\d{2})\s*-\s*(?:(\d{1,2}\.\d{1,2}\.\d{4})\s+)?(\d{1,2}:\d{2})",
                datetime_line
            )
            if not dt_match:
                app.logger.warning(f"Bulk Permission Import: Invalid datetime format for student '{name_line}'. Input: '{datetime_line}'. Expected 'DD.MM.YYYY HH:MM - [DD.MM.YYYY] HH:MM'.")
                raise ValueError("Format interval datetime invalid.") 
            start_date_str, start_time_str, end_date_str_opt, end_time_str = dt_match.groups()
            start_dt = datetime.strptime(f"{start_date_str} {start_time_str}", '%d.%m.%Y %H:%M')
            if end_date_str_opt: 
                end_dt = datetime.strptime(f"{end_date_str_opt} {end_time_str}", '%d.%m.%Y %H:%M')
            else: 
                end_time_obj_parsed = datetime.strptime(end_time_str, '%H:%M').time()
                end_date_assumed = start_dt.date()
                if end_time_obj_parsed < start_dt.time():
                    end_date_assumed += timedelta(days=1)
                end_dt = datetime.combine(end_date_assumed, end_time_obj_parsed)
            if end_dt <= start_dt:
                app.logger.warning(f"Bulk Permission Import: End datetime not after start for student '{name_line}'. Start: {start_dt}, End: {end_dt}")
                raise ValueError("Data/ora de sfârșit trebuie să fie după data/ora de început.")
        except ValueError as ve:
            if str(ve) not in ["Format interval datetime invalid.", "Data/ora de sfârșit trebuie să fie după data/ora de început."]:
                 app.logger.error(f"Bulk Permission Import: ValueError parsing datetime for student '{name_line}', line '{datetime_line}': {str(ve)}")
            error_details.append(f"Student '{name_line}': Eroare format dată/oră în '{datetime_line}' - {str(ve)}")
            error_count += 1
            continue
        parsed_destination = destination_line.strip()
        parsed_transport_mode = transport_mode_line.strip() if transport_mode_line else None
        parsed_reason = reason_car_plate_line.strip() if reason_car_plate_line else None
        if not student_obj: 
            error_details.append(f"Eroare internă: student_obj este None pentru linia '{name_line}' după ce student_error a fost None.")
            error_count += 1
            continue
        conflict = check_leave_conflict(student_obj.id, start_dt, end_dt, leave_type='permission')
        if conflict:
            error_details.append(f"Student '{name_line}': Conflict - {conflict}.")
            error_count += 1
            i += lines_this_entry # This was an error, should be: continue
            continue
        new_permission = Permission(
            student_id=student_obj.id,
            start_datetime=start_dt,
            end_datetime=end_dt,
            destination=parsed_destination,
            transport_mode=parsed_transport_mode, 
            reason=parsed_reason,
            status='Aprobată',
            created_by_user_id=current_user.id
        )
        try:
            db.session.add(new_permission)
            added_count += 1
        except Exception as e_add: 
            db.session.rollback() 
            error_details.append(f"Student '{name_line}': Eroare la adăugare în sesiune DB - {str(e_add)}")
            error_count += 1
            continue
    if added_count > 0:
        try:
            db.session.commit()
            flash(f'{added_count} permisii au fost adăugate cu succes.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la salvarea permisiilor în baza de date: {str(e)}', 'danger')
            error_count += added_count
            added_count = 0
    if error_count > 0:
        flash(f'{error_count} intrări nu au putut fi procesate sau au generat erori.', 'danger')
        if error_details:
            flash_detail_msg = "Detalii erori:<br>" + "<br>".join(error_details)
            if len(flash_detail_msg) > 1000: 
                flash_detail_msg = flash_detail_msg[:997] + "..."
            flash(flash_detail_msg, 'warning')
    if added_count > 0 or error_count > 0: 
        try:
            log_action("BULK_IMPORT_PERMISSIONS_COMPLETED",
                       description=f"User {current_user.username} ran bulk permission import. Added: {added_count}, Errors: {error_count}. First 3 errors: {error_details[:3]}",
                       details_after_dict={"added_count": added_count, "error_count": error_count, "first_few_errors_details": error_details[:3]})
            db.session.commit()
        except Exception as log_e:
            app.logger.error(f"CRITICAL: Failed to commit log for BULK_IMPORT_PERMISSIONS_COMPLETED: {str(log_e)}")
    return redirect(url_for('list_permissions'))

@app.route('/gradat/permissions/export_word', endpoint='gradat_export_permissions_word')
@login_required
def export_permissions_word():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    student_id_tuples = db.session.query(Student.id).filter_by(created_by_user_id=current_user.id).all()
    student_ids_managed_by_gradat = [s[0] for s in student_id_tuples]
    if not student_ids_managed_by_gradat:
        flash('Nu aveți studenți pentru a exporta permisii.', 'info')
        return redirect(url_for('list_permissions'))
    now = get_localized_now() 
    permissions_to_export = Permission.query.options(joinedload(Permission.student)).filter(
        Permission.student_id.in_(student_ids_managed_by_gradat),
        Permission.status == 'Aprobată',
        Permission.end_datetime >= now 
    ).join(Student).order_by(Student.nume, Student.prenume, Permission.start_datetime).all()
    if not permissions_to_export:
        flash('Nicio permisie activă sau viitoare de exportat.', 'info')
        return redirect(url_for('list_permissions'))
    document = Document()
    document.add_heading('Raport Permisii Studenți', level=1).alignment = WD_ALIGN_PARAGRAPH.CENTER
    user_info_text = f"Raport generat de: {current_user.username}\nData generării: {datetime.now().strftime('%d-%m-%Y %H:%M')}"
    p_user = document.add_paragraph()
    p_user.add_run(user_info_text).italic = True
    p_user.alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_paragraph() 
    table = document.add_table(rows=1, cols=8) 
    table.style = 'Table Grid'
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = table.rows[0].cells
    column_titles = ['Nr. Crt.', 'Grad', 'Nume și Prenume', 'Data Început', 'Data Sfârșit', 'Destinația', 'Mijloc Transport', 'Observații/Nr. Auto']
    for i, title in enumerate(column_titles):
        hdr_cells[i].text = title
        hdr_cells[i].paragraphs[0].runs[0].font.bold = True
        hdr_cells[i].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    for idx, p in enumerate(permissions_to_export):
        row_cells = table.add_row().cells
        row_cells[0].text = str(idx + 1)
        row_cells[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[1].text = p.student.grad_militar
        row_cells[2].text = f"{p.student.nume} {p.student.prenume}"
        row_cells[3].text = p.start_datetime.strftime('%d.%m.%Y %H:%M')
        row_cells[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[4].text = p.end_datetime.strftime('%d.%m.%Y %H:%M')
        row_cells[4].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[5].text = p.destination if p.destination else "-"
        row_cells[6].text = p.transport_mode if p.transport_mode else "-"
        row_cells[7].text = p.reason if p.reason else "-" 
        row_cells[7].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER 
    widths = {
        0: Inches(0.4), 1: Inches(0.7), 2: Inches(1.8), 3: Inches(1.1), 
        4: Inches(1.1), 5: Inches(1.5), 6: Inches(1.2), 7: Inches(1.2)  
    }
    for col_idx, width_val in widths.items():
        for row in table.rows:
            try:
                row.cells[col_idx].width = width_val
            except IndexError:
                app.logger.warning(f"IndexError setting width for col {col_idx} in export_permissions_word. Row has {len(row.cells)} cells.")
    style = document.styles['Normal']
    font = style.font
    font.name = 'Calibri'
    font.size = Pt(11)
    f = io.BytesIO()
    document.save(f)
    f.seek(0)
    filename = f"Raport_Permisii_{current_user.username}_{date.today().strftime('%Y%m%d')}.docx"
    return send_file(f,
                     download_name=filename,
                     as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

@app.route('/gradat/permission/cancel/<int:permission_id>', methods=['POST'])
@login_required
def cancel_permission(permission_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    permission = Permission.query.get_or_404(permission_id)
    student_of_permission = Student.query.get(permission.student_id)
    if not student_of_permission or student_of_permission.created_by_user_id != current_user.id: flash('Nu aveți permisiunea să anulați această permisie.', 'danger'); return redirect(url_for('list_permissions'))
    if permission.status == 'Aprobată':
        permission.status = 'Anulată'
        try: db.session.commit(); flash(f'Permisia pentru {student_of_permission.nume} {student_of_permission.prenume} a fost anulată.', 'success')
        except Exception as e: db.session.rollback(); flash(f'Eroare la anularea permisiei: {str(e)}', 'danger')
    else: flash('Această permisie nu poate fi anulată (statusul curent nu este "Aprobată").', 'warning')
    return redirect(url_for('list_permissions'))

@app.route('/gradat/permissions/delete/<int:permission_id>', methods=['POST'])
@app.route('/admin/permissions/delete/<int:permission_id>', methods=['POST'])
@login_required
def delete_permission(permission_id):
    permission_to_delete = db.session.get(Permission, permission_id)
    if not permission_to_delete:
        flash('Permisia nu a fost găsită.', 'danger')
        return redirect(url_for('list_permissions') if current_user.role == 'gradat' else url_for('admin_dashboard_route')) 
    student_owner = db.session.get(Student, permission_to_delete.student_id)
    if current_user.role == 'gradat':
        if not student_owner or student_owner.created_by_user_id != current_user.id:
            flash('Nu aveți permisiunea să ștergeți această permisie.', 'danger')
            return redirect(url_for('list_permissions'))
        redirect_url = url_for('list_permissions')
    elif current_user.role == 'admin':
        if student_owner and student_owner.creator and student_owner.creator.username != current_user.username: 
             flash(f'Atenție: Ștergeți o permisie pentru studentul {student_owner.nume} {student_owner.prenume}, gestionat de {student_owner.creator.username}.', 'warning')
        redirect_url = request.referrer or url_for('admin_dashboard_route') 
    else:
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    student_name_for_flash = f"{student_owner.grad_militar} {student_owner.nume} {student_owner.prenume}" if student_owner else "N/A"
    permission_details_for_flash = f"din {permission_to_delete.start_datetime.strftime('%d.%m.%Y %H:%M')} până în {permission_to_delete.end_datetime.strftime('%d.%m.%Y %H:%M')}"
    details_before_delete = model_to_dict(permission_to_delete)
    try:
        db.session.delete(permission_to_delete)
        log_action("DELETE_PERMISSION_SUCCESS", target_model_name="Permission", target_id=permission_id,
                   details_before_dict=details_before_delete,
                   description=f"User {current_user.username} deleted permission for student {student_name_for_flash} (ID: {permission_id}) details: {permission_details_for_flash}.")
        db.session.commit()
        flash(f'Permisia pentru {student_name_for_flash} ({permission_details_for_flash}) a fost ștearsă.', 'success')
    except Exception as e:
        db.session.rollback()
        flash_msg = f'Eroare la ștergerea permisiei: {str(e)}'
        flash(flash_msg, 'danger')
        try:
            log_action("DELETE_PERMISSION_FAIL", target_model_name="Permission", target_id=permission_id,
                       details_before_dict=details_before_delete,
                       description=f"User {current_user.username} failed to delete permission for {student_name_for_flash} (ID: {permission_id}). Error: {str(e)}")
            db.session.commit()
        except Exception as log_e:
            app.logger.error(f"CRITICAL: Failed to commit failure log for DELETE_PERMISSION_FAIL: {str(log_e)}")
    return redirect(redirect_url)

# --- Rute pentru Învoiri Zilnice ---
@app.route('/gradat/daily_leaves')
@login_required
def list_daily_leaves():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    student_id_tuples = db.session.query(Student.id).filter_by(created_by_user_id=current_user.id).all()
    student_ids = [s[0] for s in student_id_tuples]
    today_string_for_form = get_localized_now().date().strftime('%Y-%m-%d') 
    if not student_ids:
        return render_template('list_daily_leaves.html', active_leaves=[], upcoming_leaves=[], past_leaves=[], title="Listă Învoiri Zilnice", today_str=today_string_for_form)
    all_relevant_leaves = DailyLeave.query.options(joinedload(DailyLeave.student))\
                                      .filter(DailyLeave.student_id.in_(student_ids))\
                                      .order_by(DailyLeave.leave_date.desc(), DailyLeave.start_time.desc()).all()
    active_leaves = []; upcoming_leaves = []; past_leaves = []
    for leave in all_relevant_leaves:
        if leave.status == 'Anulată': past_leaves.append(leave)
        elif leave.is_active: active_leaves.append(leave)
        elif leave.is_upcoming: upcoming_leaves.append(leave)
        elif leave.is_past: past_leaves.append(leave)
    active_leaves.sort(key=lambda x: (x.leave_date, x.start_time)); upcoming_leaves.sort(key=lambda x: (x.leave_date, x.start_time)); past_leaves = past_leaves[:50]
    return render_template('list_daily_leaves.html', active_leaves=active_leaves, upcoming_leaves=upcoming_leaves, past_leaves=past_leaves, title="Listă Învoiri Zilnice", today_str=today_string_for_form)

@app.route('/gradat/daily_leave/add', methods=['GET', 'POST'])
@app.route('/gradat/daily_leave/edit/<int:leave_id>', methods=['GET', 'POST'])
@login_required
def add_edit_daily_leave(leave_id=None):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    form_title = "Adaugă Învoire Zilnică"; daily_leave = None; today_string = get_localized_now().date().strftime('%Y-%m-%d') 
    if leave_id:
        daily_leave = DailyLeave.query.get_or_404(leave_id)
        student_of_leave = Student.query.get(daily_leave.student_id)
        if not student_of_leave or student_of_leave.created_by_user_id != current_user.id: flash('Acces neautorizat la această învoire.', 'danger'); return redirect(url_for('list_daily_leaves'))
        form_title = f"Editare Învoire Zilnică: {student_of_leave.grad_militar} {student_of_leave.nume} {student_of_leave.prenume}"
    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    if request.method == 'POST':
        student_id = request.form.get('student_id'); leave_date_str = request.form.get('leave_date'); start_time_str = request.form.get('start_time'); end_time_str = request.form.get('end_time')
        reason = request.form.get('reason', '').strip()
        current_form_data_post = request.form
        if not all([student_id, leave_date_str, start_time_str, end_time_str]): flash('Toate câmpurile (student, dată, oră început, oră sfârșit) sunt obligatorii.', 'warning'); return render_template('add_edit_daily_leave.html', form_title=form_title, daily_leave=daily_leave, students=students_managed, today_str=today_string, form_data=current_form_data_post)
        try:
            leave_date_obj = datetime.strptime(leave_date_str, '%Y-%m-%d').date(); start_time_obj = datetime.strptime(start_time_str, '%H:%M').time(); end_time_obj = datetime.strptime(end_time_str, '%H:%M').time()
        except ValueError: flash('Format dată sau oră invalid.', 'danger'); return render_template('add_edit_daily_leave.html', form_title=form_title, daily_leave=daily_leave, students=students_managed, today_str=today_string, form_data=current_form_data_post)
        is_valid_day, day_message = validate_daily_leave_times(start_time_obj, end_time_obj, leave_date_obj)
        if not is_valid_day: flash(day_message, 'danger'); return render_template('add_edit_daily_leave.html', form_title=form_title, daily_leave=daily_leave, students=students_managed, today_str=today_string, form_data=current_form_data_post)
        start_dt = datetime.combine(leave_date_obj, start_time_obj)
        effective_end_date = leave_date_obj
        if end_time_obj < start_time_obj: 
            effective_end_date += timedelta(days=1)
        end_dt = datetime.combine(effective_end_date, end_time_obj)
        if end_dt <= start_dt : flash('Data/ora de sfârșit trebuie să fie după data/ora de început, chiar și când trece în ziua următoare.', 'warning'); return render_template('add_edit_daily_leave.html', form_title=form_title, daily_leave=daily_leave, students=students_managed, today_str=today_string, form_data=current_form_data_post)
        student_to_check = Student.query.get(student_id)
        if student_to_check:
            conflict_msg_intervention = check_leave_conflict(student_id, start_dt, end_dt, 'daily_leave', leave_id)
            if conflict_msg_intervention and "serviciu (Intervenție)" in conflict_msg_intervention:
                 flash(f'Studentul {student_to_check.nume} {student_to_check.prenume} este în serviciu de "Intervenție" și nu poate primi învoire zilnică în acest interval.', 'danger')
                 return render_template('add_edit_daily_leave.html', form_title=form_title, daily_leave=daily_leave, students=students_managed, today_str=today_string, form_data=current_form_data_post)
        general_conflict_msg = check_leave_conflict(student_id, start_dt, end_dt, 'daily_leave', leave_id if daily_leave else None)
        if general_conflict_msg:
            flash(f'Conflict detectat: Studentul are deja {general_conflict_msg}.', 'danger')
            return render_template('add_edit_daily_leave.html', form_title=form_title, daily_leave=daily_leave, students=students_managed, today_str=today_string, form_data=current_form_data_post)
        if daily_leave:
            daily_leave.student_id = int(student_id); daily_leave.leave_date = leave_date_obj; daily_leave.start_time = start_time_obj; daily_leave.end_time = end_time_obj; daily_leave.reason = reason
            flash('Învoire zilnică actualizată!', 'success')
        else:
            new_leave = DailyLeave(student_id=int(student_id), leave_date=leave_date_obj, start_time=start_time_obj, end_time=end_time_obj, reason=reason, status='Aprobată', created_by_user_id=current_user.id)
            db.session.add(new_leave); flash('Învoire zilnică adăugată!', 'success')
        try: db.session.commit()
        except Exception as e: db.session.rollback(); flash(f'Eroare la salvarea învoirii: {str(e)}', 'danger'); return render_template('add_edit_daily_leave.html', form_title=form_title, daily_leave=daily_leave, students=students_managed, today_str=today_string, form_data=current_form_data_post)
        return redirect(url_for('list_daily_leaves'))
    data_to_populate_form_with = {}
    if request.method == 'POST':
        data_to_populate_form_with = request.form
    elif daily_leave:
        data_to_populate_form_with = {
            'student_id': str(daily_leave.student_id),
            'leave_date': daily_leave.leave_date.strftime('%Y-%m-%d'),
            'start_time': daily_leave.start_time.strftime('%H:%M'),
            'end_time': daily_leave.end_time.strftime('%H:%M'),
            'reason': daily_leave.reason or ''
        }
    return render_template('add_edit_daily_leave.html',
                           form_title=form_title,
                           daily_leave=daily_leave,
                           students=students_managed,
                           today_str=today_string,
                           form_data=data_to_populate_form_with)

@app.route('/gradat/daily_leave/cancel/<int:leave_id>', methods=['POST'])
@login_required
def cancel_daily_leave(leave_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    leave = DailyLeave.query.get_or_404(leave_id)
    student_of_leave = Student.query.get(leave.student_id)
    if not student_of_leave or student_of_leave.created_by_user_id != current_user.id: flash('Nu aveți permisiunea să anulați această învoire.', 'danger'); return redirect(url_for('list_daily_leaves'))
    if leave.status == 'Aprobată':
        leave.status = 'Anulată'
        try: db.session.commit(); flash(f'Învoirea zilnică pentru {student_of_leave.nume} {student_of_leave.prenume} din data {leave.leave_date.strftime("%d.%m.%Y")} a fost anulată.', 'success')
        except Exception as e: db.session.rollback(); flash(f'Eroare la anularea învoirii: {str(e)}', 'danger')
    else: flash('Această învoire nu poate fi anulată (statusul curent nu este "Aprobată").', 'warning')
    return redirect(url_for('list_daily_leaves'))

def parse_leave_line(line_text): 
    parts = line_text.strip().split()
    grad = None
    parsed_start_time_obj = None
    parsed_end_time_obj = None
    normalized_name_search = None
    if not parts:
        return None, None, None, None
    name_parts = list(parts) 
    if len(name_parts) > 0:
        time_range_match = re.fullmatch(r"(\d{1,2}:\d{2})-(\d{1,2}:\d{2})", name_parts[-1])
        if time_range_match:
            try:
                parsed_start_time_obj = datetime.strptime(time_range_match.group(1), '%H:%M').time()
                parsed_end_time_obj = datetime.strptime(time_range_match.group(2), '%H:%M').time()
                name_parts.pop() 
            except ValueError:
                parsed_start_time_obj = None
                parsed_end_time_obj = None
    if not name_parts: 
        return None, None, None, None
    student_name_str = " ".join(name_parts)
    for pattern in KNOWN_RANK_PATTERNS:
        match = pattern.match(student_name_str)
        if match:
            grad = match.group(0).strip()
            student_name_str = pattern.sub("", student_name_str).strip()
            break
    if student_name_str: 
        normalized_name_search = unidecode(student_name_str.lower())
    else: 
        return None, grad, parsed_start_time_obj, parsed_end_time_obj 
    return normalized_name_search, grad, parsed_start_time_obj, parsed_end_time_obj

def parse_weekend_leave_line(line_text_raw):
    line_text = line_text_raw.strip()
    is_biserica_requested = False
    biserica_keyword = "biserica"
    if line_text.lower().endswith(f" {biserica_keyword}"):
        is_biserica_requested = True
        line_text = line_text[:-len(f" {biserica_keyword}")].strip()
    elif line_text.lower().endswith(f",{biserica_keyword}"):
        is_biserica_requested = True
        line_text = line_text[:-len(f",{biserica_keyword}")].strip()
    elif line_text.lower() == biserica_keyword: 
        return "", [], True, "Linia conține doar 'biserica', fără student sau intervale."
    interval_pattern = re.compile(r"(\d{1,2}\.\d{1,2}\.\d{4})\s+(\d{1,2}:\d{2})\s*-\s*(\d{1,2}:\d{2})")
    raw_interval_parts = [] 
    for match in interval_pattern.finditer(line_text):
        raw_interval_parts.append(match.groups()) 
    if not raw_interval_parts:
        student_name_part_if_no_intervals = line_text.replace(",", "").strip()
        if not student_name_part_if_no_intervals and not is_biserica_requested: 
             app.logger.debug(f"parse_weekend_leave_line: Skipping empty or biserica-only line: '{line_text_raw}'")
             return None, [], False, None 
        app.logger.warning(f"parse_weekend_leave_line: No valid datetime intervals found in line: '{line_text_raw}'. Student part considered: '{student_name_part_if_no_intervals}'. Biserica: {is_biserica_requested}")
        return student_name_part_if_no_intervals, [], is_biserica_requested, "Niciun interval de timp valid (DD.MM.YYYY HH:MM-HH:MM) găsit."
    parsed_intervals = []
    for date_str, start_str, end_str in raw_interval_parts:
        try:
            date_obj = datetime.strptime(date_str, "%d.%m.%Y").date()
            start_time_obj = datetime.strptime(start_str, "%H:%M").time()
            end_time_obj = datetime.strptime(end_str, "%H:%M").time()
            if start_time_obj == end_time_obj:
                return line_text, [], is_biserica_requested, f"Interval orar invalid (început=sfârșit) în '{date_str} {start_str}-{end_str}'."
            parsed_intervals.append({
                'date_obj': date_obj,
                'start_time_obj': start_time_obj,
                'end_time_obj': end_time_obj,
                'raw_match': f"{date_str} {start_str}-{end_str}" 
            })
        except ValueError:
            return line_text, [], is_biserica_requested, f"Format dată/oră invalid în intervalul '{date_str} {start_str}-{end_str}'."
    student_name_part = line_text
    full_interval_pattern = re.compile(r"(\d{1,2}\.\d{1,2}\.\d{4}\s+\d{1,2}:\d{2}\s*-\s*\d{1,2}:\d{2})")
    actual_matched_interval_strings = full_interval_pattern.findall(line_text)
    for matched_str in actual_matched_interval_strings:
        student_name_part = student_name_part.replace(matched_str, "")
    student_name_part = student_name_part.replace(",", "").strip() 
    if not student_name_part:
        return "", parsed_intervals, is_biserica_requested, "Numele studentului lipsește (linia conține doar intervale/biserica)." if parsed_intervals else "Linie invalidă."
    parsed_intervals.sort(key=lambda x: (x['date_obj'], x['start_time_obj']))
    return student_name_part, parsed_intervals, is_biserica_requested, None

@app.route('/gradat/daily_leaves/process_text', methods=['POST'], endpoint='gradat_process_daily_leaves_text')
@login_required
def process_daily_leaves_text():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    leave_list_text = request.form.get('leave_list_text'); apply_date_str = request.form.get('apply_date')
    if not leave_list_text or not apply_date_str: flash('Lista de învoiri și data de aplicare sunt obligatorii.', 'warning'); return redirect(url_for('list_daily_leaves'))
    try: apply_date_obj = datetime.strptime(apply_date_str, '%Y-%m-%d').date()
    except ValueError: flash('Format dată aplicare invalid.', 'danger'); return redirect(url_for('list_daily_leaves'))
    if apply_date_obj.weekday() > 3: flash('Învoirile din text pot fi aplicate doar pentru zile de Luni până Joi.', 'warning'); return redirect(url_for('list_daily_leaves'))
    lines = leave_list_text.strip().splitlines()
    default_start_time_obj = time(15, 0)
    default_end_time_obj = time(19, 0)
    processed_count, error_count, already_exists_count = 0,0,0
    error_details_import_dl = [] 
    not_found_or_ambiguous = [] # Added to collect student find issues

    for line_raw in lines:
        line_for_student_find = line_raw.strip()
        if not line_for_student_find: continue
        
        time_match_in_line = re.search(r"(\d{1,2}:\d{2})-(\d{1,2}:\d{2})$", line_for_student_find.strip())
        student_name_grad_part = line_for_student_find.strip()
        line_start_time_obj = None
        line_end_time_obj = None

        if time_match_in_line:
            student_name_grad_part = line_for_student_find.strip()[:time_match_in_line.start()].strip()
            try:
                line_start_time_obj = datetime.strptime(time_match_in_line.group(1), "%H:%M").time()
                line_end_time_obj = datetime.strptime(time_match_in_line.group(2), "%H:%M").time()
            except ValueError:
                pass 

        found_student, student_error = find_student_for_bulk_import(student_name_grad_part, current_user.id)

        if student_error:
            app.logger.warning(f"Daily Leave Text Import: Student find error for line '{line_raw}'. Error: {student_error}")
            error_details_import_dl.append(f"Linia '{line_raw}': {student_error}")
            not_found_or_ambiguous.append(f"'{line_raw}': {student_error}") # Add to specific list
            error_count += 1
            continue
        if not found_student: 
            app.logger.error(f"Daily Leave Text Import: found_student is None but student_error was also None for line '{line_raw}'.")
            error_details_import_dl.append(f"Linia '{line_raw}': Eroare internă la identificarea studentului.")
            not_found_or_ambiguous.append(f"'{line_raw}': Eroare internă") # Add to specific list
            error_count += 1
            continue
        current_start_time = line_start_time_obj if line_start_time_obj else default_start_time_obj
        current_end_time = line_end_time_obj if line_end_time_obj else default_end_time_obj 
        if line_start_time_obj and not line_end_time_obj: 
            current_end_time = default_end_time_obj
        valid_schedule, validation_message = validate_daily_leave_times(current_start_time, current_end_time, apply_date_obj)
        if not valid_schedule:
            app.logger.warning(f"Daily Leave Text Import: Invalid schedule for student '{found_student.nume}' line '{line_raw}'. Message: {validation_message}")
            error_details_import_dl.append(f"Linia '{line_raw}' ({found_student.nume}): Interval orar invalid - {validation_message}.")
            error_count +=1
            continue
        start_dt_bulk = datetime.combine(apply_date_obj, current_start_time)
        effective_end_date_bulk = apply_date_obj
        if current_end_time < current_start_time : 
            effective_end_date_bulk += timedelta(days=1)
        end_dt_bulk = datetime.combine(effective_end_date_bulk, current_end_time)
        active_intervention_service = ServiceAssignment.query.filter(
            ServiceAssignment.student_id == found_student.id,
            ServiceAssignment.service_type == 'Intervenție',
            ServiceAssignment.start_datetime < end_dt_bulk,
            ServiceAssignment.end_datetime > start_dt_bulk
        ).first()
        if active_intervention_service:
            flash(f'Studentul {found_student.nume} {found_student.prenume} este în "Intervenție". Învoire ignorată pentru {line_raw}.', 'warning')
            error_count += 1
            continue
        existing_leave = DailyLeave.query.filter_by(
            student_id=found_student.id,
            leave_date=apply_date_obj,
            start_time=current_start_time,
            end_time=current_end_time,
            status='Aprobată'
        ).first()
        if existing_leave:
            already_exists_count +=1
            continue
        new_leave = DailyLeave(
            student_id=found_student.id,
            leave_date=apply_date_obj,
            start_time=current_start_time,
            end_time=current_end_time,
            status='Aprobată',
            created_by_user_id=current_user.id,
            reason=f"Procesare text: {line_raw}"
        )
        db.session.add(new_leave)
        processed_count += 1
    try:
        db.session.commit()
        if processed_count > 0: flash(f'{processed_count} învoiri procesate și adăugate.', 'success')
        if error_count > 0: flash(f'{error_count} linii nu au putut fi procesate complet.', 'danger')
        if already_exists_count > 0: flash(f'{already_exists_count} învoiri identice existau deja și au fost ignorate.', 'info')
        if not_found_or_ambiguous: flash(f"Probleme identificare studenți: {'; '.join(not_found_or_ambiguous)}", 'warning')
    except Exception as e: db.session.rollback(); flash(f'Eroare majoră la salvarea învoirilor din text: {str(e)}', 'danger')
    return redirect(url_for('list_daily_leaves'))

@app.route('/gradat/daily_leaves/delete/<int:leave_id>', methods=['POST'])
@app.route('/admin/daily_leaves/delete/<int:leave_id>', methods=['POST'])
@login_required
def delete_daily_leave(leave_id):
    leave_to_delete = db.session.get(DailyLeave, leave_id)
    if not leave_to_delete:
        flash('Învoirea zilnică nu a fost găsită.', 'danger')
        return redirect(url_for('list_daily_leaves') if current_user.role == 'gradat' else url_for('admin_dashboard_route'))
    student_owner = db.session.get(Student, leave_to_delete.student_id)
    if current_user.role == 'gradat':
        if not student_owner or student_owner.created_by_user_id != current_user.id:
            flash('Nu aveți permisiunea să ștergeți această învoire zilnică.', 'danger')
            return redirect(url_for('list_daily_leaves'))
        redirect_url = url_for('list_daily_leaves')
    elif current_user.role == 'admin':
        if student_owner and student_owner.creator and student_owner.creator.username != current_user.username:
             flash(f'Atenție: Ștergeți o învoire zilnică pentru studentul {student_owner.nume} {student_owner.prenume}, gestionat de {student_owner.creator.username}.', 'warning')
        redirect_url = request.referrer or url_for('admin_dashboard_route')
    else:
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    student_name_for_flash = f"{student_owner.grad_militar} {student_owner.nume} {student_owner.prenume}" if student_owner else "N/A"
    leave_details_for_flash = f"din {leave_to_delete.leave_date.strftime('%d.%m.%Y')} ({leave_to_delete.start_time.strftime('%H:%M')}-{leave_to_delete.end_time.strftime('%H:%M')})"
    try:
        db.session.delete(leave_to_delete)
        db.session.commit()
        flash(f'Învoirea zilnică pentru {student_name_for_flash} {leave_details_for_flash} a fost ștearsă.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la ștergerea învoirii zilnice: {str(e)}', 'danger')
    return redirect(redirect_url)

# --- Rute pentru Învoiri Weekend ---
@app.route('/gradat/weekend_leaves')
@login_required
def list_weekend_leaves():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    student_id_tuples = db.session.query(Student.id).filter_by(created_by_user_id=current_user.id).all()
    student_ids = [s[0] for s in student_id_tuples]
    if not student_ids:
        return render_template('list_weekend_leaves.html', active_or_upcoming_leaves=[], past_leaves=[], title="Listă Învoiri Weekend")
    all_relevant_leaves = WeekendLeave.query.options(joinedload(WeekendLeave.student))\
                                          .filter(WeekendLeave.student_id.in_(student_ids))\
                                          .order_by(WeekendLeave.weekend_start_date.desc()).all()
    active_or_upcoming_leaves = []; past_leaves = []
    for leave in all_relevant_leaves:
        if leave.status == 'Anulată': past_leaves.append(leave)
        elif leave.is_overall_active_or_upcoming: active_or_upcoming_leaves.append(leave)
        else: past_leaves.append(leave)
    active_or_upcoming_leaves.sort(key=lambda x: x.weekend_start_date); past_leaves = past_leaves[:50]
    return render_template('list_weekend_leaves.html', active_or_upcoming_leaves=active_or_upcoming_leaves, past_leaves=past_leaves, title="Listă Învoiri Weekend")

@app.route('/gradat/weekend_leave/add', methods=['GET', 'POST'])
@app.route('/gradat/weekend_leave/edit/<int:leave_id>', methods=['GET', 'POST'])
@login_required
def add_edit_weekend_leave(leave_id=None):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    form_title = "Adaugă Învoire Weekend"; weekend_leave = None; form_data_on_get = {}
    if leave_id:
        weekend_leave = WeekendLeave.query.get_or_404(leave_id)
        student_of_leave = Student.query.get(weekend_leave.student_id)
        if not student_of_leave or student_of_leave.created_by_user_id != current_user.id: flash('Acces neautorizat la această învoire de weekend.', 'danger'); return redirect(url_for('list_weekend_leaves'))
        form_title = f"Editare Învoire Weekend: {student_of_leave.grad_militar} {student_of_leave.nume} {student_of_leave.prenume}"
        form_data_on_get['student_id'] = str(weekend_leave.student_id)
        form_data_on_get['weekend_start_date'] = weekend_leave.weekend_start_date.strftime('%Y-%m-%d')
        form_data_on_get['reason'] = weekend_leave.reason
        form_data_on_get['duminica_biserica'] = weekend_leave.duminica_biserica 
        selected_days_from_db = []
        day_fields_map = {
            'day1': (weekend_leave.day1_date, weekend_leave.day1_start_time, weekend_leave.day1_end_time, weekend_leave.day1_selected),
            'day2': (weekend_leave.day2_date, weekend_leave.day2_start_time, weekend_leave.day2_end_time, weekend_leave.day2_selected),
            'day3': (weekend_leave.day3_date, weekend_leave.day3_start_time, weekend_leave.day3_end_time, weekend_leave.day3_selected)
        }
        for _field_prefix, (d_date, s_time, e_time, d_name_selected) in day_fields_map.items():
            if d_date and d_name_selected: 
                day_name_template_key = d_name_selected.lower() 
                if day_name_template_key not in selected_days_from_db: 
                    selected_days_from_db.append(d_name_selected) 
                form_data_on_get[f'{day_name_template_key}_start_time'] = s_time.strftime('%H:%M') if s_time else ''
                form_data_on_get[f'{day_name_template_key}_end_time'] = e_time.strftime('%H:%M') if e_time else ''
        form_data_on_get['selected_days[]'] = selected_days_from_db 
    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    upcoming_fridays_list = get_upcoming_fridays()
    if request.method == 'POST':
        student_id = request.form.get('student_id'); weekend_start_date_str = request.form.get('weekend_start_date'); selected_days = request.form.getlist('selected_days[]')
        reason = request.form.get('reason', '').strip()
        current_form_data_post = request.form 
        if not student_id or not weekend_start_date_str:
            flash('Studentul și data de început a weekendului (Vineri) sunt obligatorii.', 'warning')
            return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
        if not selected_days or len(selected_days) == 0 or len(selected_days) > 3: 
            flash('Trebuie să selectați între 1 și 3 zile din weekend.', 'warning')
            return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
        try:
            friday_date_obj = datetime.strptime(weekend_start_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Format dată weekend invalid.', 'danger')
            return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
        day_data = [] 
        for day_name_selected in selected_days:
            start_time_str = request.form.get(f'{day_name_selected.lower()}_start_time'); end_time_str = request.form.get(f'{day_name_selected.lower()}_end_time')
            if not start_time_str or not end_time_str: flash(f'Orele de început și sfârșit sunt obligatorii pentru {day_name_selected}.', 'warning'); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
            try: start_time_obj = datetime.strptime(start_time_str, '%H:%M').time(); end_time_obj = datetime.strptime(end_time_str, '%H:%M').time()
            except ValueError: flash(f'Format oră invalid pentru {day_name_selected}.', 'danger'); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
            if end_time_obj == start_time_obj: flash(f'Ora de început și sfârșit nu pot fi identice pentru {day_name_selected}.', 'warning'); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
            day_offset_map = {'Vineri': 0, 'Sambata': 1, 'Duminica': 2}; day_offset = day_offset_map.get(day_name_selected)
            if day_offset is None: flash(f"Nume zi invalid: {day_name_selected}", "danger"); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
            actual_date_obj = friday_date_obj + timedelta(days=day_offset)
            current_interval_start_dt = datetime.combine(actual_date_obj, start_time_obj); effective_end_date_for_interval = actual_date_obj
            if end_time_obj < start_time_obj: effective_end_date_for_interval += timedelta(days=1)
            current_interval_end_dt = datetime.combine(effective_end_date_for_interval, end_time_obj)
            if current_interval_end_dt <= current_interval_start_dt: flash(f'Interval orar invalid pentru {day_name_selected}.', 'warning'); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
            day_data.append({'name': day_name_selected, 'date': actual_date_obj, 'start': start_time_obj, 'end': end_time_obj, 'start_dt': current_interval_start_dt, 'end_dt': current_interval_end_dt})
        day_data.sort(key=lambda x: x['start_dt'])
        student_to_check = Student.query.get(student_id)
        if student_to_check:
            for interval_data in day_data:
                active_intervention_service = ServiceAssignment.query.filter(ServiceAssignment.student_id == student_id, ServiceAssignment.service_type == 'Intervenție', ServiceAssignment.start_datetime < interval_data['end_dt'], ServiceAssignment.end_datetime > interval_data['start_dt']).first()
                if active_intervention_service: flash(f'Studentul {student_to_check.nume} este în "Intervenție" pe {interval_data["name"]} și nu poate primi învoire.', 'danger'); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
        if weekend_leave:
            target_leave = weekend_leave
            target_leave.day1_selected = None; target_leave.day1_date = None; target_leave.day1_start_time = None; target_leave.day1_end_time = None
            target_leave.day2_selected = None; target_leave.day2_date = None; target_leave.day2_start_time = None; target_leave.day2_end_time = None
            target_leave.day3_selected = None; target_leave.day3_date = None; target_leave.day3_start_time = None; target_leave.day3_end_time = None
            flash_msg = 'Învoire Weekend actualizată!'
        else:
            target_leave = WeekendLeave(created_by_user_id=current_user.id, status='Aprobată')
            flash_msg = 'Învoire Weekend adăugată!'
        target_leave.student_id = int(student_id)
        target_leave.weekend_start_date = friday_date_obj
        target_leave.reason = reason
        target_leave.duminica_biserica = request.form.get('duminica_biserica') == 'true'
        if len(day_data) >= 1:
            target_leave.day1_selected = day_data[0]['name']
            target_leave.day1_date = day_data[0]['date']
            target_leave.day1_start_time = day_data[0]['start']
            target_leave.day1_end_time = day_data[0]['end']
        if len(day_data) >= 2:
            target_leave.day2_selected = day_data[1]['name']
            target_leave.day2_date = day_data[1]['date']
            target_leave.day2_start_time = day_data[1]['start']
            target_leave.day2_end_time = day_data[1]['end']
        if len(day_data) >= 3: 
            target_leave.day3_selected = day_data[2]['name']
            target_leave.day3_date = day_data[2]['date']
            target_leave.day3_start_time = day_data[2]['start']
            target_leave.day3_end_time = day_data[2]['end']
        if not weekend_leave: 
            db.session.add(target_leave)
        try:
            db.session.commit()
            if len(selected_days) == 3:
                 flash(flash_msg + " Ați selectat 3 zile pentru învoire.", 'success') 
            else:
                 flash(flash_msg, 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la salvarea învoirii de weekend: {str(e)}', 'danger')
            return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
        return redirect(url_for('list_weekend_leaves'))
    data_to_populate_form_with = {}
    if request.method == 'POST':
        data_to_populate_form_with = request.form
    elif weekend_leave:
        data_to_populate_form_with = form_data_on_get
    return render_template('add_edit_weekend_leave.html',
                           form_title=form_title,
                           weekend_leave=weekend_leave,
                           students=students_managed,
                           upcoming_weekends=upcoming_fridays_list,
                           form_data=data_to_populate_form_with)

@app.route('/gradat/weekend_leave/cancel/<int:leave_id>', methods=['POST'])
@login_required
def cancel_weekend_leave(leave_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    leave = WeekendLeave.query.get_or_404(leave_id)
    student_of_leave = Student.query.get(leave.student_id)
    if not student_of_leave or student_of_leave.created_by_user_id != current_user.id: flash('Nu aveți permisiunea să anulați această învoire de weekend.', 'danger'); return redirect(url_for('list_weekend_leaves'))
    if leave.status == 'Aprobată':
        leave.status = 'Anulată'
        try: db.session.commit(); flash(f'Învoirea de weekend pentru {student_of_leave.nume} {student_of_leave.prenume} (începând cu {leave.weekend_start_date.strftime("%d.%m")}) a fost anulată.', 'success')
        except Exception as e: db.session.rollback(); flash(f'Eroare la anularea învoirii de weekend: {str(e)}', 'danger')
    else: flash('Această învoire de weekend nu poate fi anulată (statusul curent nu este "Aprobată").', 'warning')
    return redirect(url_for('list_weekend_leaves'))

@app.route('/gradat/weekend_leaves/process_text', methods=['POST'], endpoint='gradat_process_weekend_leaves_text')
@login_required
def process_weekend_leaves_text():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    leave_list_text = request.form.get('weekend_leave_list_text', '').strip() 
    if not leave_list_text:
        flash('Lista de învoiri este goală.', 'warning')
        return redirect(url_for('list_weekend_leaves'))
    lines = leave_list_text.strip().splitlines()
    processed_count = 0
    error_count = 0
    error_details_list = [] 
    for line_raw in lines:
        line_content = line_raw.strip()
        if not line_content:
            continue
        student_name_str, parsed_intervals, is_biserica_req, error_msg = parse_weekend_leave_line(line_content)
        if error_msg and student_name_str is None and not parsed_intervals : 
            continue
        if error_msg:
            error_details_list.append({"line": line_content, "error": error_msg})
            error_count += 1
            continue
        if not parsed_intervals: 
            error_details_list.append({"line": line_content, "error": "Niciun interval valid de procesat."})
            error_count +=1
            continue
        student_obj, student_error = find_student_for_bulk_import(student_name_str, current_user.id)
        if student_error:
            error_details_list.append({"line": line_content, "error": f"Student '{student_name_str}': {student_error}"})
            error_count += 1
            continue
        if not parsed_intervals: 
            error_details_list.append({"line": line_content, "student": student_obj.nume, "error": "Eroare internă: Intervale goale după parsare reușită."})
            error_count += 1
            continue
        first_interval_date = parsed_intervals[0]['date_obj']
        weekend_start_date_obj = first_interval_date - timedelta(days=first_interval_date.weekday()) + timedelta(days=4)
        current_weekend_leave_data = { 
            "day1_date": None, "day1_start_time": None, "day1_end_time": None, "day1_selected": None,
            "day2_date": None, "day2_start_time": None, "day2_end_time": None, "day2_selected": None,
            "day3_date": None, "day3_start_time": None, "day3_end_time": None, "day3_selected": None,
            "intervals_for_conflict_check": []
        }
        distinct_days_processed = set()
        for interval in parsed_intervals:
            interval_date = interval['date_obj']
            delta_days = (interval_date - weekend_start_date_obj).days
            day_slot_key = None 
            day_name_ro = None
            if delta_days == 0 and interval_date.weekday() == 4: 
                day_slot_key = "day1"
                day_name_ro = "Vineri"
            elif delta_days == 1 and interval_date.weekday() == 5: 
                day_slot_key = "day2"
                day_name_ro = "Sambata"
            elif delta_days == 2 and interval_date.weekday() == 6: 
                day_slot_key = "day3"
                day_name_ro = "Duminica"
            else:
                error_details_list.append({"line": line_content, "student": student_obj.nume, "error": f"Data {interval_date.strftime('%d.%m.%Y')} nu corespunde weekendului definit de prima dată ({weekend_start_date_obj.strftime('%d.%m.%Y')})."})
                error_count += 1; break 
            if day_slot_key in distinct_days_processed : 
                 error_details_list.append({"line": line_content, "student": student_obj.nume, "error": f"Intervale multiple specificate pentru aceeași zi ({day_name_ro}). Doar primul va fi considerat."})
                 continue 
            distinct_days_processed.add(day_slot_key)
            current_weekend_leave_data[f"{day_slot_key}_date"] = interval_date
            current_weekend_leave_data[f"{day_slot_key}_start_time"] = interval['start_time_obj']
            current_weekend_leave_data[f"{day_slot_key}_end_time"] = interval['end_time_obj']
            current_weekend_leave_data[f"{day_slot_key}_selected"] = day_name_ro 
            start_dt = datetime.combine(interval_date, interval['start_time_obj'])
            effective_end_date = interval_date
            if interval['end_time_obj'] < interval['start_time_obj']: effective_end_date += timedelta(days=1)
            end_dt = datetime.combine(effective_end_date, interval['end_time_obj'])
            current_weekend_leave_data["intervals_for_conflict_check"].append({'start': start_dt, 'end': end_dt, 'day_name': day_name_ro})
        if error_count > 0 and error_details_list[-1]["line"] == line_content: 
            continue
        if not distinct_days_processed:
            error_details_list.append({"line": line_content, "student": student_obj.nume, "error": "Niciun interval valid mapat la zilele weekendului."})
            error_count += 1; continue
        conflict_found_for_student = False
        for interval_to_check in current_weekend_leave_data["intervals_for_conflict_check"]:
            conflict = check_leave_conflict(student_obj.id, interval_to_check['start'], interval_to_check['end'], leave_type='weekend_leave')
            if conflict:
                error_details_list.append({"line": line_content, "student": student_obj.nume, "error": f"Conflict pentru {interval_to_check['day_name']}: {conflict}."})
                error_count += 1; conflict_found_for_student = True; break
        if conflict_found_for_student: continue
        new_wl = WeekendLeave(
            student_id=student_obj.id,
            weekend_start_date=weekend_start_date_obj,
            day1_selected=current_weekend_leave_data['day1_selected'], day1_date=current_weekend_leave_data['day1_date'],
            day1_start_time=current_weekend_leave_data['day1_start_time'], day1_end_time=current_weekend_leave_data['day1_end_time'],
            day2_selected=current_weekend_leave_data['day2_selected'], day2_date=current_weekend_leave_data['day2_date'],
            day2_start_time=current_weekend_leave_data['day2_start_time'], day2_end_time=current_weekend_leave_data['day2_end_time'],
            day3_selected=current_weekend_leave_data['day3_selected'], day3_date=current_weekend_leave_data['day3_date'],
            day3_start_time=current_weekend_leave_data['day3_start_time'], day3_end_time=current_weekend_leave_data['day3_end_time'],
            duminica_biserica=(is_biserica_req and current_weekend_leave_data['day3_selected'] == "Duminica"), 
            status='Aprobată',
            created_by_user_id=current_user.id,
            reason=f"Procesare text: {line_content[:100]}" 
        )
        db.session.add(new_wl)
        processed_count += 1
    try:
        if processed_count > 0: 
            db.session.commit()
            flash(f'{processed_count} învoiri de weekend procesate și adăugate cu succes.', 'success')
        elif error_count == 0 and processed_count == 0 : 
             flash('Nu au fost furnizate date de procesat.', 'info')
        if error_count > 0:
            flash(f'{error_count} linii nu au putut fi procesate sau au generat erori.', 'danger')
            error_flash_message = "Detalii erori:<br>"
            for err_detail in error_details_list[:5]: 
                error_flash_message += f"- Linia: '{err_detail['line'][:60]}...' Student: {err_detail.get('student','N/A')} Eroare: {err_detail['error']}<br>"
            if len(error_details_list) > 5:
                error_flash_message += f"... și încă {len(error_details_list) - 5} erori."
            flash(error_flash_message, 'warning')
        log_action("BULK_IMPORT_WEEKEND_LEAVES_COMPLETED",
                   description=f"User {current_user.username} ran bulk weekend leave import. Added: {processed_count}, Errors: {error_count}. Line count: {len(lines)}",
                   details_after_dict={"added_count": processed_count, "error_count": error_count, "total_lines_input": len(lines), "first_few_error_details": error_details_list[:3]})
        db.session.commit() 
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare majoră la salvarea învoirilor de weekend din text: {str(e)}', 'danger')
        try:
            log_action("BULK_IMPORT_WEEKEND_LEAVES_FAIL_MAJOR",
                       description=f"User {current_user.username} bulk weekend leave import failed critically. Error: {str(e)}",
                       details_after_dict={"added_count": processed_count, "error_count": error_count, "exception": str(e)})
            db.session.commit()
        except Exception as log_e:
            app.logger.error(f"CRITICAL: Failed to commit failure log for BULK_IMPORT_WEEKEND_LEAVES_FAIL_MAJOR: {str(log_e)}")
    return redirect(url_for('list_weekend_leaves'))

@app.route('/gradat/weekend_leaves/export_word', endpoint='gradat_export_weekend_leaves_word')
@login_required
def export_weekend_leaves_word():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    student_id_tuples = db.session.query(Student.id).filter_by(created_by_user_id=current_user.id).all()
    student_ids = [s[0] for s in student_id_tuples]
    if not student_ids:
        flash('Nu aveți studenți pentru a exporta învoiri de weekend.', 'info')
        return redirect(url_for('list_weekend_leaves'))
    leaves_to_export = WeekendLeave.query.options(joinedload(WeekendLeave.student)).filter(
        WeekendLeave.student_id.in_(student_ids),
        WeekendLeave.status == 'Aprobată'
    ).join(Student).order_by(Student.nume, Student.prenume, WeekendLeave.weekend_start_date).all()
    leaves_to_export = [leave for leave in leaves_to_export if leave.is_overall_active_or_upcoming]
    if not leaves_to_export:
        flash('Nicio învoire de weekend activă sau viitoare de exportat.', 'info')
        return redirect(url_for('list_weekend_leaves'))
    document = Document()
    document.add_heading('Raport Învoiri Weekend', level=1).alignment = WD_ALIGN_PARAGRAPH.CENTER
    user_info_text = f"Raport generat de: {current_user.username}\nData generării: {datetime.now().strftime('%d-%m-%Y %H:%M')}"
    p_user = document.add_paragraph()
    p_user.add_run(user_info_text).italic = True
    p_user.alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_paragraph()
    table = document.add_table(rows=1, cols=6) 
    table.style = 'Table Grid'
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = table.rows[0].cells
    col_titles = ['Nr. Crt.', 'Grad', 'Nume și Prenume', 'Weekend (Vineri)', 'Intervale Selectate', 'Motiv (Biserică)']
    for i, title in enumerate(col_titles):
        hdr_cells[i].text = title
        hdr_cells[i].paragraphs[0].runs[0].font.bold = True
        hdr_cells[i].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    for idx, leave in enumerate(leaves_to_export):
        row_cells = table.add_row().cells
        row_cells[0].text = str(idx + 1)
        row_cells[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[1].text = leave.student.grad_militar
        row_cells[2].text = f"{leave.student.nume} {leave.student.prenume}"
        row_cells[3].text = leave.weekend_start_date.strftime('%d.%m.%Y')
        row_cells[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        intervals_str = []
        for interval in leave.get_intervals():
            intervals_str.append(f"{interval['day_name']} ({interval['start'].strftime('%d.%m')}) {interval['start'].strftime('%H:%M')}-{interval['end'].strftime('%H:%M')}")
        row_cells[4].text = "; ".join(intervals_str) if intervals_str else "N/A"
        reason_text = leave.reason or ""
        if leave.duminica_biserica:
            reason_text = (reason_text + " (Biserică Duminică)").strip()
        if not reason_text: reason_text = "-"
        row_cells[5].text = reason_text
    widths = {0: 0.5, 1: 0.7, 2: 1.8, 3: 1.0, 4: 2.8, 5: 1.5} 
    for col_idx, width_val in widths.items():
        for row in table.rows:
            if col_idx < len(row.cells): 
                 row.cells[col_idx].width = Inches(width_val)
    style = document.styles['Normal']
    font = style.font
    font.name = 'Calibri'
    font.size = Pt(11)
    f = io.BytesIO()
    document.save(f)
    f.seek(0)
    filename = f"Raport_Invoiri_Weekend_{current_user.username}_{date.today().strftime('%Y%m%d')}.docx"
    return send_file(f,
                     download_name=filename,
                     as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

@app.route('/gradat/weekend_leaves/delete/<int:leave_id>', methods=['POST'])
@app.route('/admin/weekend_leaves/delete/<int:leave_id>', methods=['POST'])
@login_required
def delete_weekend_leave(leave_id):
    leave_to_delete = db.session.get(WeekendLeave, leave_id)
    if not leave_to_delete:
        flash('Învoirea de weekend nu a fost găsită.', 'danger')
        return redirect(url_for('list_weekend_leaves') if current_user.role == 'gradat' else url_for('admin_dashboard_route'))
    student_owner = db.session.get(Student, leave_to_delete.student_id)
    if current_user.role == 'gradat':
        if not student_owner or student_owner.created_by_user_id != current_user.id:
            flash('Nu aveți permisiunea să ștergeți această învoire de weekend.', 'danger')
            return redirect(url_for('list_weekend_leaves'))
        redirect_url = url_for('list_weekend_leaves')
    elif current_user.role == 'admin':
        if student_owner and student_owner.creator and student_owner.creator.username != current_user.username:
             flash(f'Atenție: Ștergeți o învoire de weekend pentru studentul {student_owner.nume} {student_owner.prenume}, gestionat de {student_owner.creator.username}.', 'warning')
        redirect_url = request.referrer or url_for('admin_dashboard_route')
    else:
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    student_name_for_flash = f"{student_owner.grad_militar} {student_owner.nume} {student_owner.prenume}" if student_owner else "N/A"
    leave_details_for_flash = f"din weekend-ul {leave_to_delete.weekend_start_date.strftime('%d.%m.%Y')}"
    try:
        db.session.delete(leave_to_delete)
        db.session.commit()
        flash(f'Învoirea de weekend pentru {student_name_for_flash} {leave_details_for_flash} a fost ștearsă.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la ștergerea învoirii de weekend: {str(e)}', 'danger')
    return redirect(redirect_url)

# --- Rute pentru Servicii ---
@app.route('/gradat/services')
@login_required
def list_services():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    students_managed_by_gradat = Student.query.filter_by(created_by_user_id=current_user.id).with_entities(Student.id).all()
    student_ids = [s_id[0] for s_id in students_managed_by_gradat]
    if not student_ids:
        return render_template('list_services.html',
                                upcoming_services=[],
                                past_services=[],
                                title="Management Servicii")
    now = get_localized_now() 
    upcoming_services = ServiceAssignment.query.options(joinedload(ServiceAssignment.student))\
                            .filter(
                                ServiceAssignment.student_id.in_(student_ids),
                                ServiceAssignment.end_datetime >= now
                            ).order_by(ServiceAssignment.start_datetime.asc()).all()
    past_services = ServiceAssignment.query.options(joinedload(ServiceAssignment.student))\
                        .filter(
                            ServiceAssignment.student_id.in_(student_ids),
                            ServiceAssignment.end_datetime < now
                        ).order_by(ServiceAssignment.start_datetime.desc()).limit(50).all()
    return render_template('list_services.html',
                           upcoming_services=upcoming_services,
                           past_services=past_services,
                           title="Management Servicii")

@app.route('/gradat/services/assign', methods=['GET', 'POST'])
@app.route('/gradat/services/edit/<int:assignment_id>', methods=['GET', 'POST'])
@login_required
def assign_service(assignment_id=None):
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    form_title = "Asignează Serviciu Nou"
    service_assignment = None
    form_data_for_template = {}
    if assignment_id:
        service_assignment = ServiceAssignment.query.get_or_404(assignment_id)
        student_of_service = Student.query.get(service_assignment.student_id)
        if not student_of_service or student_of_service.created_by_user_id != current_user.id:
            flash('Acces neautorizat la acest serviciu.', 'danger')
            return redirect(url_for('list_services'))
        form_title = f"Editare Serviciu: {student_of_service.grad_militar} {student_of_service.nume} ({service_assignment.service_type})"
        form_data_for_template = {
            'student_id': str(service_assignment.student_id),
            'service_type': service_assignment.service_type,
            'service_date': service_assignment.service_date.strftime('%Y-%m-%d'),
            'start_time': service_assignment.start_datetime.strftime('%H:%M'),
            'end_time': service_assignment.end_datetime.strftime('%H:%M'),
            'participates_in_roll_call': 'true' if service_assignment.participates_in_roll_call else '',
            'notes': service_assignment.notes or ''
        }
    students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    if not students and not assignment_id:
        flash('Nu aveți studenți pentru a le asigna servicii.', 'warning')
        return redirect(url_for('list_students'))
    default_times_for_js = { 
        "GSS": ("07:00", "07:00"), "SVM": ("05:50", "20:00"),
        "Intervenție": ("20:00", "00:00"),
        "Planton 1": ("22:00", "00:00"), "Planton 2": ("00:00", "02:00"),
        "Planton 3": ("02:00", "04:00"), "Altul": ("", "")
    }
    today_iso_str = get_localized_now().date().isoformat() 
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        service_type = request.form.get('service_type')
        service_date_str = request.form.get('service_date')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        participates = 'participates_in_roll_call' in request.form
        notes = request.form.get('notes', '').strip()
        current_form_data = request.form
        if not all([student_id, service_type, service_date_str, start_time_str, end_time_str]):
            flash('Toate câmpurile marcate cu * (student, tip, dată, ore) sunt obligatorii.', 'warning')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=today_iso_str, form_data=current_form_data)
        try:
            service_date_obj = datetime.strptime(service_date_str, '%Y-%m-%d').date()
            start_time_obj = datetime.strptime(start_time_str, '%H:%M').time()
            end_time_obj = datetime.strptime(end_time_str, '%H:%M').time()
        except ValueError:
            flash('Format dată sau oră invalid.', 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=today_iso_str, form_data=current_form_data)
        start_dt_obj = datetime.combine(service_date_obj, start_time_obj) 
        effective_end_date = service_date_obj
        if end_time_obj < start_time_obj:
            effective_end_date += timedelta(days=1)
        elif service_type == "GSS" and end_time_obj == start_time_obj: 
            effective_end_date += timedelta(days=1)
        end_dt_obj = datetime.combine(effective_end_date, end_time_obj)
        if end_dt_obj <= start_dt_obj: 
            flash('Intervalul orar al serviciului este invalid (sfârșitul trebuie să fie după început).', 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=today_iso_str, form_data=current_form_data)
        stud = Student.query.filter_by(id=student_id, created_by_user_id=current_user.id).first()
        if not stud:
            flash('Student selectat invalid sau nu vă aparține.', 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=today_iso_str, form_data=current_form_data)
        conflict_msg = check_service_conflict_for_student(stud.id, start_dt_obj, end_dt_obj, service_type, assignment_id)
        if conflict_msg:
            flash(f"Conflict: studentul are deja {conflict_msg}", 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=today_iso_str, form_data=current_form_data)
        if service_assignment:
            service_assignment.student_id = stud.id
            service_assignment.service_type = service_type
            service_assignment.service_date = service_date_obj
            service_assignment.start_datetime = start_dt_obj
            service_assignment.end_datetime = end_dt_obj
            service_assignment.participates_in_roll_call = participates
            service_assignment.notes = notes
            flash_msg = f'Serviciul {service_type} pentru {stud.nume} {stud.prenume} a fost actualizat!'
        else:
            new_assignment = ServiceAssignment(
                student_id=stud.id, service_type=service_type, service_date=service_date_obj,
                start_datetime=start_dt_obj, end_datetime=end_dt_obj,
                participates_in_roll_call=participates, notes=notes, created_by_user_id=current_user.id
            )
            db.session.add(new_assignment)
            flash_msg = f'Serviciul {service_type} a fost asignat lui {stud.nume} {stud.prenume}.'
        try:
            db.session.commit()
            flash(flash_msg, 'success')
            return redirect(url_for('list_services'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la salvarea serviciului: {str(e)}', 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=today_iso_str, form_data=current_form_data)
    data_to_populate_form_with = {}
    if request.method == 'POST':
        data_to_populate_form_with = request.form
    elif service_assignment: 
        data_to_populate_form_with = form_data_for_template
    return render_template('assign_service.html',
                           form_title=form_title,
                           service_assignment=service_assignment,
                           students=students,
                           service_types=SERVICE_TYPES,
                           default_times=default_times_for_js,
                           today_str=today_iso_str, 
                           form_data=data_to_populate_form_with)

@app.route('/gradat/services/assign_multiple', methods=['GET', 'POST'])
@login_required
def assign_multiple_services():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    if not students:
        flash('Nu aveți studenți în evidență pentru a le asigna servicii.', 'warning')
        return redirect(url_for('list_services')) 
    default_times_for_js = {
        "GSS": ("07:00", "07:00"), "SVM": ("05:50", "20:00"),
        "Intervenție": ("20:00", "00:00"),
        "Planton 1": ("22:00", "00:00"), "Planton 2": ("00:00", "02:00"),
        "Planton 3": ("02:00", "04:00"), "Altul": ("", "")
    }
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        if not student_id:
            flash('Trebuie să selectați un student.', 'warning')
            return redirect(url_for('assign_multiple_services'))
        stud = Student.query.filter_by(id=student_id, created_by_user_id=current_user.id).first()
        if not stud:
            flash('Student invalid sau nu vă aparține.', 'danger')
            return redirect(url_for('assign_multiple_services'))
        service_indices = sorted(list(set(key.split('_')[1] for key in request.form if key.startswith('service_type_'))))
        added_count = 0
        error_count = 0
        error_messages = []
        for index in service_indices:
            service_type = request.form.get(f'service_type_{index}')
            service_date_str = request.form.get(f'service_date_{index}')
            start_time_str = request.form.get(f'start_time_{index}')
            end_time_str = request.form.get(f'end_time_{index}')
            participates_str = request.form.get(f'participates_{index}') 
            notes = request.form.get(f'notes_{index}', '').strip()
            if not all([service_type, service_date_str, start_time_str, end_time_str]):
                if service_type: 
                    error_messages.append(f"Serviciul #{int(index)+1}: Date incomplete (tip, dată, ore).")
                    error_count += 1
                continue
            try:
                service_date_obj = datetime.strptime(service_date_str, '%Y-%m-%d').date()
                start_time_obj = datetime.strptime(start_time_str, '%H:%M').time()
                end_time_obj = datetime.strptime(end_time_str, '%H:%M').time()
            except ValueError:
                error_messages.append(f"Serviciul #{int(index)+1} ({service_type}): Format dată/oră invalid.")
                error_count += 1
                continue
            start_dt_obj = datetime.combine(service_date_obj, start_time_obj)
            effective_end_date = service_date_obj
            if end_time_obj < start_time_obj:
                effective_end_date += timedelta(days=1)
            elif service_type == "GSS" and end_time_obj == start_time_obj: 
                effective_end_date += timedelta(days=1)
            end_dt_obj = datetime.combine(effective_end_date, end_time_obj)
            if end_dt_obj <= start_dt_obj:
                error_messages.append(f"Serviciul #{int(index)+1} ({service_type}): Interval orar invalid.")
                error_count += 1
                continue
            participates_bool = (participates_str == 'on')
            conflict_msg = check_service_conflict_for_student(stud.id, start_dt_obj, end_dt_obj, service_type, None) 
            if conflict_msg:
                error_messages.append(f"Serviciul #{int(index)+1} ({service_type} pe {service_date_str}): Conflict - studentul are deja {conflict_msg}.")
                error_count += 1
                continue
            new_assignment = ServiceAssignment(
                student_id=stud.id, service_type=service_type, service_date=service_date_obj,
                start_datetime=start_dt_obj, end_datetime=end_dt_obj,
                participates_in_roll_call=participates_bool, notes=notes,
                created_by_user_id=current_user.id
            )
            db.session.add(new_assignment)
            added_count +=1
        if error_count > 0:
            for msg in error_messages:
                flash(msg, 'danger')
            if added_count > 0: 
                 try:
                    db.session.commit()
                    flash(f'{added_count} servicii au fost adăugate cu succes pentru {stud.nume} {stud.prenume}.', 'success')
                 except Exception as e:
                    db.session.rollback()
                    flash(f'Eroare la salvarea unor servicii: {str(e)}', 'danger')
            else: 
                db.session.rollback() 
            return redirect(url_for('assign_multiple_services', student_id_selected=stud.id))
        if added_count > 0:
            try:
                db.session.commit()
                flash(f'{added_count} servicii au fost adăugate cu succes pentru {stud.nume} {stud.prenume}!', 'success')
                return redirect(url_for('list_services'))
            except Exception as e:
                db.session.rollback()
                flash(f'Eroare la salvarea serviciilor: {str(e)}', 'danger')
                return redirect(url_for('assign_multiple_services', student_id_selected=stud.id))
        else: 
            flash('Niciun serviciu valid nu a fost introdus pentru a fi adăugat.', 'info')
            return redirect(url_for('assign_multiple_services', student_id_selected=stud.id if stud else None))
    student_id_selected_on_get = request.args.get('student_id_selected', type=int)
    today_iso_str_get = get_localized_now().date().isoformat() 
    return render_template('assign_multiple_services.html',
                           students=students,
                           service_types=SERVICE_TYPES,
                           default_times_json=json.dumps(default_times_for_js), 
                           today_str=today_iso_str_get,
                           student_id_selected=student_id_selected_on_get)
@app.route('/gradat/services/delete/<int:assignment_id>', methods=['POST'])
@login_required
def delete_service_assignment(assignment_id):
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    assign_del = ServiceAssignment.query.get_or_404(assignment_id)
    student_owner = Student.query.filter_by(id=assign_del.student_id, created_by_user_id=current_user.id).first()
    if not student_owner:
        flash('Acces neautorizat la acest serviciu pentru ștergere.', 'danger')
        return redirect(url_for('list_services'))
    student_name = assign_del.student.nume + " " + assign_del.student.prenume if assign_del.student else "N/A"
    service_type_deleted = assign_del.service_type
    try:
        db.session.delete(assign_del)
        db.session.commit()
        flash(f'Serviciul ({service_type_deleted}) pentru {student_name} a fost șters.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la ștergerea serviciului: {str(e)}', 'danger')
    return redirect(url_for('list_services'))

# --- Rapoarte ---
@app.route('/company_commander/report/text', methods=['GET'])
@login_required
def text_report_display_company():
    if current_user.role != 'comandant_companie':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    company_id_str = _get_commander_unit_id(current_user.username, "CmdC")
    if not company_id_str:
        flash('ID-ul companiei nu a putut fi determinat.', 'danger')
        return redirect(url_for('dashboard'))
    roll_call_datetime = get_standard_roll_call_datetime()
    report_datetime_str = roll_call_datetime.strftime('%d.%m.%Y, %H:%M')
    students_in_company = Student.query.filter_by(companie=company_id_str).all()
    if not students_in_company:
        flash(f'Niciun student în compania {company_id_str} pentru a genera raportul.', 'info')
        return render_template('text_report_display.html', report_title=f"Raport Compania {company_id_str}", report_content="Niciun student în unitate.", report_datetime_str=report_datetime_str)
    company_presence_data = _calculate_presence_data(students_in_company, roll_call_datetime)
    report_lines = []
    report_lines.append(f"RAPORT OPERATIV - COMPANIA {company_id_str}")
    report_lines.append(f"Data și ora raportului: {report_datetime_str}")
    report_lines.append("-" * 30)
    report_lines.append(f"Efectiv control (Ec): {company_presence_data['efectiv_control']}")
    report_lines.append(f"Efectiv prezent (Ep): {company_presence_data['efectiv_prezent_total']}")
    report_lines.append(f"  - În formație: {company_presence_data['in_formation_count']}")
    report_lines.append(f"  - La Servicii: {company_presence_data['on_duty_count']}") 
    report_lines.append(f"  - Gradat Pluton (prezent): {company_presence_data['platoon_graded_duty_count']}")
    report_lines.append(f"Efectiv absent (Ea): {company_presence_data['efectiv_absent_total']}")
    report_lines.append("-" * 30)
    if company_presence_data['in_formation_students_details']:
        report_lines.append("\nPREZENȚI ÎN FORMAȚIE:")
        for detail in company_presence_data['in_formation_students_details']: report_lines.append(f"  - {detail}")
    if company_presence_data['on_duty_students_details']:
        report_lines.append("\nLA SERVICII:") 
        for detail in company_presence_data['on_duty_students_details']: report_lines.append(f"  - {detail}")
    if company_presence_data['platoon_graded_duty_students_details']:
        report_lines.append("\nGRADAȚI PLUTON (prezenți):")
        for detail in company_presence_data['platoon_graded_duty_students_details']: report_lines.append(f"  - {detail}")
    if company_presence_data['absent_students_details']:
        report_lines.append("\nABSENȚI MOTIVAT:")
        for detail in company_presence_data['absent_students_details']: report_lines.append(f"  - {detail}")
    report_lines.append("\n" + "-" * 30)
    report_lines.append("Raport generat de sistem.")
    final_report_content = "\n".join(report_lines)
    return render_template('text_report_display.html',
                           report_title=f"Raport Text Compania {company_id_str}",
                           report_content=final_report_content,
                           report_datetime_str=report_datetime_str)

@app.route('/battalion_commander/report/text', methods=['GET'])
@login_required
def text_report_display_battalion():
    if current_user.role != 'comandant_batalion':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    battalion_id_str = _get_commander_unit_id(current_user.username, "CmdB")
    if not battalion_id_str:
        flash('ID-ul batalionului nu a putut fi determinat.', 'danger')
        return redirect(url_for('dashboard'))
    roll_call_datetime = get_standard_roll_call_datetime()
    report_datetime_str = roll_call_datetime.strftime('%d.%m.%Y, %H:%M')
    students_in_battalion = Student.query.filter_by(batalion=battalion_id_str).all()
    if not students_in_battalion:
        flash(f'Niciun student în batalionul {battalion_id_str} pentru a genera raportul.', 'info')
        return render_template('text_report_display.html', report_title=f"Raport Batalionul {battalion_id_str}", report_content="Niciun student în unitate.", report_datetime_str=report_datetime_str)
    total_battalion_presence = _calculate_presence_data(students_in_battalion, roll_call_datetime)
    report_lines = []
    report_lines.append(f"RAPORT OPERATIV - BATALIONUL {battalion_id_str}")
    report_lines.append(f"Data și ora raportului: {report_datetime_str}")
    report_lines.append("=" * 40)
    report_lines.append("SITUAȚIE CENTRALIZATOARE BATALION:")
    report_lines.append(f"  Efectiv control (Ec): {total_battalion_presence['efectiv_control']}")
    report_lines.append(f"  Efectiv prezent (Ep): {total_battalion_presence['efectiv_prezent_total']}")
    report_lines.append(f"    - În formație: {total_battalion_presence['in_formation_count']}")
    report_lines.append(f"    - La Servicii: {total_battalion_presence['on_duty_count']}") 
    report_lines.append(f"    - Gradat Pluton (prezent): {total_battalion_presence['platoon_graded_duty_count']}")
    report_lines.append(f"  Efectiv absent (Ea): {total_battalion_presence['efectiv_absent_total']}")
    report_lines.append("=" * 40)
    companies_in_battalion = sorted(list(set(s.companie for s in students_in_battalion if s.companie)))
    for company_id_loop in companies_in_battalion:
        students_in_company_loop = [s for s in students_in_battalion if s.companie == company_id_loop]
        company_presence_data = _calculate_presence_data(students_in_company_loop, roll_call_datetime)
        report_lines.append(f"\nSITUAȚIE COMPANIA {company_id_loop}:")
        report_lines.append(f"  Ec: {company_presence_data['efectiv_control']}, Ep: {company_presence_data['efectiv_prezent_total']}, Ea: {company_presence_data['efectiv_absent_total']}")
        report_lines.append(f"    În formație: {company_presence_data['in_formation_count']}")
        report_lines.append(f"    La Servicii: {company_presence_data['on_duty_count']}") 
        report_lines.append(f"    Gradat Pluton (prezent): {company_presence_data['platoon_graded_duty_count']}")
        if company_presence_data['absent_students_details']:
            report_lines.append("    Absenți motivat:")
            for detail in company_presence_data['absent_students_details']:
                report_lines.append(f"      - {detail}")
        report_lines.append("-" * 30)
    report_lines.append("\n" + "=" * 40)
    report_lines.append("DETALII ABSENȚE LA NIVEL DE BATALION (dacă există):")
    if total_battalion_presence['absent_students_details']:
        for detail in total_battalion_presence['absent_students_details']:
            report_lines.append(f"  - {detail}")
    else:
        report_lines.append("  Nicio absență înregistrată la nivel de batalion.")
    report_lines.append("\n" + "=" * 40)
    report_lines.append("Raport generat de sistem.")
    final_report_content = "\n".join(report_lines)
    return render_template('text_report_display.html',
                           report_title=f"Raport Text Batalionul {battalion_id_str}",
                           report_content=final_report_content,
                           report_datetime_str=report_datetime_str)

@app.route('/gradat/permissions/import_page', methods=['GET'], endpoint='gradat_page_import_permissions')
@login_required
def gradat_page_import_permissions():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    # Corrected template filename
    return render_template('gradat_import_permissions.html', title="Import Masiv Permisii din Text")

@app.route('/gradat/weekend_leaves/import_page', methods=['GET'], endpoint='gradat_page_import_weekend_leaves')
@login_required
def gradat_page_import_weekend_leaves():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    # Corrected template filename
    return render_template('gradat_import_weekend_leaves.html', title="Import Masiv Învoiri Weekend din Text")

@app.route('/commander/presence_report_data', methods=['GET'])
@login_required
def presence_report():
    if current_user.role not in ['comandant_companie', 'comandant_batalion']:
        return jsonify({"error": "Acces neautorizat"}), 403
    unit_type = request.args.get('unit_type') 
    unit_id = request.args.get('unit_id')
    report_datetime_str = request.args.get('report_datetime', get_localized_now().isoformat()) 
    try:
        report_datetime = datetime.fromisoformat(report_datetime_str)
        if report_datetime.tzinfo is None:
            report_datetime = EUROPE_BUCHAREST.localize(report_datetime)
        else:
            report_datetime = report_datetime.astimezone(EUROPE_BUCHAREST)
    except ValueError:
        return jsonify({"error": "Format dată/oră raport invalid."}), 400
    if not unit_id:
        return jsonify({"error": "ID unitate lipsă."}), 400
    students_in_unit_q = Student.query
    if unit_type == 'company':
        students_in_unit_q = students_in_unit_q.filter(Student.companie == unit_id)
    elif unit_type == 'battalion':
        students_in_unit_q = students_in_unit_q.filter(Student.batalion == unit_id)
    else:
        return jsonify({"error": "Tip unitate invalid."}), 400
    students_for_report = students_in_unit_q.all()
    if not students_for_report:
        return jsonify({"error": f"Niciun student găsit pentru {unit_type} {unit_id}."}), 404
    presence_data = _calculate_presence_data(students_for_report, report_datetime)
    presence_data['report_datetime_display'] = report_datetime.strftime('%d %B %Y, %H:%M:%S %Z')
    return jsonify(presence_data)

@app.route('/admin/action_logs', endpoint='admin_action_logs')
@login_required
def admin_action_logs():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    page = request.args.get('page', 1, type=int)
    per_page = 20 
    logs_query = ActionLog.query.options(joinedload(ActionLog.user)).order_by(ActionLog.timestamp.desc())
    logs_pagination = logs_query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('admin_action_logs.html',
                           logs_pagination=logs_pagination,
                           title="Jurnal Acțiuni Sistem")

@app.route('/admin/profile/change_password', methods=['GET', 'POST'], endpoint='admin_change_self_password')
@login_required
def admin_change_self_password():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        if not current_user.check_password(current_password):
            flash('Parola curentă este incorectă.', 'danger')
            return redirect(url_for('admin_change_self_password'))
        if not new_password or len(new_password) < 6: 
            flash('Parola nouă trebuie să aibă minim 6 caractere.', 'warning')
            return redirect(url_for('admin_change_self_password'))
        if new_password != confirm_new_password:
            flash('Parolele noi nu se potrivesc.', 'warning')
            return redirect(url_for('admin_change_self_password'))
        details_before = {"user_id": current_user.id, "username": current_user.username, "action": "Attempt change own password"}
        current_user.set_password(new_password)
        try:
            log_action("ADMIN_CHANGE_OWN_PASSWORD_SUCCESS", target_model_name="User", target_id=current_user.id,
                       details_before_dict=details_before, 
                       description=f"Admin {current_user.username} changed their own password successfully.")
            db.session.commit()
            flash('Parola a fost schimbată cu succes!', 'success')
            return redirect(url_for('admin_dashboard_route'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la schimbarea parolei: {str(e)}', 'danger')
            log_action("ADMIN_CHANGE_OWN_PASSWORD_FAIL", target_model_name="User", target_id=current_user.id,
                       details_before_dict=details_before,
                       description=f"Admin {current_user.username} failed to change their own password. Error: {str(e)}")
            db.session.commit() 
            return redirect(url_for('admin_change_self_password'))
    return render_template('admin_change_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard_route'))
    elif current_user.role == 'gradat':
        # Redirecting to gradat_dashboard_route which renders situatie_pluton.html
        return redirect(url_for('gradat_dashboard_route'))
    elif current_user.role == 'comandant_companie':
        return redirect(url_for('company_commander_dashboard'))
    elif current_user.role == 'comandant_batalion':
        return redirect(url_for('battalion_commander_dashboard'))
    else:
        # Fallback, though ideally all authenticated users have a role
        # that directs them to a specific dashboard.
        flash('Rol utilizator necunoscut sau neconfigurat pentru dashboard.', 'warning')
        return redirect(url_for('home'))

@app.route('/admin/user/<int:user_id>/set_personal_code', methods=['GET', 'POST'], endpoint='admin_set_user_personal_code')
@login_required
def admin_set_user_personal_code(user_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash('Utilizatorul specificat nu a fost găsit.', 'danger')
        return redirect(url_for('admin_dashboard_route'))
    if target_user.role == 'admin':
        flash('Codul personal nu poate fi setat pentru un alt administrator prin această metodă.', 'warning')
        return redirect(url_for('admin_dashboard_route'))
    if request.method == 'POST':
        new_code = request.form.get('new_personal_code')
        confirm_new_code = request.form.get('confirm_new_personal_code')
        if not new_code or len(new_code) < 4:
            flash('Noul cod personal trebuie să aibă minim 4 caractere.', 'warning')
            return render_template('admin_set_user_personal_code.html', target_user=target_user)
        if new_code != confirm_new_code:
            flash('Codurile personale introduse nu se potrivesc.', 'warning')
            return render_template('admin_set_user_personal_code.html', target_user=target_user)
        details_before = model_to_dict(target_user, exclude_fields=['password_hash', 'unique_code', 'personal_code_hash'])
        details_before['personal_code_was_set'] = target_user.personal_code_hash is not None
        details_before['was_first_login'] = target_user.is_first_login
        target_user.set_personal_code(new_code) 
        try:
            details_after = model_to_dict(target_user, exclude_fields=['password_hash', 'unique_code', 'personal_code_hash'])
            details_after['personal_code_is_set'] = True
            details_after['is_first_login'] = False
            log_action("ADMIN_SET_USER_PERSONAL_CODE_SUCCESS", target_model_name="User", target_id=target_user.id,
                       details_before_dict=details_before, details_after_dict=details_after,
                       description=f"Admin {current_user.username} set new personal code for user {target_user.username} (ID: {target_user.id}).")
            db.session.commit()
            flash(f'Noul cod personal pentru utilizatorul {target_user.username} a fost setat cu succes.', 'success')
            return redirect(url_for('admin_dashboard_route'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la setarea codului personal: {str(e)}', 'danger')
            log_action("ADMIN_SET_USER_PERSONAL_CODE_FAIL", target_model_name="User", target_id=target_user.id,
                       details_before_dict=details_before, 
                       description=f"Admin {current_user.username} failed to set new personal code for {target_user.username}. Error: {str(e)}")
            db.session.commit()
            return render_template('admin_set_user_personal_code.html', target_user=target_user)
    return render_template('admin_set_user_personal_code.html', target_user=target_user)

@app.route('/admin/permissions', endpoint='admin_list_permissions')
@login_required
def admin_list_permissions():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query = Permission.query.options(
        joinedload(Permission.student).joinedload(Student.creator), 
        joinedload(Permission.creator) 
    ).order_by(Permission.start_datetime.desc())
    search_student_name = request.args.get('search_student_name', '').strip()
    filter_status = request.args.get('filter_status', '').strip()
    if search_student_name:
        search_pattern = f"%{unidecode(search_student_name.lower())}%"
        query = query.join(Permission.student).filter(
            or_(
                func.lower(unidecode(Student.nume)).like(search_pattern),
                func.lower(unidecode(Student.prenume)).like(search_pattern)
            )
        )
    if filter_status:
        query = query.filter(Permission.status == filter_status)
    permissions_pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    statuses = sorted(list(set(item[0] for item in db.session.query(Permission.status).distinct().all() if item[0])))
    return render_template('admin_list_permissions.html',
                           permissions_pagination=permissions_pagination,
                           search_student_name=search_student_name,
                           filter_status=filter_status,
                           statuses=statuses,
                           title="Listă Generală Permisii (Admin)")

@app.route('/admin/daily_leaves', endpoint='admin_list_daily_leaves')
@login_required
def admin_list_daily_leaves():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query = DailyLeave.query.options(
        joinedload(DailyLeave.student),
        joinedload(DailyLeave.creator)
    ).order_by(DailyLeave.leave_date.desc(), DailyLeave.start_time.desc())
    search_student_name = request.args.get('search_student_name', '').strip()
    filter_status = request.args.get('filter_status', '').strip()
    filter_date = request.args.get('filter_date', '').strip()
    if search_student_name:
        search_pattern = f"%{unidecode(search_student_name.lower())}%"
        query = query.join(DailyLeave.student).filter(
            or_(
                func.lower(unidecode(Student.nume)).like(search_pattern),
                func.lower(unidecode(Student.prenume)).like(search_pattern)
            )
        )
    if filter_status:
        query = query.filter(DailyLeave.status == filter_status)
    if filter_date:
        try:
            date_obj = datetime.strptime(filter_date, '%Y-%m-%d').date()
            query = query.filter(DailyLeave.leave_date == date_obj)
        except ValueError:
            flash('Format dată invalid pentru filtrare. Folosiți YYYY-MM-DD.', 'warning')
    daily_leaves_pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    statuses = sorted(list(set(item[0] for item in db.session.query(DailyLeave.status).distinct().all() if item[0])))
    return render_template('admin_list_daily_leaves.html',
                           daily_leaves_pagination=daily_leaves_pagination,
                           search_student_name=search_student_name,
                           filter_status=filter_status,
                           filter_date=filter_date,
                           statuses=statuses,
                           title="Listă Generală Învoiri Zilnice (Admin)")

@app.route('/admin/weekend_leaves', endpoint='admin_list_weekend_leaves')
@login_required
def admin_list_weekend_leaves():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query = WeekendLeave.query.options(
        joinedload(WeekendLeave.student),
        joinedload(WeekendLeave.creator)
    ).order_by(WeekendLeave.weekend_start_date.desc())
    search_student_name = request.args.get('search_student_name', '').strip()
    filter_status = request.args.get('filter_status', '').strip()
    filter_weekend_start_date = request.args.get('filter_weekend_start_date', '').strip() 
    if search_student_name:
        search_pattern = f"%{unidecode(search_student_name.lower())}%"
        query = query.join(WeekendLeave.student).filter(
            or_(
                func.lower(unidecode(Student.nume)).like(search_pattern),
                func.lower(unidecode(Student.prenume)).like(search_pattern)
            )
        )
    if filter_status:
        query = query.filter(WeekendLeave.status == filter_status)
    if filter_weekend_start_date:
        try:
            date_obj = datetime.strptime(filter_weekend_start_date, '%Y-%m-%d').date()
            query = query.filter(WeekendLeave.weekend_start_date == date_obj)
        except ValueError:
            flash('Format dată invalid pentru filtrare (Vineri weekend). Folosiți YYYY-MM-DD.', 'warning')
    weekend_leaves_pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    statuses = sorted(list(set(item[0] for item in db.session.query(WeekendLeave.status).distinct().all() if item[0])))
    return render_template('admin_list_weekend_leaves.html',
                           weekend_leaves_pagination=weekend_leaves_pagination,
                           search_student_name=search_student_name,
                           filter_status=filter_status,
                           filter_weekend_start_date=filter_weekend_start_date,
                           statuses=statuses,
                           title="Listă Generală Învoiri Weekend (Admin)")

@app.route('/admin/services', endpoint='admin_list_services')
@login_required
def admin_list_services():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query = ServiceAssignment.query.options(
        joinedload(ServiceAssignment.student),
        joinedload(ServiceAssignment.creator)
    ).order_by(ServiceAssignment.start_datetime.desc())
    search_student_name = request.args.get('search_student_name', '').strip()
    filter_service_type = request.args.get('filter_service_type', '').strip()
    filter_service_date = request.args.get('filter_service_date', '').strip()
    if search_student_name:
        search_pattern = f"%{unidecode(search_student_name.lower())}%"
        query = query.join(ServiceAssignment.student).filter(
            or_(
                func.lower(unidecode(Student.nume)).like(search_pattern),
                func.lower(unidecode(Student.prenume)).like(search_pattern)
            )
        )
    if filter_service_type:
        query = query.filter(ServiceAssignment.service_type == filter_service_type)
    if filter_service_date:
        try:
            date_obj = datetime.strptime(filter_service_date, '%Y-%m-%d').date()
            query = query.filter(ServiceAssignment.service_date == date_obj)
        except ValueError:
            flash('Format dată invalid pentru filtrare (Data serviciu). Folosiți YYYY-MM-DD.', 'warning')
    services_pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    service_types_for_filter = sorted(list(set(item[0] for item in db.session.query(ServiceAssignment.service_type).distinct().all() if item[0])))
    return render_template('admin_list_services.html',
                           services_pagination=services_pagination,
                           search_student_name=search_student_name,
                           filter_service_type=filter_service_type,
                           filter_service_date=filter_service_date,
                           service_types_for_filter=service_types_for_filter, 
                           title="Listă Generală Servicii (Admin)")

@app.route('/admin/reset/permissions', methods=['POST'], endpoint='admin_reset_permissions')
@login_required
def admin_reset_permissions():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_dashboard_route'))
    try:
        num_deleted = db.session.query(Permission).delete()
        log_action("ADMIN_RESET_DATA_SUCCESS", target_model_name="Permission",
                   description=f"Admin {current_user.username} reset all permissions. {num_deleted} records deleted.")
        db.session.commit()
        flash(f'Toate permisiile ({num_deleted} înregistrări) au fost șterse cu succes!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la resetarea permisiilor: {str(e)}', 'danger')
        log_action("ADMIN_RESET_DATA_FAIL", target_model_name="Permission",
                   description=f"Admin {current_user.username} failed to reset permissions. Error: {str(e)}")
        db.session.commit()
    return redirect(url_for('admin_dashboard_route'))

@app.route('/admin/reset/daily_leaves', methods=['POST'])
@login_required
def admin_reset_daily_leaves():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_dashboard_route'))
    try:
        num_deleted = db.session.query(DailyLeave).delete()
        log_action("ADMIN_RESET_DATA_SUCCESS", target_model_name="DailyLeave",
                   description=f"Admin {current_user.username} reset all daily leaves. {num_deleted} records deleted.")
        db.session.commit()
        flash(f'Toate învoirile zilnice ({num_deleted} înregistrări) au fost șterse cu succes!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la resetarea învoirilor zilnice: {str(e)}', 'danger')
        log_action("ADMIN_RESET_DATA_FAIL", target_model_name="DailyLeave",
                   description=f"Admin {current_user.username} failed to reset daily leaves. Error: {str(e)}")
        db.session.commit()
    return redirect(url_for('admin_dashboard_route'))

@app.route('/admin/reset/weekend_leaves', methods=['POST'])
@login_required
def admin_reset_weekend_leaves():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_dashboard_route'))
    try:
        num_deleted = db.session.query(WeekendLeave).delete()
        log_action("ADMIN_RESET_DATA_SUCCESS", target_model_name="WeekendLeave",
                   description=f"Admin {current_user.username} reset all weekend leaves. {num_deleted} records deleted.")
        db.session.commit()
        flash(f'Toate învoirile de weekend ({num_deleted} înregistrări) au fost șterse cu succes!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la resetarea învoirilor de weekend: {str(e)}', 'danger')
        log_action("ADMIN_RESET_DATA_FAIL", target_model_name="WeekendLeave",
                   description=f"Admin {current_user.username} failed to reset weekend leaves. Error: {str(e)}")
        db.session.commit()
    return redirect(url_for('admin_dashboard_route'))

@app.route('/gradat/weekend_leave/bulk_add', methods=['GET', 'POST'], endpoint='gradat_bulk_add_weekend_leave')
@login_required
def gradat_bulk_add_weekend_leave():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.pluton, Student.nume).all()
    upcoming_fridays_list = get_upcoming_fridays() 
    if request.method == 'POST':
        student_ids_selected = request.form.getlist('student_ids')
        weekend_start_date_str = request.form.get('weekend_start_date')
        selected_days_names = request.form.getlist('selected_days') 
        reason_common = request.form.get('reason', '').strip()
        if not student_ids_selected:
            flash('Nu ați selectat niciun student.', 'warning')
            return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=request.form)
        if not weekend_start_date_str:
            flash('Data de început a weekendului (Vineri) este obligatorie.', 'warning')
            return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=request.form)
        if not selected_days_names:
            flash('Nu ați selectat nicio zi din weekend.', 'warning')
            return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=request.form)
        try:
            friday_date_obj = datetime.strptime(weekend_start_date_str, '%Y-%m-%d').date()
            if friday_date_obj.weekday() != 4: 
                flash('Data de început a weekendului selectată nu este o zi de Vineri.', 'warning')
                return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=request.form)
        except ValueError:
            flash('Format dată weekend invalid.', 'danger')
            return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=request.form)
        day_inputs_from_form = []
        for day_name_form in selected_days_names:
            start_time_str = request.form.get(f'bulk_{day_name_form.lower()}_start_time')
            end_time_str = request.form.get(f'bulk_{day_name_form.lower()}_end_time')
            if not start_time_str or not end_time_str:
                flash(f'Orele de început și sfârșit sunt obligatorii pentru {day_name_form} în formularul de adăugare rapidă.', 'warning')
                return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=request.form)
            try:
                start_time_obj = datetime.strptime(start_time_str, '%H:%M').time()
                end_time_obj = datetime.strptime(end_time_str, '%H:%M').time()
            except ValueError:
                flash(f'Format oră invalid pentru {day_name_form}.', 'danger')
                return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=request.form)
            if end_time_obj == start_time_obj:
                flash(f'Ora de început și sfârșit nu pot fi identice pentru {day_name_form}.', 'warning')
                return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=request.form)
            day_offset_map = {'Vineri': 0, 'Sambata': 1, 'Duminica': 2}
            actual_date_for_day = friday_date_obj + timedelta(days=day_offset_map[day_name_form])
            current_interval_start_dt = datetime.combine(actual_date_for_day, start_time_obj)
            effective_end_date_for_interval = actual_date_for_day
            if end_time_obj < start_time_obj:  
                effective_end_date_for_interval += timedelta(days=1)
            current_interval_end_dt = datetime.combine(effective_end_date_for_interval, end_time_obj)
            if current_interval_end_dt <= current_interval_start_dt:
                flash(f'Interval orar invalid pentru {day_name_form} (sfârșitul trebuie să fie după început).', 'warning')
                return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=request.form)
            day_inputs_from_form.append({
                'name': day_name_form,
                'date': actual_date_for_day,
                'start_time': start_time_obj,
                'end_time': end_time_obj
            })
        day_inputs_from_form.sort(key=lambda x: x['date']) 
        added_count = 0
        skipped_due_to_conflict_count = 0
        error_details_conflict = []
        for student_id_str in student_ids_selected:
            student_id = int(student_id_str)
            conflict_for_this_student = False
            for day_data_input in day_inputs_from_form:
                start_dt_check = datetime.combine(day_data_input['date'], day_data_input['start_time'])
                end_dt_check = datetime.combine(day_data_input['date'], day_data_input['end_time'])
                if day_data_input['end_time'] < day_data_input['start_time']: 
                    end_dt_check += timedelta(days=1)
                conflict_reason = check_leave_conflict(student_id, start_dt_check, end_dt_check, leave_type='weekend_leave', existing_leave_id=None)
                if conflict_reason:
                    student_obj = db.session.get(Student, student_id)
                    error_details_conflict.append(f"Studentul {student_obj.nume} {student_obj.prenume}: conflict pe {day_data_input['name']} ({conflict_reason}). Învoirea nu a fost adăugată.")
                    conflict_for_this_student = True
                    break
            if conflict_for_this_student:
                skipped_due_to_conflict_count += 1
                continue
            new_leave = WeekendLeave(
                student_id=student_id,
                weekend_start_date=friday_date_obj,
                reason=reason_common,
                status='Aprobată',
                created_by_user_id=current_user.id,
                duminica_biserica=False 
            )
            if len(day_inputs_from_form) >= 1:
                new_leave.day1_selected = day_inputs_from_form[0]['name']
                new_leave.day1_date = day_inputs_from_form[0]['date']
                new_leave.day1_start_time = day_inputs_from_form[0]['start_time']
                new_leave.day1_end_time = day_inputs_from_form[0]['end_time']
            if len(day_inputs_from_form) >= 2:
                new_leave.day2_selected = day_inputs_from_form[1]['name']
                new_leave.day2_date = day_inputs_from_form[1]['date']
                new_leave.day2_start_time = day_inputs_from_form[1]['start_time']
                new_leave.day2_end_time = day_inputs_from_form[1]['end_time']
            if len(day_inputs_from_form) >= 3:
                new_leave.day3_selected = day_inputs_from_form[2]['name']
                new_leave.day3_date = day_inputs_from_form[2]['date']
                new_leave.day3_start_time = day_inputs_from_form[2]['start_time']
                new_leave.day3_end_time = day_inputs_from_form[2]['end_time']
            db.session.add(new_leave)
            added_count += 1
        try:
            db.session.commit()
            if added_count > 0:
                flash(f'{added_count} învoiri de weekend au fost adăugate cu succes.', 'success')
            if skipped_due_to_conflict_count > 0:
                flash(f'{skipped_due_to_conflict_count} învoiri au fost omise din cauza conflictelor existente. Detalii mai jos.', 'warning')
                for err_detail in error_details_conflict:
                    flash(err_detail, 'info') 
            if added_count == 0 and skipped_due_to_conflict_count == 0 and len(student_ids_selected) > 0:
                 flash('Nicio învoire nu a fost adăugată. Verificați selecțiile și încercați din nou.', 'info')
            log_action("BULK_ADD_WEEKEND_LEAVE",
                       description=f"User {current_user.username} attempted bulk weekend leave. Added: {added_count}, Skipped (conflict): {skipped_due_to_conflict_count} for weekend starting {friday_date_obj.isoformat()}.",
                       details_after_dict={"students_selected_count": len(student_ids_selected), "days_selected": selected_days_names, "conflicts_details": error_details_conflict[:5]}) 
            db.session.commit() 
            return redirect(url_for('list_weekend_leaves'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la salvarea învoirilor de weekend: {str(e)}', 'danger')
            log_action("BULK_ADD_WEEKEND_LEAVE_FAIL", description=f"Bulk add weekend leave failed for user {current_user.username}. Error: {str(e)}")
            db.session.commit()
    return render_template('bulk_add_weekend_leave.html', students=students_managed, upcoming_fridays=upcoming_fridays_list, form_data=None)

@app.route('/gradat/permission/bulk_add', methods=['GET', 'POST'], endpoint='gradat_bulk_add_permission')
@login_required
def gradat_bulk_add_permission():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.pluton, Student.nume).all()
    if request.method == 'POST':
        student_ids_selected = request.form.getlist('student_ids')
        start_datetime_str = request.form.get('start_datetime')
        end_datetime_str = request.form.get('end_datetime')
        destination = request.form.get('destination', '').strip()
        transport_mode = request.form.get('transport_mode', '').strip()
        reason = request.form.get('reason', '').strip()
        if not student_ids_selected:
            flash('Nu ați selectat niciun student.', 'warning')
            return render_template('bulk_add_permission.html', students=students_managed, form_data=request.form)
        if not start_datetime_str or not end_datetime_str:
            flash('Data de început și de sfârșit sunt obligatorii.', 'warning')
            return render_template('bulk_add_permission.html', students=students_managed, form_data=request.form)
        try:
            start_dt = datetime.strptime(start_datetime_str, '%Y-%m-%dT%H:%M')
            end_dt = datetime.strptime(end_datetime_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Format dată/oră invalid.', 'danger')
            return render_template('bulk_add_permission.html', students=students_managed, form_data=request.form)
        if end_dt <= start_dt:
            flash('Data de sfârșit trebuie să fie după data de început.', 'warning')
            return render_template('bulk_add_permission.html', students=students_managed, form_data=request.form)
        added_count = 0
        skipped_due_to_conflict_count = 0
        conflict_details_messages = []
        for student_id_str in student_ids_selected:
            student_id = int(student_id_str)
            conflict_msg = check_leave_conflict(student_id, start_dt, end_dt, leave_type='permission', existing_leave_id=None)
            if conflict_msg:
                student_obj = db.session.get(Student, student_id)
                conflict_details_messages.append(f"Student {student_obj.nume} {student_obj.prenume}: conflict ({conflict_msg}). Permisia nu a fost adăugată.")
                skipped_due_to_conflict_count += 1
                continue
            new_permission = Permission(
                student_id=student_id,
                start_datetime=start_dt,
                end_datetime=end_dt,
                destination=destination,
                transport_mode=transport_mode,
                reason=reason,
                status='Aprobată', 
                created_by_user_id=current_user.id
            )
            db.session.add(new_permission)
            added_count += 1
        try:
            db.session.commit()
            if added_count > 0:
                flash(f'{added_count} permisii au fost adăugate cu succes.', 'success')
            if skipped_due_to_conflict_count > 0:
                flash(f'{skipped_due_to_conflict_count} permisii au fost omise din cauza conflictelor. Detalii mai jos.', 'warning')
                for detail_msg in conflict_details_messages:
                    flash(detail_msg, 'info')
            if added_count == 0 and skipped_due_to_conflict_count == 0 and len(student_ids_selected) > 0:
                 flash('Nicio permisie nu a fost adăugată. Verificați selecțiile și încercați din nou.', 'info')
            log_action("BULK_ADD_PERMISSION",
                       description=f"User {current_user.username} attempted bulk permission. Added: {added_count}, Skipped (conflict): {skipped_due_to_conflict_count}.",
                       details_after_dict={"students_selected_count": len(student_ids_selected),
                                           "start_datetime": start_datetime_str, "end_datetime": end_datetime_str,
                                           "destination": destination, "conflict_messages": conflict_details_messages[:5]})
            db.session.commit()
            return redirect(url_for('list_permissions'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la salvarea permisiilor: {str(e)}', 'danger')
            log_action("BULK_ADD_PERMISSION_FAIL", description=f"Bulk add permission failed for user {current_user.username}. Error: {str(e)}")
            db.session.commit()
    return render_template('bulk_add_permission.html', students=students_managed, form_data=None, timedelta=timedelta, get_localized_now=get_localized_now)

@app.route('/gradat/invoiri/istoric', methods=['GET'], endpoint='gradat_invoiri_istoric')
@login_required
def gradat_invoiri_istoric():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    students_managed_by_gradat = Student.query.filter_by(created_by_user_id=current_user.id).with_entities(Student.id).all()
    student_ids = [s[0] for s in students_managed_by_gradat]
    if not student_ids:
        return render_template('invoiri_istoric.html', leaves_history=[], title="Istoric Învoiri Pluton", form_data=request.args)
    perioada = request.args.get('perioada', 'ultimele_7_zile') 
    data_start_custom_str = request.args.get('data_start_custom')
    data_sfarsit_custom_str = request.args.get('data_sfarsit_custom')
    today_date = get_localized_now().date()
    end_date = today_date
    start_date = None
    if perioada == 'ieri':
        start_date = today_date - timedelta(days=1)
        end_date = start_date
    elif perioada == 'ultimele_2_zile':
        start_date = today_date - timedelta(days=1)
    elif perioada == 'ultimele_7_zile':
        start_date = today_date - timedelta(days=6)
    elif perioada == 'luna_curenta':
        start_date = today_date.replace(day=1)
    elif perioada == 'custom' and data_start_custom_str and data_sfarsit_custom_str:
        try:
            start_date = datetime.strptime(data_start_custom_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(data_sfarsit_custom_str, '%Y-%m-%d').date()
            if start_date > end_date:
                flash('Data de început custom nu poate fi după data de sfârșit.', 'warning')
                start_date = end_date
        except ValueError:
            flash('Format dată custom invalid. Se afișează ultimele 7 zile.', 'warning')
            perioada = 'ultimele_7_zile'
            start_date = today_date - timedelta(days=6)
            end_date = today_date
    elif perioada == 'toate':
        start_date = None
        end_date = None
    else: 
        perioada = 'ultimele_7_zile'
        start_date = today_date - timedelta(days=6)
        end_date = today_date
    leaves_history = []
    filter_start_dt_for_overlap = datetime.combine(start_date, time.min) if start_date else None
    filter_end_dt_for_overlap = datetime.combine(end_date, time.max) if end_date else None
    daily_leaves_query = DailyLeave.query.options(joinedload(DailyLeave.student)).filter(DailyLeave.student_id.in_(student_ids))
    if start_date and end_date :
        daily_leaves_query = daily_leaves_query.filter(DailyLeave.leave_date >= start_date, DailyLeave.leave_date <= end_date)
    for dl in daily_leaves_query.order_by(DailyLeave.leave_date.desc(), DailyLeave.start_time.desc()).all():
        leaves_history.append({
            "student_name": f"{dl.student.grad_militar} {dl.student.nume} {dl.student.prenume}",
            "tip": "Zilnică",
            "data_start_obj": dl.start_datetime, 
            "data_start": dl.leave_date,
            "ora_start": dl.start_time,
            "ora_sfarsit": dl.end_time,
            "detalii": f"{dl.leave_type_display}",
            "motiv": dl.reason or "-",
            "status": dl.status
        })
    weekend_leaves_query = WeekendLeave.query.options(joinedload(WeekendLeave.student)).filter(WeekendLeave.student_id.in_(student_ids))
    all_wl_gradat = weekend_leaves_query.order_by(WeekendLeave.weekend_start_date.desc()).all()
    for wl in all_wl_gradat:
        relevant_for_period = False
        first_interval_start_for_sort = None
        intervals_display_list = []
        for interval_idx, interval in enumerate(wl.get_intervals()):
            interval_start_naive = interval['start'].astimezone(EUROPE_BUCHAREST).replace(tzinfo=None)
            interval_end_naive = interval['end'].astimezone(EUROPE_BUCHAREST).replace(tzinfo=None)
            if interval_idx == 0: 
                first_interval_start_for_sort = interval_start_naive
            if perioada == 'toate' or (filter_start_dt_for_overlap and filter_end_dt_for_overlap and \
               interval_start_naive <= filter_end_dt_for_overlap and interval_end_naive >= filter_start_dt_for_overlap):
                relevant_for_period = True
            intervals_display_list.append(
                f"{interval['day_name']} ({interval['start'].strftime('%d.%m')}) "
                f"{interval['start'].strftime('%H:%M')}-{interval['end'].strftime('%H:%M')}"
            )
        if relevant_for_period:
            leaves_history.append({
                "student_name": f"{wl.student.grad_militar} {wl.student.nume} {wl.student.prenume}",
                "tip": "Weekend",
                "data_start_obj": first_interval_start_for_sort if first_interval_start_for_sort else datetime.combine(wl.weekend_start_date, time.min), 
                "data_start": wl.weekend_start_date,
                "ora_start": None,
                "ora_sfarsit": None,
                "detalii": "; ".join(intervals_display_list) + (f", Biserica Duminică" if wl.duminica_biserica and any(d['day_name']=='Duminica' for d in wl.get_intervals()) else ""),
                "motiv": wl.reason or "-",
                "status": wl.status
            })
    permissions_query = Permission.query.options(joinedload(Permission.student)).filter(Permission.student_id.in_(student_ids))
    if perioada != 'toate' and filter_start_dt_for_overlap and filter_end_dt_for_overlap:
        permissions_query = permissions_query.filter(
            Permission.start_datetime <= filter_end_dt_for_overlap,
            Permission.end_datetime >= filter_start_dt_for_overlap
        )
    for p in permissions_query.order_by(Permission.start_datetime.desc()).all():
        leaves_history.append({
            "student_name": f"{p.student.grad_militar} {p.student.nume} {p.student.prenume}",
            "tip": "Permisie",
            "data_start_obj": p.start_datetime, 
            "data_start": p.start_datetime.date(),
            "ora_start": p.start_datetime.time(),
            "ora_sfarsit": p.end_datetime.time(),
            "detalii": p.destination or "N/A",
            "motiv": p.reason or "-",
            "status": p.status
        })
    leaves_history.sort(key=lambda x: x['data_start_obj'], reverse=True)
    return render_template('invoiri_istoric.html',
                           leaves_history=leaves_history,
                           title="Istoric Învoiri Pluton",
                           form_data=request.args, 
                           selected_period=perioada,
                           selected_start_custom=data_start_custom_str,
                           selected_end_custom=data_sfarsit_custom_str
                           )

@app.route('/admin/export/text/studenti', endpoint='admin_export_studenti_text')
@login_required
def admin_export_studenti_text():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_dashboard_route'))
    students = Student.query.order_by(Student.grad_militar, Student.nume, Student.prenume).all()
    if not students:
        flash('Niciun student în baza de date pentru export.', 'info')
        return redirect(url_for('admin_dashboard_route'))
    output_lines = []
    for s in students:
        line = f"{s.grad_militar} {s.nume} {s.prenume} {s.gender} {s.pluton} {s.companie} {s.batalion}"
        output_lines.append(line)
    text_content = "\n".join(output_lines)
    text_file = io.BytesIO()
    text_file.write(text_content.encode('utf-8'))
    text_file.seek(0) 
    filename = f"studenti_export_{get_localized_now().strftime('%Y%m%d_%H%M%S')}.txt"
    return send_file(
        text_file,
        as_attachment=True,
        download_name=filename,
        mimetype='text/plain; charset=utf-8'
    )

@app.route('/admin/export/text/permisii', endpoint='admin_export_permisii_text')
@login_required
def admin_export_permisii_text():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_dashboard_route'))
    permissions = Permission.query.join(Student).options(joinedload(Permission.student)).order_by(Student.nume, Student.prenume, Permission.start_datetime).all()
    if not permissions:
        flash('Nicio permisie în baza de date pentru export.', 'info')
        return redirect(url_for('admin_dashboard_route'))
    output_lines = []
    for p in permissions:
        student_name_line = f"{p.student.grad_militar} {p.student.nume} {p.student.prenume}"
        start_date_str_export = p.start_datetime.strftime('%d.%m.%Y')
        start_time_str_export = p.start_datetime.strftime('%H:%M')
        end_date_str_export = p.end_datetime.strftime('%d.%m.%Y')
        end_time_str_export = p.end_datetime.strftime('%H:%M')
        if start_date_str_export == end_date_str_export:
            datetime_line = f"{start_date_str_export} {start_time_str_export} - {end_time_str_export}"
        else:
            datetime_line = f"{start_date_str_export} {start_time_str_export} - {end_date_str_export} {end_time_str_export}"
        destination_line = p.destination if p.destination else "-" 
        transport_mode_line = p.transport_mode if p.transport_mode else None
        reason_line = p.reason if p.reason else None
        output_lines.append(student_name_line)
        output_lines.append(datetime_line)
        output_lines.append(destination_line)
        if transport_mode_line is not None:
            output_lines.append(transport_mode_line)
            if reason_line is not None:
                 output_lines.append(reason_line)
        elif reason_line is not None:
            output_lines.append("")
            output_lines.append(reason_line)
        output_lines.append("") 
    text_content = "\n".join(output_lines)
    text_file = io.BytesIO(text_content.encode('utf-8'))
    text_file.seek(0)
    filename = f"permisii_export_{get_localized_now().strftime('%Y%m%d_%H%M%S')}.txt"
    return send_file(text_file, as_attachment=True, download_name=filename, mimetype='text/plain; charset=utf-8')

@app.route('/admin/export/text/invoiri', endpoint='admin_export_invoiri_text')
@login_required
def admin_export_invoiri_text():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_dashboard_route'))
    output_lines = []
    daily_leaves_by_date = {}
    all_daily_leaves = DailyLeave.query.join(Student).options(joinedload(DailyLeave.student)).order_by(DailyLeave.leave_date, Student.nume, DailyLeave.start_time).all()
    for dl in all_daily_leaves:
        date_str = dl.leave_date.strftime('%d.%m.%Y')
        if date_str not in daily_leaves_by_date:
            daily_leaves_by_date[date_str] = []
        student_name_part = f"{dl.student.grad_militar} {dl.student.nume} {dl.student.prenume}"
        time_part = f"{dl.start_time.strftime('%H:%M')}-{dl.end_time.strftime('%H:%M')}"
        daily_leaves_by_date[date_str].append(f"{student_name_part} {time_part}")
    if daily_leaves_by_date:
        output_lines.append("--- ÎNVOIRI ZILNICE (grupate pe dată) ---")
        for date_group, leaves_in_group in sorted(daily_leaves_by_date.items()):
            output_lines.append(f"\nData: {date_group}")
            for leave_entry in leaves_in_group:
                output_lines.append(leave_entry)
        output_lines.append("\n")
    all_weekend_leaves = WeekendLeave.query.join(Student).options(joinedload(WeekendLeave.student)).order_by(WeekendLeave.weekend_start_date, Student.nume).all()
    if all_weekend_leaves:
        output_lines.append("--- ÎNVOIRI WEEKEND ---")
        for wl in all_weekend_leaves:
            student_info = f"{wl.student.grad_militar} {wl.student.nume} {wl.student.prenume}"
            intervals_str_parts = []
            leave_intervals = wl.get_intervals()
            for interval in leave_intervals:
                date_str = interval['start'].astimezone(EUROPE_BUCHAREST).strftime('%d.%m.%Y')
                start_time_str = interval['start'].astimezone(EUROPE_BUCHAREST).strftime('%H:%M')
                end_time_str = interval['end'].astimezone(EUROPE_BUCHAREST).strftime('%H:%M')
                intervals_str_parts.append(f"{date_str} {start_time_str}-{end_time_str}")
            intervals_full_str = ", ".join(intervals_str_parts)
            duminica_selectata_efectiv = False
            if wl.day3_selected == "Duminica" and wl.day3_date and wl.day3_start_time and wl.day3_end_time:
                duminica_selectata_efectiv = True
            elif wl.day2_selected == "Duminica" and wl.day2_date and wl.day2_start_time and wl.day2_end_time:
                 duminica_selectata_efectiv = True
            elif wl.day1_selected == "Duminica" and wl.day1_date and wl.day1_start_time and wl.day1_end_time:
                 duminica_selectata_efectiv = True
            biserica_str = ", biserica" if wl.duminica_biserica and duminica_selectata_efectiv else ""
            output_lines.append(f"{student_info}, {intervals_full_str}{biserica_str}")
        output_lines.append("\n")
    if not output_lines:
        flash('Nicio învoire (zilnică sau weekend) în baza de date pentru export.', 'info')
        return redirect(url_for('admin_dashboard_route'))
    text_content = "\n".join(output_lines)
    text_file = io.BytesIO(text_content.encode('utf-8'))
    text_file.seek(0)
    filename = f"invoiri_export_{get_localized_now().strftime('%Y%m%d_%H%M%S')}.txt"
    return send_file(text_file, as_attachment=True, download_name=filename, mimetype='text/plain; charset=utf-8')

@app.route('/admin/permissions/export_word', endpoint='admin_export_permissions_word')
@login_required
def admin_export_permissions_word():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    now = get_localized_now()
    permissions_to_export = Permission.query.options(joinedload(Permission.student)).join(Student, Permission.student_id == Student.id).filter(
        Permission.status == 'Aprobată',
        Permission.end_datetime >= now  
    ).order_by(Student.nume, Student.prenume, Permission.start_datetime).all()
    if not permissions_to_export:
        flash('Nicio permisie activă sau viitoare de exportat în sistem.', 'info')
        return redirect(url_for('admin_dashboard_route'))
    document = Document()
    document.add_heading('Raport General Permisii (Admin)', level=1).alignment = WD_ALIGN_PARAGRAPH.CENTER
    user_info_text = f"Raport generat de: {current_user.username} (Admin)\nData generării: {datetime.now().strftime('%d-%m-%Y %H:%M')}"
    p_user = document.add_paragraph()
    p_user.add_run(user_info_text).italic = True
    p_user.alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_paragraph()
    table = document.add_table(rows=1, cols=8)
    table.style = 'Table Grid'
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = table.rows[0].cells
    column_titles = ['Nr. Crt.', 'Grad', 'Nume și Prenume', 'Data Început', 'Data Sfârșit', 'Destinația', 'Mijloc Transport', 'Observații/Nr. Auto']
    for i, title in enumerate(column_titles):
        hdr_cells[i].text = title
        hdr_cells[i].paragraphs[0].runs[0].font.bold = True
        hdr_cells[i].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    for idx, p in enumerate(permissions_to_export):
        row_cells = table.add_row().cells
        row_cells[0].text = str(idx + 1)
        row_cells[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[1].text = p.student.grad_militar
        row_cells[2].text = f"{p.student.nume} {p.student.prenume}"
        row_cells[3].text = p.start_datetime.strftime('%d.%m.%Y %H:%M')
        row_cells[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[4].text = p.end_datetime.strftime('%d.%m.%Y %H:%M')
        row_cells[4].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[5].text = p.destination if p.destination else "-"
        row_cells[6].text = p.transport_mode if p.transport_mode else "-"
        row_cells[7].text = p.reason if p.reason else "-"
        row_cells[7].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    widths = {0: Inches(0.4), 1: Inches(0.7), 2: Inches(1.8), 3: Inches(1.1), 4: Inches(1.1), 5: Inches(1.5), 6: Inches(1.2), 7: Inches(1.2)}
    for col_idx, width_val in widths.items():
        for row in table.rows:
            if col_idx < len(row.cells): row.cells[col_idx].width = width_val
    style = document.styles['Normal']; font = style.font; font.name = 'Calibri'; font.size = Pt(11)
    f = io.BytesIO(); document.save(f); f.seek(0)
    filename = f"Raport_General_Permisii_Admin_{date.today().strftime('%Y%m%d')}.docx"
    return send_file(f, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

@app.route('/admin/weekend_leaves/export_word', endpoint='admin_export_weekend_leaves_word')
@login_required
def admin_export_weekend_leaves_word():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))
    leaves_to_export = WeekendLeave.query.options(joinedload(WeekendLeave.student)).join(Student, WeekendLeave.student_id == Student.id).filter(
        WeekendLeave.status == 'Aprobată'
    ).order_by(Student.nume, Student.prenume, WeekendLeave.weekend_start_date).all()
    leaves_to_export = [leave for leave in leaves_to_export if leave.is_overall_active_or_upcoming]
    if not leaves_to_export:
        flash('Nicio învoire de weekend activă sau viitoare de exportat în sistem.', 'info')
        return redirect(url_for('admin_dashboard_route'))
    document = Document()
    document.add_heading('Raport General Învoiri Weekend (Admin)', level=1).alignment = WD_ALIGN_PARAGRAPH.CENTER
    user_info_text = f"Raport generat de: {current_user.username} (Admin)\nData generării: {datetime.now().strftime('%d-%m-%Y %H:%M')}"
    p_user = document.add_paragraph(); p_user.add_run(user_info_text).italic = True; p_user.alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_paragraph()
    table = document.add_table(rows=1, cols=6)
    table.style = 'Table Grid'; table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = table.rows[0].cells
    col_titles = ['Nr. Crt.', 'Grad', 'Nume și Prenume', 'Weekend (Vineri)', 'Intervale Selectate', 'Motiv (Biserică)']
    for i, title in enumerate(col_titles):
        hdr_cells[i].text = title; hdr_cells[i].paragraphs[0].runs[0].font.bold = True; hdr_cells[i].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    for idx, leave in enumerate(leaves_to_export):
        row_cells = table.add_row().cells
        row_cells[0].text = str(idx + 1); row_cells[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[1].text = leave.student.grad_militar
        row_cells[2].text = f"{leave.student.nume} {leave.student.prenume}"
        row_cells[3].text = leave.weekend_start_date.strftime('%d.%m.%Y'); row_cells[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        intervals_str = [f"{i['day_name']} ({i['start'].strftime('%d.%m')}) {i['start'].strftime('%H:%M')}-{i['end'].strftime('%H:%M')}" for i in leave.get_intervals()]
        row_cells[4].text = "; ".join(intervals_str) if intervals_str else "N/A"
        reason_text = leave.reason or ""
        if leave.duminica_biserica and any(d['day_name']=='Duminica' for d in leave.get_intervals()): reason_text = (reason_text + " (Biserică Duminică)").strip()
        if not reason_text: reason_text = "-"
        row_cells[5].text = reason_text
    widths = {0: Inches(0.4), 1: Inches(0.7), 2: Inches(1.8), 3: Inches(1.0), 4: Inches(2.8), 5: Inches(1.5)}
    for col_idx, width_val in widths.items():
        for row in table.rows:
            if col_idx < len(row.cells): row.cells[col_idx].width = width_val
    style = document.styles['Normal']; font = style.font; font.name = 'Calibri'; font.size = Pt(11)
    f = io.BytesIO(); document.save(f); f.seek(0)
    filename = f"Raport_General_Weekend_Admin_{date.today().strftime('%Y%m%d')}.docx"
    return send_file(f, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
