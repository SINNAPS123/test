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
        # Presupunem că datetime-urile naive sunt în ora serverului (care ar trebui să fie Europe/Bucharest)
        # sau sunt UTC și trebuie convertite. Pentru siguranță, dacă e naive, îl localizăm ca UTC apoi convertim.
        # Dar majoritatea datetime-urilor create cu datetime.now() fără tz sunt deja în ora sistemului.
        # Cel mai sigur este să verificăm dacă provin din datetime.utcnow() sau datetime.now()
        # Pentru ActionLog.timestamp care e default=datetime.utcnow, va fi conștient de fus (UTC)
        # Pentru celelalte (ex: Permission.start_datetime), sunt stocate ca naive.
        # Le vom considera ca fiind în ora serverului și le vom localiza.
        # Totuși, o practică mai bună ar fi să stocăm totul ca UTC.
        # Având în vedere structura actuală, vom considera datetime-urile naive ca fiind în ora serverului.
        localized_dt = EUROPE_BUCHAREST.localize(dt, is_dst=None) # is_dst=None pentru a gestiona tranzițiile DST
    else:
        localized_dt = dt.astimezone(EUROPE_BUCHAREST)
    return localized_dt.strftime(fmt)

@app.template_filter('localtime')
def localtime_filter(t, fmt='%H:%M'):
    if not t:
        return ""
    # Ora (time object) nu are fus orar, deci o formatăm direct.
    # Dacă ar fi nevoie de conversie bazată pe dată, ar fi mai complex.
    return t.strftime(fmt)

@app.template_filter('localdate')
def localdate_filter(d, fmt='%d-%m-%Y'):
    if not d:
        return ""
    # Data (date object) nu are fus orar.
    return d.strftime(fmt)

@app.context_processor
def inject_global_vars():
    # This context processor makes the get_localized_now function available
    # to all Jinja templates. If 'get_localized_now' is undefined in a template,
    # ensure this processor is correctly registered and the Flask app is restarted.
    return dict(get_localized_now=get_localized_now)

# IMPORTANT: Change this to a strong, unique, and static secret key in a real environment!
# Using a static key is crucial for session persistence across app restarts.
# For production, load from an environment variable.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev_fallback_super_secret_key_123!@#')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30) # Sesiune permanentă de 30 de zile

db = SQLAlchemy(app)
migrate = Migrate(app, db) # Initialize Flask-Migrate
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
# MAX_ACTIVE_COMPANY_GRADERS = 3 # Eliminat

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
        return datetime.combine(effective_end_date, self.end_time) # Returns naive datetime
    @property
    def is_active(self):
        now = get_localized_now()
        # self.start_datetime and self.end_datetime are properties returning naive datetimes
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
    duminica_biserica = db.Column(db.Boolean, default=False, nullable=False) # New field for church attendance
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
                # Create naive datetime objects first
                s_dt_naive = datetime.combine(d_date, s_time)
                e_dt_naive = datetime.combine(d_date, e_time)

                # Handle overnight case for naive end datetime
                if e_dt_naive < s_dt_naive: # e.g. start 22:00, end 02:00
                    e_dt_naive += timedelta(days=1)

                # Localize to make them aware
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
        # This code is only reached if status is 'Aprobată'
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Nullable if action can be system-initiated or by non-logged-in user
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    action_type = db.Column(db.String(50), nullable=False) # e.g., CREATE, UPDATE, DELETE, LOGIN, LOGOUT, RESET_CODE
    target_model = db.Column(db.String(100), nullable=True) # e.g., "Student", "Permission", "User"
    target_id = db.Column(db.Integer, nullable=True) # ID of the affected record
    details_before = db.Column(db.Text, nullable=True) # JSON string of relevant fields before change
    details_after = db.Column(db.Text, nullable=True)  # JSON string of relevant fields after change
    description = db.Column(db.Text, nullable=True) # General description (e.g., IP address for login, or summary)

    user = db.relationship('User', backref=db.backref('action_logs', lazy='dynamic')) # Changed to lazy='dynamic'

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
    # status_color can map to Bootstrap alert/badge classes e.g., 'primary', 'success', 'warning', 'danger', 'info', 'light', 'dark'
    status_color = db.Column(db.String(20), nullable=True)
    is_visible = db.Column(db.Boolean, default=True, nullable=False) # For soft delete or drafts

    def __repr__(self):
        return f'<UpdateTopic {self.id}: {self.title[:50]}>'

@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))

def init_db():
    with app.app_context():
        db.create_all() # This will create UpdateTopic table if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin', is_first_login=False); admin.set_password('admin123')
            db.session.add(admin); db.session.commit(); print("Admin user created.")
        else: print("Admin user already exists.")
        print("DB initialized.")

def get_next_friday(start_date=None):
    d = start_date if start_date else get_localized_now().date() # Use localized date
    while d.weekday() != 4: d += timedelta(days=1)
    return d

def get_upcoming_fridays(num_fridays=5):
    """
    Generates a list of upcoming (and potentially the current or immediate past) Fridays.
    Returns a list of dicts, each with 'value' (YYYY-MM-DD string) and 'display' (Month Day, Year string).
    """
    fridays_list = []
    today = get_localized_now().date() # Use localized date
    # Start from the Friday of the current week or previous week if today is past Friday
    current_friday_offset = today.weekday() - 4 # Friday is weekday 4
    if current_friday_offset > 0: # If today is Sat (5) or Sun (6)
        start_friday = today - timedelta(days=current_friday_offset)
    else: # If today is Mon, Tue, Wed, Thu, or Fri itself
        start_friday = today - timedelta(days=current_friday_offset) # Will be today if it's Friday, or upcoming Friday of current week

    # Ensure we don't start too far in the past if today is, e.g., Monday and last Friday was for a weekend already started
    # Let's adjust to start from the Friday of the week containing `today - 2 days`
    # This ensures if it's Sunday, we can still select the Friday of that weekend.
    # If it's Monday, we can select last Friday.
    # If it's Friday, we select today.

    # Simpler approach: find the Friday of the week of (today - 2 days)
    # This means if today is Sunday, (today-2) is Friday.
    # If today is Monday, (today-2) is Saturday of last week, so we find that Friday.
    # If today is Friday, (today-2) is Wednesday, we find this Friday.

    # Let's find the Friday of the current week. If today is past it, it's fine.
    # Or, more simply, find the *next* Friday from (today - 7 days) to ensure we always get the closest ones.
    # No, let's find the Friday of the week of `today`.
    # If today is Monday (0), Friday is today + 4 days.
    # If today is Friday (4), Friday is today + 0 days.
    # If today is Sunday (6), Friday was today - 2 days.

    # Let's find the Friday of the current calendar week (Mon-Sun)
    # If today is Sunday (weekday 6), current week's Friday was 2 days ago.
    # If today is Monday (weekday 0), current week's Friday is 4 days ahead.
    start_point = today - timedelta(days=today.weekday()) # This is Monday of the current week
    current_week_friday = start_point + timedelta(days=4)

    # We want to offer the current weekend's Friday even if it just passed.
    # So, if today is Sat/Sun, current_week_friday is the one that just passed.
    # If today is Mon-Thu, current_week_friday is upcoming.
    # If today is Fri, current_week_friday is today.

    # Let's make sure we offer at least one past Friday if it's early in the week,
    # but not too many.
    # Consider the Friday of the week prior to the current week's Monday, if today is early in the week.

    # Revised logic for start_friday:
    # Find the Friday of the week that contains 'today'.
    # If today is Sat/Sun, that Friday has passed.
    # If today is Mon-Thu, that Friday is upcoming.
    # If today is Fri, that Friday is today.

    # We want to list the closest Friday (could be past if today is Sat/Sun)
    # and then a few upcoming ones.

    # Let initial_friday be the Friday of the week containing 'today'.
    # If today is Monday (0), initial_friday is today + 4 days.
    # If today is Friday (4), initial_friday is today.
    # If today is Sunday (6), initial_friday is today - 2 days.
    days_from_friday = today.weekday() - 4 # Monday: -4, Tuesday: -3, ..., Friday: 0, Saturday: 1, Sunday: 2
    initial_friday = today - timedelta(days=days_from_friday)

    for i in range(num_fridays):
        loop_friday = initial_friday + timedelta(weeks=i)
        fridays_list.append({
            'value': loop_friday.strftime('%Y-%m-%d'),
            'display': loop_friday.strftime('%d %B %Y') + f" (Vineri)"
        })

    # If today is Monday or Tuesday, the 'initial_friday' might be too far in the future.
    # We might want to include the *previous* Friday as well.
    # Let's ensure the list starts from the previous Friday if today is Mon/Tue/Wed.
    if today.weekday() < 3: # Mon, Tue, Wed
        previous_friday = initial_friday - timedelta(weeks=1)
        # Check if it's already in the list (should not happen with current logic, but good for safety)
        if not any(f['value'] == previous_friday.strftime('%Y-%m-%d') for f in fridays_list):
            fridays_list.insert(0, {
                'value': previous_friday.strftime('%Y-%m-%d'),
                'display': previous_friday.strftime('%d %B %Y') + f" (Vineri)"
            })
            if len(fridays_list) > num_fridays: # Keep the list size consistent
                fridays_list.pop()

    return fridays_list


def validate_daily_leave_times(start_time_obj, end_time_obj, leave_date_obj):
    if leave_date_obj.weekday() > 3: return False, "Învoirile zilnice sunt permise doar de Luni până Joi."
    if start_time_obj == end_time_obj: return False, "Ora de început și de sfârșit nu pot fi identice."
    return True, "Valid"

# Funcția get_student_status a fost integrată și optimizată în _calculate_presence_data
# și nu mai este necesară separat dacă _calculate_presence_data este singurul apelant.

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

# --- Action Logging Utilities ---
def model_to_dict(instance, exclude_fields=None):
    """Converts a SQLAlchemy model instance to a dictionary, excluding specified fields."""
    if not instance:
        return {}

    default_exclude = ['_sa_instance_state', 'password_hash', 'personal_code_hash', 'unique_code'] # Standard + sensitive user fields
    fields_to_exclude = set(default_exclude)
    if exclude_fields:
        fields_to_exclude.update(exclude_fields)

    data = {}
    for c in inspect(instance).mapper.column_attrs:
        if c.key not in fields_to_exclude:
            val = getattr(instance, c.key)
            # Convert datetime/date/time objects to ISO format string
            if isinstance(val, (datetime, date, time)):
                data[c.key] = val.isoformat()
            else:
                data[c.key] = val
    return data

def log_action(action_type, target_model_name=None, target_id=None, details_before_dict=None, details_after_dict=None, description=None, user_override=None):
    """
    Logs an action to the ActionLog table.
    - action_type: Verb describing the action (e.g., "USER_LOGIN", "CREATE_STUDENT").
    - target_model_name: String name of the model class being affected (e.g., "Student").
    - target_id: Integer ID of the specific record affected.
    - details_before_dict: Dictionary representing the state of the object before changes.
    - details_after_dict: Dictionary representing the state of the object after changes.
    - description: A textual description of the event (e.g., IP address, summary of bulk operation).
    - user_override: Optionally provide a User object if current_user is not appropriate (e.g. system actions).
    """
    try:
        log = ActionLog(action_type=action_type)

        acting_user = user_override
        if not acting_user and hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            acting_user = current_user

        if acting_user:
            log.user_id = acting_user.id

        log.target_model = target_model_name
        log.target_id = int(target_id) if target_id is not None else None # Ensure int or None

        if details_before_dict:
            log.details_before = json.dumps(details_before_dict, ensure_ascii=False, default=str)
        if details_after_dict:
            log.details_after = json.dumps(details_after_dict, ensure_ascii=False, default=str)

        log.description = description

        db.session.add(log)
        # Committing is handled by the calling route after the main operation succeeds.
    except Exception as e:
        app.logger.error(f"AUDIT LOGGING FAILED for action '{action_type}': {str(e)}")
        # Avoid rollback here, as it might interfere with the main operation's transaction.
        # The main operation should handle its own rollback on failure.

# --- Rute Comune ---
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
@login_required # Sau eliminați @login_required dacă pagina este publică
def public_updates_page():
    # Aici veți adăuga logica pentru a prelua anunțurile/actualizările din baza de date
    # De exemplu: updates = UpdateTopic.query.order_by(UpdateTopic.created_at.desc()).all()
    # Momentan, vom presupune că există un template public_updates.html
    # return render_template('public_updates.html', updates=updates)
    # Pentru a evita o nouă eroare dacă template-ul nu există, redăm un text simplu
    # return "Pagina de Anunțuri Publice va fi aici."
    # Sau, dacă aveți un template generic pentru "în construcție"
    # return render_template('placeholder.html', page_title="Anunțuri")
    # Să presupunem că aveți un template 'public_updates.html' și vom trece o listă goală deocamdată
    page = request.args.get('page', 1, type=int)
    per_page = 10 # Sau orice alt număr de elemente pe pagină doriți
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
            if user_by_personal_code.is_first_login: # Should not happen if logic is correct
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

            current_user.set_personal_code(personal_code) # This also sets is_first_login = False

            details_after = model_to_dict(current_user, exclude_fields=['password_hash', 'unique_code']) # Get updated state
            details_after["personal_code_hash_exists"] = True # Explicitly state it now exists

            log_action("USER_SET_PERSONAL_CODE_SUCCESS", target_model_name="User", target_id=current_user.id,
                       details_before_dict=details_before, details_after_dict=details_after,
                       description=f"User {current_user.username} set personal code. IP: {request.remote_addr}")

            db.session.commit() # Commit user changes and log entry

            flash_message = 'Codul personal a fost setat cu succes. Te rugăm să te autentifici din nou folosind noul cod.'

            # Log automatic logout after setting personal code
            user_id_logged_out = current_user.id # Capture before logout_user() invalidates current_user
            username_logged_out = current_user.username
            logout_user()
            log_action("USER_LOGOUT_POST_SET_CODE", target_model_name="User", target_id=user_id_logged_out,
                       description=f"User {username_logged_out} automatically logged out after setting personal code. IP: {request.remote_addr}")
            db.session.commit() # Commit logout log

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

@app.route('/admin/dashboard')
@login_required
def admin_dashboard_route():
    if current_user.role != 'admin':
        flash('Acces neautorizat la panoul de administrare.', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch all users that are not admins to display in the list
    users_to_display = User.query.filter(User.role != 'admin').order_by(User.username).all()

    # Statistics (can be kept or enhanced)
    total_user_count = User.query.count() # Includes admin
    total_students_count = Student.query.count()

    return render_template('admin_dashboard.html',
                           users=users_to_display,
                           total_users=total_user_count,
                           total_students=total_students_count)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard_route'))
    elif current_user.role == 'gradat':
        student_ids_managed = [s.id for s in Student.query.filter_by(created_by_user_id=current_user.id).with_entities(Student.id).all()]
        student_count = len(student_ids_managed)

        today_localized = get_localized_now().date()
        today_start = datetime.combine(today_localized, time.min)
        today_end = datetime.combine(today_localized, time.max)

        # Permisii active AZI (se suprapun cu ziua de azi)
        permissions_today_count = Permission.query.filter(
            Permission.student_id.in_(student_ids_managed),
            Permission.status == 'Aprobată',
            Permission.start_datetime <= today_end,
            Permission.end_datetime >= today_start
        ).count()

        # Învoiri zilnice active AZI
        daily_leaves_today_count = DailyLeave.query.filter(
            DailyLeave.student_id.in_(student_ids_managed),
            DailyLeave.status == 'Aprobată',
            DailyLeave.leave_date == today_localized # Folosim data localizată
        ).count()

        # Învoiri weekend active AZI
        weekend_leaves_active_today = 0
        all_wl_gradat = WeekendLeave.query.filter(WeekendLeave.student_id.in_(student_ids_managed), WeekendLeave.status == 'Aprobată').all()
        for wl in all_wl_gradat:
            for interval in wl.get_intervals():
                if interval['start'].date() == today_localized or \
                   interval['end'].date() == today_localized or \
                   (interval['start'].date() < today_localized and interval['end'].date() > today_localized):
                    weekend_leaves_active_today += 1
                    break

        # Servicii active AZI
        services_today_count = ServiceAssignment.query.filter(
            ServiceAssignment.student_id.in_(student_ids_managed),
            ServiceAssignment.start_datetime <= today_end,
            ServiceAssignment.end_datetime >= today_start
        ).count()

        total_volunteer_activities = VolunteerActivity.query.filter_by(created_by_user_id=current_user.id).count()

        # Data for "Mini Situație Pluton (ACUM)"
        now_for_dashboard = get_localized_now()
        students_managed_by_gradat = Student.query.filter_by(created_by_user_id=current_user.id).all()

        # Use _calculate_presence_data for current situation
        # Ensure _calculate_presence_data correctly identifies "present in formation"
        # _calculate_presence_data returns:
        # "efectiv_control", "efectiv_prezent_total", "efectiv_absent_total",
        # "in_formation_count", "on_duty_count", "platoon_graded_duty_count", "absent_students_details"

        # "Prezenți" for mini-dashboard = "in_formation_count" (cei care nu sunt in permisie/serviciu/etc.)
        # "Învoiți" = "efectiv_absent_total" (cei care sunt in permisie, invoire zilnica, invoire weekend)
        # "În Serviciu" = "on_duty_count"
        # "Gradat Pluton Prezent" = "platoon_graded_duty_count" (dacă e considerat separat de "Prezenți")

        current_platoon_situation = {}
        if students_managed_by_gradat:
            current_platoon_situation = _calculate_presence_data(students_managed_by_gradat, now_for_dashboard)
            # Consolidate "absent" categories for the "Învoiți" count for simplicity on dashboard
            # _calculate_presence_data already gives 'efectiv_absent_total' which is this sum.
        else: # Default values if no students
            current_platoon_situation = {
                "efectiv_control": 0,
                "in_formation_count": 0, # Prezenți în formație
                "efectiv_absent_total": 0, # Total învoiți/absenți motivat
                "on_duty_count": 0, # În Serviciu
                "platoon_graded_duty_count": 0 # Gradat pluton (dacă e separat)
            }


        return render_template('gradat_dashboard.html',
                               student_count=student_count,
                               permissions_today_count=permissions_today_count, # Statistică veche "azi"
                               daily_leaves_today_count=daily_leaves_today_count, # Statistică veche "azi"
                               weekend_leaves_today_count=weekend_leaves_active_today, # Statistică veche "azi"
                               services_today_count=services_today_count, # Statistică veche "azi"
                               total_volunteer_activities=total_volunteer_activities,
                               # Date noi pentru "Mini Situație ACUM"
                               sit_total_studenti=current_platoon_situation.get("efectiv_control", 0),
                               sit_prezenti_formatie=current_platoon_situation.get("in_formation_count", 0),
                               sit_total_invoiti_acum=current_platoon_situation.get("efectiv_absent_total", 0),
                               sit_in_serviciu_acum=current_platoon_situation.get("on_duty_count", 0),
                               sit_gradat_pluton_prezent_acum=current_platoon_situation.get("platoon_graded_duty_count",0)
                               )
    elif current_user.role == 'comandant_companie':
        return redirect(url_for('company_commander_dashboard'))
    elif current_user.role == 'comandant_batalion':
        return redirect(url_for('battalion_commander_dashboard'))

    return render_template('dashboard.html', name=current_user.username)

# --- Admin User Management ---
@app.route('/admin/users/create', methods=['POST'], endpoint='admin_create_user') # Form is on admin_dashboard, so this handles POST
@login_required
def admin_create_user():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        role = request.form.get('role')
        valid_roles = ['gradat', 'comandant_companie', 'comandant_batalion']

        if not username:
            flash('Numele de utilizator este obligatoriu.', 'warning')
            return redirect(url_for('admin_dashboard_route'))
        if User.query.filter_by(username=username).first():
            flash(f'Numele de utilizator "{username}" există deja.', 'warning')
            return redirect(url_for('admin_dashboard_route'))
        if not role or role not in valid_roles:
            flash('Rolul selectat este invalid.', 'warning')
            return redirect(url_for('admin_dashboard_route'))

        unique_code = secrets.token_hex(8)
        while User.query.filter_by(unique_code=unique_code).first(): # Ensure unique_code is truly unique
            unique_code = secrets.token_hex(8)

        new_user = User(
            username=username,
            role=role,
            unique_code=unique_code,
            is_first_login=True
            # password_hash is not set, user will set personal_code
        )
        db.session.add(new_user)
        try:
            db.session.add(new_user) # Add to session first
            db.session.flush() # Assign an ID to new_user so we can log it

            log_action("ADMIN_CREATE_USER_SUCCESS", target_model_name="User", target_id=new_user.id,
                       details_after_dict=model_to_dict(new_user),
                       description=f"Admin {current_user.username} created user {new_user.username} ({new_user.role}). Unique code: {unique_code}. IP: {request.remote_addr}")
            db.session.commit()
            flash(f'Utilizatorul "{username}" ({role}) a fost creat cu succes! Cod unic de autentificare: {unique_code}', 'success')
        except Exception as e:
            db.session.rollback()
            flash_msg = f'Eroare la crearea utilizatorului: {str(e)}'
            flash(flash_msg, 'danger')
            try:
                log_action("ADMIN_CREATE_USER_FAIL",
                           description=f"Admin {current_user.username} failed to create user {username} ({role}). Error: {str(e)}. IP: {request.remote_addr}")
                db.session.commit()
            except Exception as log_e:
                app.logger.error(f"CRITICAL: Failed to commit failure log for ADMIN_CREATE_USER_FAIL: {str(log_e)}")
        return redirect(url_for('admin_dashboard_route'))

    return redirect(url_for('admin_dashboard_route'))

@app.route('/admin/users/reset_code/<int:user_id>', methods=['POST'], endpoint='admin_reset_user_code')
@login_required
def admin_reset_user_code(user_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    user_to_reset = db.session.get(User, user_id)
    if not user_to_reset:
        flash('Utilizatorul nu a fost găsit.', 'danger')
        return redirect(url_for('admin_dashboard_route'))

    if user_to_reset.role == 'admin':
        flash('Codul utilizatorului admin nu poate fi resetat prin această metodă.', 'warning')
        return redirect(url_for('admin_dashboard_route'))

    details_before = model_to_dict(user_to_reset)
    old_unique_code = user_to_reset.unique_code # For logging

    new_unique_code = secrets.token_hex(8)
    while User.query.filter_by(unique_code=new_unique_code).first():
        new_unique_code = secrets.token_hex(8)

    user_to_reset.unique_code = new_unique_code
    user_to_reset.is_first_login = True
    user_to_reset.password_hash = None
    user_to_reset.personal_code_hash = None

    try:
        details_after = model_to_dict(user_to_reset)
        log_action("ADMIN_RESET_USER_CODE_SUCCESS", target_model_name="User", target_id=user_to_reset.id,
                   details_before_dict=details_before, details_after_dict=details_after,
                   description=f"Admin {current_user.username} reset code for user {user_to_reset.username}. Old unique code: {old_unique_code}, New unique code: {new_unique_code}. IP: {request.remote_addr}")
        db.session.commit()
        flash(f'Codul pentru utilizatorul "{user_to_reset.username}" a fost resetat. Noul cod unic de autentificare: {new_unique_code}', 'success')
    except Exception as e:
        db.session.rollback()
        flash_msg = f'Eroare la resetarea codului: {str(e)}'
        flash(flash_msg, 'danger')
        try:
            log_action("ADMIN_RESET_USER_CODE_FAIL", target_model_name="User", target_id=user_to_reset.id,
                       details_before_dict=details_before, # Log what it was before the attempt
                       description=f"Admin {current_user.username} failed to reset code for user {user_to_reset.username}. Error: {str(e)}. IP: {request.remote_addr}")
            db.session.commit()
        except Exception as log_e:
            app.logger.error(f"CRITICAL: Failed to commit failure log for ADMIN_RESET_USER_CODE_FAIL: {str(log_e)}")
    return redirect(url_for('admin_dashboard_route'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'], endpoint='admin_delete_user')
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('Utilizatorul nu a fost găsit.', 'danger')
        # Log attempt to delete non-existent user?
        log_action("ADMIN_DELETE_USER_FAIL_NOT_FOUND", target_id=user_id, description=f"Admin {current_user.username} attempt to delete non-existent user ID {user_id}. IP: {request.remote_addr}")
        db.session.commit()
        return redirect(url_for('admin_dashboard_route'))

    if user_to_delete.role == 'admin':
        flash('Conturile de administrator nu pot fi șterse prin această interfață.', 'warning')
        log_action("ADMIN_DELETE_USER_FAIL_IS_ADMIN", target_model_name="User", target_id=user_to_delete.id,
                   description=f"Admin {current_user.username} attempt to delete admin user {user_to_delete.username}. IP: {request.remote_addr}")
        db.session.commit()
        return redirect(url_for('admin_dashboard_route'))

    username_deleted_log = user_to_delete.username
    role_deleted_log = user_to_delete.role
    details_before = model_to_dict(user_to_delete)
    num_students_deleted = 0

    try:
        if user_to_delete.role == 'gradat':
            students_to_delete = Student.query.filter_by(created_by_user_id=user_to_delete.id).all()
            num_students_deleted = len(students_to_delete)
            for student in students_to_delete:
                # Log student deletion implicitly by user deletion or explicitly if needed
                # For now, covered by the user deletion log's description.
                db.session.delete(student)
            if num_students_deleted > 0:
                flash(f'Toți studenții ({num_students_deleted}) și datele asociate pentru gradatul {username_deleted_log} au fost șterse.', 'info')

        db.session.delete(user_to_delete)

        log_action("ADMIN_DELETE_USER_SUCCESS", target_model_name="User", target_id=user_id, # user_id from param, as user_to_delete.id will be gone
                   details_before_dict=details_before,
                   description=f"Admin {current_user.username} deleted user {username_deleted_log} ({role_deleted_log}). {num_students_deleted} students also deleted if user was gradat. IP: {request.remote_addr}")
        db.session.commit()
        flash(f'Utilizatorul "{username_deleted_log}" și toate datele asociate (dacă este cazul) au fost șterse cu succes.', 'success')

    except Exception as e:
        db.session.rollback()
        flash_msg = f'Eroare la ștergerea utilizatorului {username_deleted_log}: {str(e)}'
        flash(flash_msg, 'danger')
        try:
            log_action("ADMIN_DELETE_USER_FAIL", target_model_name="User", target_id=user_id,
                       details_before_dict=details_before, # Log what it was before the attempt
                       description=f"Admin {current_user.username} failed to delete user {username_deleted_log}. Error: {str(e)}. IP: {request.remote_addr}")
            db.session.commit()
        except Exception as log_e:
            app.logger.error(f"CRITICAL: Failed to commit failure log for ADMIN_DELETE_USER_FAIL: {str(log_e)}")

    return redirect(url_for('admin_dashboard_route'))

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'], endpoint='admin_edit_user')
@login_required
def admin_edit_user(user_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    user_to_edit = db.session.get(User, user_id)
    if not user_to_edit:
        flash('Utilizatorul nu a fost găsit.', 'danger')
        return redirect(url_for('admin_dashboard_route'))

    if user_to_edit.role == 'admin': # Prevent admin from editing their own or other admin usernames via this form
        flash('Numele de utilizator pentru conturile de admin nu poate fi modificat prin această interfață.', 'warning')
        return redirect(url_for('admin_dashboard_route'))

    original_username = user_to_edit.username # For logging and comparison
    details_before_edit = model_to_dict(user_to_edit)

    if request.method == 'POST':
        new_username = request.form.get('new_username', '').strip()

        if not new_username:
            flash('Noul nume de utilizator nu poate fi gol.', 'warning')
            return render_template('admin_edit_user.html', user_to_edit=user_to_edit) # Re-render with error

        if new_username != original_username:
            existing_user = User.query.filter(User.username == new_username).first()
            if existing_user:
                flash(f"Numele de utilizator '{new_username}' există deja. Te rugăm alege altul.", 'warning')
                return render_template('admin_edit_user.html', user_to_edit=user_to_edit)

            user_to_edit.username = new_username

            try:
                details_after_edit = model_to_dict(user_to_edit)
                log_action("ADMIN_UPDATE_USERNAME_SUCCESS", target_model_name="User", target_id=user_to_edit.id,
                           details_before_dict=details_before_edit, details_after_dict=details_after_edit,
                           description=f"Admin {current_user.username} changed username for user ID {user_to_edit.id} from '{original_username}' to '{new_username}'.")
                db.session.commit()
                flash(f"Numele de utilizator pentru '{original_username}' a fost schimbat în '{new_username}'.", 'success')

                if user_to_edit.role in ['comandant_companie', 'comandant_batalion']:
                    # Check if new username still allows unit ID derivation
                    derived_id_after_change = _get_commander_unit_id(new_username, "CmdC" if user_to_edit.role == 'comandant_companie' else "CmdB")
                    if not derived_id_after_change:
                         flash(f"Atenție: Noul nume de utilizator '{new_username}' pentru comandantul {new_username} nu mai corespunde modelului pentru extragerea automată a ID-ului unității. Funcționalitatea specifică rolului său ar putea fi afectată.", 'warning')
                    else:
                         # Optionally, confirm the new derived ID if it's part of the username structure
                         flash(f"Verificare ID unitate pentru '{new_username}': ID derivat este '{derived_id_after_change}'. Asigurați-vă că este corect.", "info")


                return redirect(url_for('admin_dashboard_route'))
            except Exception as e:
                db.session.rollback()
                user_to_edit.username = original_username # Revert optimistic change
                flash(f"Eroare la salvarea noului nume de utilizator: {str(e)}", 'danger')
                try:
                    log_action("ADMIN_UPDATE_USERNAME_FAIL", target_model_name="User", target_id=user_to_edit.id,
                               details_before_dict=details_before_edit,
                               description=f"Admin {current_user.username} failed to change username for user ID {user_to_edit.id} from '{original_username}' to '{new_username}'. Error: {str(e)}")
                    db.session.commit()
                except Exception as log_e:
                    app.logger.error(f"CRITICAL: Failed to commit failure log for ADMIN_UPDATE_USERNAME_FAIL: {str(log_e)}")
        else:
            flash('Numele de utilizator nu a fost schimbat.', 'info') # No change made
            return redirect(url_for('admin_dashboard_route'))

    # For GET request
    return render_template('admin_edit_user.html', user_to_edit=user_to_edit)


@app.route('/admin/student/edit/<int:student_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_student(student_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard')) # Or home

    student_to_edit = db.session.get(Student, student_id)
    if not student_to_edit:
        flash('Studentul nu a fost găsit.', 'danger')
        return redirect(url_for('list_students', _anchor='admin_view_params_if_any')) # Assuming admin view of list_students

    details_before_edit = model_to_dict(student_to_edit)
    original_creator_username = student_to_edit.creator.username if student_to_edit.creator else "N/A"


    if request.method == 'POST':
        form = request.form
        # Capture values from form
        student_to_edit.nume = form.get('nume','').strip()
        student_to_edit.prenume = form.get('prenume','').strip()
        student_to_edit.grad_militar = form.get('grad_militar','').strip()
        student_to_edit.pluton = form.get('pluton','').strip()
        student_to_edit.companie = form.get('companie','').strip()
        student_to_edit.batalion = form.get('batalion','').strip()
        student_to_edit.gender = form.get('gender')
        student_to_edit.is_platoon_graded_duty = 'is_platoon_graded_duty' in request.form
        new_id_unic = form.get('id_unic_student','').strip() or None

        # Potentially allow changing created_by_user_id by admin? For now, no.
        # student_to_edit.created_by_user_id = form.get('created_by_user_id', student_to_edit.created_by_user_id)


        if not all([student_to_edit.nume, student_to_edit.prenume, student_to_edit.grad_militar, student_to_edit.pluton, student_to_edit.companie, student_to_edit.batalion, student_to_edit.gender]):
            flash('Toate câmpurile marcate cu * (nume, prenume, grad, unități, gen) sunt obligatorii.', 'warning')
            # Pass original creator info for display even on error
            return render_template('admin_edit_student.html', form_title=f"Editare Student (Admin): {details_before_edit.get('grad_militar','')} {details_before_edit.get('nume','')}", student=student_to_edit, genders=GENDERS, original_creator_username=original_creator_username, form_data=request.form)

        if student_to_edit.gender not in GENDERS:
            flash('Valoare invalidă pentru gen.', 'warning')
            return render_template('admin_edit_student.html', form_title=f"Editare Student (Admin): {details_before_edit.get('grad_militar','')} {details_before_edit.get('nume','')}", student=student_to_edit, genders=GENDERS, original_creator_username=original_creator_username, form_data=request.form)

        # Check for ID Unic conflict if changed
        if new_id_unic and new_id_unic != details_before_edit.get('id_unic_student') : # Check against original value from details_before
            existing_student_with_id = Student.query.filter(Student.id_unic_student == new_id_unic, Student.id != student_to_edit.id).first()
            if existing_student_with_id:
                flash(f"Alt student (ID: {existing_student_with_id.id}) cu ID unic '{new_id_unic}' există deja.", 'warning')
                return render_template('admin_edit_student.html', form_title=f"Editare Student (Admin): {details_before_edit.get('grad_militar','')} {details_before_edit.get('nume','')}", student=student_to_edit, genders=GENDERS, original_creator_username=original_creator_username, form_data=request.form)
        student_to_edit.id_unic_student = new_id_unic

        try:
            details_after_edit = model_to_dict(student_to_edit)
            log_action("ADMIN_UPDATE_STUDENT_SUCCESS", target_model_name="Student", target_id=student_to_edit.id,
                       details_before_dict=details_before_edit, details_after_dict=details_after_edit,
                       description=f"Admin {current_user.username} updated student {student_to_edit.grad_militar} {student_to_edit.nume} (ID: {student_to_edit.id}).")
            db.session.commit()
            flash(f'Studentul {student_to_edit.grad_militar} {student_to_edit.nume} {student_to_edit.prenume} a fost actualizat de admin!', 'success')
            return redirect(url_for('list_students')) # Redirects to admin view due to session/role context
        except Exception as e:
            db.session.rollback()
            flash_msg = f'Eroare la actualizarea studentului de către admin: {str(e)}'
            flash(flash_msg, 'danger')
            try:
                log_action("ADMIN_UPDATE_STUDENT_FAIL", target_model_name="Student", target_id=student_to_edit.id,
                           details_before_dict=details_before_edit,
                           description=f"Admin {current_user.username} failed to update student ID {student_to_edit.id}. Error: {str(e)}")
                db.session.commit()
            except Exception as log_e:
                app.logger.error(f"CRITICAL: Failed to commit failure log for ADMIN_UPDATE_STUDENT_FAIL: {str(log_e)}")
            return render_template('admin_edit_student.html', form_title=f"Editare Student (Admin): {details_before_edit.get('grad_militar','')} {details_before_edit.get('nume','')}", student=student_to_edit, genders=GENDERS, original_creator_username=original_creator_username, form_data=request.form)

    # For GET request, populate form with student's current data
    form_data_for_get = model_to_dict(student_to_edit)
    # Ensure boolean is_platoon_graded_duty is correctly passed for checkbox
    form_data_for_get['is_platoon_graded_duty'] = student_to_edit.is_platoon_graded_duty

    return render_template('admin_edit_student.html',
                           form_title=f"Editare Student (Admin): {student_to_edit.grad_militar} {student_to_edit.nume} {student_to_edit.prenume}",
                           student=student_to_edit,
                           genders=GENDERS,
                           original_creator_username=original_creator_username,
                           form_data=form_data_for_get)

# --- Admin List View for Permissions ---
@app.route('/admin/permissions', endpoint='admin_list_permissions')
@login_required
def admin_list_permissions():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    page = request.args.get('page', 1, type=int)
    per_page = 20

    query = Permission.query.options(
        joinedload(Permission.student).joinedload(Student.creator), # Creator of student
        joinedload(Permission.creator) # Creator of permission
    ).order_by(Permission.start_datetime.desc())

    # Basic Filtering (can be expanded)
    search_student_name = request.args.get('search_student_name', '').strip()
    filter_status = request.args.get('filter_status', '').strip()
    # TODO: Add date range filters if needed

    if search_student_name:
        # Search in student's nume or prenume
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

    # For status filter dropdown
    statuses = sorted(list(set(item[0] for item in db.session.query(Permission.status).distinct().all() if item[0])))


    return render_template('admin_list_permissions.html',
                           permissions_pagination=permissions_pagination,
                           search_student_name=search_student_name,
                           filter_status=filter_status,
                           statuses=statuses,
                           title="Listă Generală Permisii (Admin)")

# --- Admin List View for Daily Leaves ---
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

    # Filtering
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

# --- Admin List View for Weekend Leaves ---
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

    # Filtering
    search_student_name = request.args.get('search_student_name', '').strip()
    filter_status = request.args.get('filter_status', '').strip()
    filter_weekend_start_date = request.args.get('filter_weekend_start_date', '').strip() # This is the Friday

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

# --- Admin List View for Service Assignments ---
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

    # Filtering
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
            # ServiceAssignment has start_datetime and end_datetime, and service_date
            # Filter by service_date for simplicity, or choose start/end date part.
            query = query.filter(ServiceAssignment.service_date == date_obj)
        except ValueError:
            flash('Format dată invalid pentru filtrare (Data serviciu). Folosiți YYYY-MM-DD.', 'warning')

    services_pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    # For service type filter dropdown
    service_types_for_filter = sorted(list(set(item[0] for item in db.session.query(ServiceAssignment.service_type).distinct().all() if item[0])))


    return render_template('admin_list_services.html',
                           services_pagination=services_pagination,
                           search_student_name=search_student_name,
                           filter_service_type=filter_service_type,
                           filter_service_date=filter_service_date,
                           service_types_for_filter=service_types_for_filter, # Pass this to template
                           title="Listă Generală Servicii (Admin)")


# --- Helper function to parse commander's unit ID ---
def _get_commander_unit_id(username, role_prefix):
    # role_prefix could be "CmdC" or "CmdB"
    # We are looking for patterns like "CmdC1", "Vasile_CmdC1", "CmdB12", "Popescu_CmdB123"
    # The ID is the numeric part immediately following the role_prefix in the username string.

    # Escape role_prefix in case it contains special regex characters (though "CmdC" and "CmdB" don't)
    # Then look for one or more digits (\d+) captured in a group.
    match = re.search(f"{re.escape(role_prefix)}(\\d+)", username)
    if match:
        unit_id_part = match.group(1) # Get the captured digits (e.g., "1", "123")
        # The \d+ ensures unit_id_part is not empty and contains only digits.
        return unit_id_part
    return None # Return None if prefix followed by digits is not found

# --- Helper function to determine standard roll call time ---
def get_standard_roll_call_datetime(for_date=None):
    target_date = for_date if for_date else get_localized_now().date() # Folosim data localizată
    weekday = target_date.weekday() # Monday is 0 and Sunday is 6

    if 0 <= weekday <= 3: # Monday to Thursday
        roll_call_time = time(20, 0)
    else: # Friday to Sunday
        roll_call_time = time(22, 0)

    return datetime.combine(target_date, roll_call_time)

# --- Helper function to calculate presence data for a list of students (Optimized) ---
def _calculate_presence_data(student_list, check_datetime):
    if not student_list:
        return {
            "efectiv_control": 0, "efectiv_prezent_total": 0, "efectiv_absent_total": 0,
            "in_formation_count": 0, "in_formation_students_details": [],
            "on_duty_count": 0, "on_duty_students_details": [],
            "platoon_graded_duty_count": 0, "platoon_graded_duty_students_details": [],
            "absent_students_details": []
        }

    student_ids = [s.id for s in student_list]
    now = check_datetime # Folosim check_datetime consistent

    # Preîncărcare date
    # Folosim dictionare pentru a mapa student_id la obiectul relevant, pentru acces rapid
    # Presupunem ca un student are cel mult un item activ din fiecare categorie (serviciu, permisie etc.)
    # Daca pot fi multiple, logica de mai jos ia primul gasit dupa sortare (daca e cazul)

    active_services_map = {sa.student_id: sa for sa in ServiceAssignment.query.filter(
        ServiceAssignment.student_id.in_(student_ids),
        ServiceAssignment.start_datetime <= now,
        ServiceAssignment.end_datetime >= now
    ).order_by(ServiceAssignment.start_datetime).all()}

    active_permissions_map = {p.student_id: p for p in Permission.query.filter(
        Permission.student_id.in_(student_ids),
        Permission.status == 'Aprobată',
        Permission.start_datetime <= now,
        Permission.end_datetime >= now
    ).order_by(Permission.start_datetime).all()}

    all_daily_leaves = DailyLeave.query.filter(
        DailyLeave.student_id.in_(student_ids),
        DailyLeave.status == 'Aprobată'
    ).all()
    active_daily_leaves_map = {}
    for dl in all_daily_leaves:
        # Make dl.start_datetime and dl.end_datetime (which are naive properties) timezone-aware
        # Assuming they represent time in EUROPE_BUCHAREST timezone
        dl_start_aware = EUROPE_BUCHAREST.localize(dl.start_datetime)
        dl_end_aware = EUROPE_BUCHAREST.localize(dl.end_datetime)
        if dl_start_aware <= now <= dl_end_aware:
            if dl.student_id not in active_daily_leaves_map: # Ia prima învoire activă
                 active_daily_leaves_map[dl.student_id] = dl

    all_weekend_leaves = WeekendLeave.query.filter(
        WeekendLeave.student_id.in_(student_ids),
        WeekendLeave.status == 'Aprobată'
    ).all()
    active_weekend_leaves_map = {}
    for wl in all_weekend_leaves:
        for interval in wl.get_intervals(): # get_intervals() ar trebui să fie eficient
            if interval['start'] <= now <= interval['end']:
                if wl.student_id not in active_weekend_leaves_map:
                    active_weekend_leaves_map[wl.student_id] = {"leave": wl, "interval": interval}
                break

    efectiv_control = len(student_list)
    in_formation_list = []
    on_duty_list = []
    platoon_graded_duty_list = []
    absent_list = []

    for s in student_list:
        student_display_name = f"{s.grad_militar} {s.nume} {s.prenume}"
        status_found = False # Flag pentru a ne asigura că un student nu e numărat de mai multe ori

        # Ordinea verificării contează dacă un student ar putea fi în mai multe stări simultan
        # (de ex. serviciu și permisie - deși conflictele ar trebui prevenite la creare)
        # Serviciile 'critice' au prioritate.
        if s.id in active_services_map:
            active_service = active_services_map[s.id]
            # Considerăm 'participates_in_roll_call' aici dacă e relevant pentru 'on_duty_list' vs 'in_formation_list'
            # Pentru moment, toți cei cu serviciu activ sunt 'on_duty'
            on_duty_list.append(f"{student_display_name} - Serviciu ({active_service.service_type})")
            status_found = True
        elif s.id in active_permissions_map:
            # active_permission = active_permissions_map[s.id] # Nu e nevoie de obiectul în sine pentru mesaj
            absent_list.append(f"{student_display_name} - Permisie")
            status_found = True
        elif s.id in active_weekend_leaves_map:
            wl_data = active_weekend_leaves_map[s.id]
            absent_list.append(f"{student_display_name} - Învoire Weekend ({wl_data['interval']['day_name']})")
            status_found = True
        elif s.id in active_daily_leaves_map:
            dl = active_daily_leaves_map[s.id]
            absent_list.append(f"{student_display_name} - Învoire Zilnică ({dl.leave_type_display})")
            status_found = True

        if not status_found: # Dacă nu e în niciun serviciu sau învoire/permisie
            if s.is_platoon_graded_duty:
                platoon_graded_duty_list.append(f"{student_display_name} - Gradat Pluton")
            else:
                in_formation_list.append(student_display_name)
        # else: studentul a fost deja clasificat (serviciu, permisie, etc.)

    in_formation_count = len(in_formation_list)
    on_duty_count = len(on_duty_list)
    platoon_graded_duty_count = len(platoon_graded_duty_list)
    efectiv_absent_total = len(absent_list)

    # Ep = (în formație) + (la datorie, dar nu la apel dacă e cazul) + (gradat pluton prezent)
    # Simplificat: toți cei care nu sunt absenți sunt prezenți într-o formă sau alta.
    # on_duty_list și platoon_graded_duty_list sunt considerați prezenți.
    efectiv_prezent_total = in_formation_count + on_duty_count + platoon_graded_duty_count

    # Verificare consistență (opțional, pentru debug)
    # if efectiv_control != efectiv_prezent_total + efectiv_absent_total:
    #     app.logger.warning(f"Discrepancy in presence data: EC({efectiv_control}) != EP({efectiv_prezent_total}) + EA({efectiv_absent_total})")

    return {
        "efectiv_control": efectiv_control,
        "efectiv_prezent_total": efectiv_prezent_total,
        "efectiv_absent_total": efectiv_absent_total,
        "in_formation_count": in_formation_count,
        "in_formation_students_details": sorted(in_formation_list),
        "on_duty_count": on_duty_count,
        "on_duty_students_details": sorted(on_duty_list),
        "platoon_graded_duty_count": platoon_graded_duty_count,
        "platoon_graded_duty_students_details": sorted(platoon_graded_duty_list),
        "absent_students_details": sorted(absent_list)
    }

# --- Commander Dashboards ---
@app.route('/dashboard/company')
@login_required
def company_commander_dashboard():
    if current_user.role != 'comandant_companie':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    company_id_str = _get_commander_unit_id(current_user.username, "CmdC")
    if not company_id_str:
        flash('ID-ul companiei nu a putut fi determinat din numele de utilizator.', 'warning')
        return redirect(url_for('dashboard'))

    roll_call_datetime = get_standard_roll_call_datetime()
    roll_call_time_str = roll_call_datetime.strftime('%d %B %Y, %H:%M')

    # Fetch all students in this specific company
    students_in_company_all = Student.query.filter_by(companie=company_id_str).all()
    student_ids_in_company = [s.id for s in students_in_company_all]

    total_company_presence_roll_call = _calculate_presence_data(students_in_company_all, roll_call_datetime) # For existing roll call report

    # New stats for "today"
    today_localized_company = get_localized_now().date()
    today_start = datetime.combine(today_localized_company, time.min)
    today_end = datetime.combine(today_localized_company, time.max)

    permissions_today_company_count = Permission.query.filter(
        Permission.student_id.in_(student_ids_in_company),
        Permission.status == 'Aprobată',
        Permission.start_datetime <= today_end,
        Permission.end_datetime >= today_start
    ).count()

    daily_leaves_today_company_count = DailyLeave.query.filter(
        DailyLeave.student_id.in_(student_ids_in_company),
        DailyLeave.status == 'Aprobată',
        DailyLeave.leave_date == today_localized_company
    ).count()

    weekend_leaves_today_company_count = 0
    all_wl_company_for_today_stats = WeekendLeave.query.filter(WeekendLeave.student_id.in_(student_ids_in_company), WeekendLeave.status == 'Aprobată').all()
    for wl_today in all_wl_company_for_today_stats:
        for interval_today in wl_today.get_intervals():
            if interval_today['start'].date() == today_localized_company or \
               interval_today['end'].date() == today_localized_company or \
               (interval_today['start'].date() < today_localized_company and interval_today['end'].date() > today_localized_company):
                weekend_leaves_today_company_count += 1
                break

    total_leaves_today_company_count = daily_leaves_today_company_count + weekend_leaves_today_company_count

    services_today_company_count = ServiceAssignment.query.filter(
        ServiceAssignment.student_id.in_(student_ids_in_company),
        ServiceAssignment.start_datetime <= today_end,
        ServiceAssignment.end_datetime >= today_start
    ).count()

    # Stats for "NOW"
    now_localized = get_localized_now()
    permissions_active_now_company = Permission.query.filter(
        Permission.student_id.in_(student_ids_in_company),
        Permission.status == 'Aprobată',
        Permission.start_datetime <= now_localized,
        Permission.end_datetime >= now_localized
    ).count()

    daily_leaves_active_now_company = 0
    all_dl_company = DailyLeave.query.filter(DailyLeave.student_id.in_(student_ids_in_company), DailyLeave.status == 'Aprobată').all()
    for dl_now in all_dl_company:
        if dl_now.is_active: # is_active already uses get_localized_now()
            daily_leaves_active_now_company +=1

    weekend_leaves_active_now_company = 0
    all_wl_company_for_now_stats = WeekendLeave.query.filter(WeekendLeave.student_id.in_(student_ids_in_company), WeekendLeave.status == 'Aprobată').all()
    for wl_now in all_wl_company_for_now_stats:
        if wl_now.is_any_interval_active_now: # is_any_interval_active_now uses get_localized_now()
            weekend_leaves_active_now_company += 1

    total_on_leave_now_company = permissions_active_now_company + daily_leaves_active_now_company + weekend_leaves_active_now_company

    services_active_now_company = ServiceAssignment.query.filter(
        ServiceAssignment.student_id.in_(student_ids_in_company),
        ServiceAssignment.start_datetime <= now_localized,
        ServiceAssignment.end_datetime >= now_localized
    ).count()


    platoons_data_roll_call = {}
    platoons_in_company = sorted(list(set(s.pluton for s in students_in_company_all if s.pluton)))
    for pluton_id_str in platoons_in_company:
        students_in_pluton = [s for s in students_in_company_all if s.pluton == pluton_id_str]
        platoon_name = f"Plutonul {pluton_id_str}"
        platoons_data_roll_call[platoon_name] = _calculate_presence_data(students_in_pluton, roll_call_datetime)

    return render_template('company_commander_dashboard.html',
                           company_id=company_id_str,
                           roll_call_time_str=roll_call_time_str,
                            total_company_presence=total_company_presence_roll_call,
                            platoons_data=platoons_data_roll_call,
                            # Statistici "Astăzi"
                            permissions_today_count=permissions_today_company_count,
                            daily_leaves_today_company=daily_leaves_today_company_count, # Nume nou pentru claritate
                            weekend_leaves_today_company=weekend_leaves_today_company_count, # Nume nou
                            total_leaves_today_count=total_leaves_today_company_count,
                            services_today_count=services_today_company_count,
                            total_students_company=len(student_ids_in_company),
                            # Statistici "ACUM"
                            permissions_active_now_company=permissions_active_now_company,
                            daily_leaves_active_now_company=daily_leaves_active_now_company,
                            weekend_leaves_active_now_company=weekend_leaves_active_now_company,
                            total_on_leave_now_company=total_on_leave_now_company,
                            services_active_now_company=services_active_now_company,
                            current_time_for_display=now_localized
                           )

@app.route('/company_commander/logs', endpoint='company_commander_logs')
@login_required
def company_commander_logs():
    if current_user.role != 'comandant_companie':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    company_id_str = _get_commander_unit_id(current_user.username, "CmdC")
    if not company_id_str:
        flash('ID-ul companiei nu a putut fi determinat.', 'warning')
        return redirect(url_for('company_commander_dashboard'))

    page = request.args.get('page', 1, type=int)
    per_page = 25

    # Subquery pentru a găsi ID-urile studenților din compania comandantului
    student_ids_in_company = db.session.query(Student.id).filter(Student.companie == company_id_str).scalar_subquery()

    # Interogare principală pentru ActionLog
    # Filtrăm logurile unde target_id (dacă modelul este Student, Permission, etc.) corespunde unui student din companie.
    # Acest query este complex și ar putea necesita optimizări sau o abordare diferită pentru performanță pe volume mari.

    # Interogare principală pentru ActionLog, optimizată
    base_query = ActionLog.query.join(User, ActionLog.user_id == User.id, isouter=True).options(joinedload(ActionLog.user))

    conditions = []

    # Condiție pentru Studenți
    student_subquery = db.session.query(Student.id).filter(Student.companie == company_id_str).scalar_subquery()
    conditions.append(and_(ActionLog.target_model == 'Student', ActionLog.target_id.in_(student_subquery)))

    # Condiție pentru Permisii
    permission_subquery = db.session.query(Permission.id).join(Student, Permission.student_id == Student.id).filter(Student.companie == company_id_str).scalar_subquery()
    conditions.append(and_(ActionLog.target_model == 'Permission', ActionLog.target_id.in_(permission_subquery)))

    # Condiție pentru DailyLeave
    daily_leave_subquery = db.session.query(DailyLeave.id).join(Student, DailyLeave.student_id == Student.id).filter(Student.companie == company_id_str).scalar_subquery()
    conditions.append(and_(ActionLog.target_model == 'DailyLeave', ActionLog.target_id.in_(daily_leave_subquery)))

    # Condiție pentru WeekendLeave
    weekend_leave_subquery = db.session.query(WeekendLeave.id).join(Student, WeekendLeave.student_id == Student.id).filter(Student.companie == company_id_str).scalar_subquery()
    conditions.append(and_(ActionLog.target_model == 'WeekendLeave', ActionLog.target_id.in_(weekend_leave_subquery)))

    # Condiție pentru ServiceAssignment
    service_subquery = db.session.query(ServiceAssignment.id).join(Student, ServiceAssignment.student_id == Student.id).filter(Student.companie == company_id_str).scalar_subquery()
    conditions.append(and_(ActionLog.target_model == 'ServiceAssignment', ActionLog.target_id.in_(service_subquery)))

    # TODO: Adaugă condiții pentru alte modele relevante dacă este necesar (ex. VolunteerActivity, ActivityParticipant)
    # Exemplu pentru ActivityParticipant (dacă s-ar loga target_id-ul participantului)
    # participant_subquery = db.session.query(ActivityParticipant.id).join(Student, ActivityParticipant.student_id == Student.id).filter(Student.companie == company_id_str).scalar_subquery()
    # conditions.append(and_(ActionLog.target_model == 'ActivityParticipant', ActionLog.target_id.in_(participant_subquery)))

    # Aplică condițiile cu OR
    if conditions:
        final_query = base_query.filter(or_(*conditions)).order_by(ActionLog.timestamp.desc())
    else: # În caz că nu există condiții (deși e improbabil aici)
        final_query = base_query.order_by(ActionLog.timestamp.desc()) # Sau returnează o listă goală direct

    logs_pagination = final_query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template('commander_action_logs.html',
                           logs_pagination=logs_pagination,
                           title=f"Jurnal Acțiuni Compania {company_id_str}",
                           unit_id=company_id_str,
                           unit_type="Compania")

@app.route('/battalion_commander/logs', endpoint='battalion_commander_logs')
@login_required
def battalion_commander_logs():
    if current_user.role != 'comandant_batalion':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    battalion_id_str = _get_commander_unit_id(current_user.username, "CmdB")
    if not battalion_id_str:
        flash('ID-ul batalionului nu a putut fi determinat.', 'warning')
        return redirect(url_for('battalion_commander_dashboard'))

    page = request.args.get('page', 1, type=int)
    per_page = 25

    # Similar cu company_commander_logs, dar filtrăm pe battalion_id_str
    base_query_battalion = ActionLog.query.join(User, ActionLog.user_id == User.id, isouter=True).options(joinedload(ActionLog.user))
    conditions_battalion = []

    student_subquery_b = db.session.query(Student.id).filter(Student.batalion == battalion_id_str).scalar_subquery()
    conditions_battalion.append(and_(ActionLog.target_model == 'Student', ActionLog.target_id.in_(student_subquery_b)))

    permission_subquery_b = db.session.query(Permission.id).join(Student, Permission.student_id == Student.id).filter(Student.batalion == battalion_id_str).scalar_subquery()
    conditions_battalion.append(and_(ActionLog.target_model == 'Permission', ActionLog.target_id.in_(permission_subquery_b)))

    daily_leave_subquery_b = db.session.query(DailyLeave.id).join(Student, DailyLeave.student_id == Student.id).filter(Student.batalion == battalion_id_str).scalar_subquery()
    conditions_battalion.append(and_(ActionLog.target_model == 'DailyLeave', ActionLog.target_id.in_(daily_leave_subquery_b)))

    weekend_leave_subquery_b = db.session.query(WeekendLeave.id).join(Student, WeekendLeave.student_id == Student.id).filter(Student.batalion == battalion_id_str).scalar_subquery()
    conditions_battalion.append(and_(ActionLog.target_model == 'WeekendLeave', ActionLog.target_id.in_(weekend_leave_subquery_b)))

    service_subquery_b = db.session.query(ServiceAssignment.id).join(Student, ServiceAssignment.student_id == Student.id).filter(Student.batalion == battalion_id_str).scalar_subquery()
    conditions_battalion.append(and_(ActionLog.target_model == 'ServiceAssignment', ActionLog.target_id.in_(service_subquery_b)))

    if conditions_battalion:
        final_query_battalion = base_query_battalion.filter(or_(*conditions_battalion)).order_by(ActionLog.timestamp.desc())
    else:
        final_query_battalion = base_query_battalion.order_by(ActionLog.timestamp.desc())

    logs_pagination = final_query_battalion.paginate(page=page, per_page=per_page, error_out=False)

    return render_template('commander_action_logs.html',
                           logs_pagination=logs_pagination,
                           title=f"Jurnal Acțiuni Batalionul {battalion_id_str}",
                           unit_id=battalion_id_str,
                           unit_type="Batalionul")


@app.route('/dashboard/battalion')
@login_required
def battalion_commander_dashboard():
    if current_user.role != 'comandant_batalion':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    battalion_id_str = _get_commander_unit_id(current_user.username, "CmdB")
    if not battalion_id_str:
        flash('ID-ul batalionului nu a putut fi determinat din numele de utilizator.', 'warning')
        return redirect(url_for('dashboard'))

    roll_call_datetime = get_standard_roll_call_datetime()
    roll_call_time_str = roll_call_datetime.strftime('%d %B %Y, %H:%M')

    students_in_battalion_all = Student.query.filter_by(batalion=battalion_id_str).all()
    student_ids_in_battalion = [s.id for s in students_in_battalion_all]

    total_battalion_presence_roll_call = _calculate_presence_data(students_in_battalion_all, roll_call_datetime) # For existing roll call report

    # New stats for "today"
    today_localized_battalion = get_localized_now().date()
    today_start = datetime.combine(today_localized_battalion, time.min)
    today_end = datetime.combine(today_localized_battalion, time.max)

    permissions_today_battalion_count = Permission.query.filter(
        Permission.student_id.in_(student_ids_in_battalion),
        Permission.status == 'Aprobată',
        Permission.start_datetime <= today_end,
        Permission.end_datetime >= today_start
    ).count()

    daily_leaves_today_battalion_count = DailyLeave.query.filter(
        DailyLeave.student_id.in_(student_ids_in_battalion),
        DailyLeave.status == 'Aprobată',
        DailyLeave.leave_date == today_localized_battalion
    ).count()

    weekend_leaves_today_battalion_count = 0
    all_wl_battalion_for_today_stats = WeekendLeave.query.filter(WeekendLeave.student_id.in_(student_ids_in_battalion), WeekendLeave.status == 'Aprobată').all()
    for wl_today in all_wl_battalion_for_today_stats:
        for interval_today in wl_today.get_intervals():
            if interval_today['start'].date() == today_localized_battalion or \
               interval_today['end'].date() == today_localized_battalion or \
               (interval_today['start'].date() < today_localized_battalion and interval_today['end'].date() > today_localized_battalion):
                weekend_leaves_today_battalion_count += 1
                break

    total_leaves_today_battalion_count = daily_leaves_today_battalion_count + weekend_leaves_today_battalion_count

    services_today_battalion_count = ServiceAssignment.query.filter(
        ServiceAssignment.student_id.in_(student_ids_in_battalion),
        ServiceAssignment.start_datetime <= today_end,
        ServiceAssignment.end_datetime >= today_start
    ).count()

    # Stats for "NOW"
    now_localized_b = get_localized_now()
    permissions_active_now_battalion = Permission.query.filter(
        Permission.student_id.in_(student_ids_in_battalion),
        Permission.status == 'Aprobată',
        Permission.start_datetime <= now_localized_b,
        Permission.end_datetime >= now_localized_b
    ).count()

    daily_leaves_active_now_battalion = 0
    all_dl_battalion = DailyLeave.query.filter(DailyLeave.student_id.in_(student_ids_in_battalion), DailyLeave.status == 'Aprobată').all()
    for dl_now_b in all_dl_battalion:
        if dl_now_b.is_active:
            daily_leaves_active_now_battalion +=1

    weekend_leaves_active_now_battalion = 0
    all_wl_battalion_for_now_stats = WeekendLeave.query.filter(WeekendLeave.student_id.in_(student_ids_in_battalion), WeekendLeave.status == 'Aprobată').all()
    for wl_now_b in all_wl_battalion_for_now_stats:
        if wl_now_b.is_any_interval_active_now:
            weekend_leaves_active_now_battalion += 1

    total_on_leave_now_battalion = permissions_active_now_battalion + daily_leaves_active_now_battalion + weekend_leaves_active_now_battalion

    services_active_now_battalion = ServiceAssignment.query.filter(
        ServiceAssignment.student_id.in_(student_ids_in_battalion),
        ServiceAssignment.start_datetime <= now_localized_b,
        ServiceAssignment.end_datetime >= now_localized_b
    ).count()

    companies_data_roll_call = {}
    companies_in_battalion = sorted(list(set(s.companie for s in students_in_battalion_all if s.companie)))
    for company_id_str_loop in companies_in_battalion:
        students_in_company_loop = [s for s in students_in_battalion_all if s.companie == company_id_str_loop]
        company_name = f"Compania {company_id_str_loop}"
        companies_data_roll_call[company_name] = _calculate_presence_data(students_in_company_loop, roll_call_datetime)

    return render_template('battalion_commander_dashboard.html',
                           battalion_id=battalion_id_str,
                           roll_call_time_str=roll_call_time_str,
                           total_battalion_presence=total_battalion_presence_roll_call,
                           companies_data=companies_data_roll_call,
                           # Statistici "Astăzi"
                           permissions_today_count=permissions_today_battalion_count,
                           daily_leaves_today_battalion=daily_leaves_today_battalion_count, # Nume nou
                           weekend_leaves_today_battalion=weekend_leaves_today_battalion_count, # Nume nou
                           total_leaves_today_count=total_leaves_today_battalion_count,
                           services_today_count=services_today_battalion_count,
                           total_students_battalion=len(student_ids_in_battalion),
                           # Statistici "ACUM"
                           permissions_active_now_battalion=permissions_active_now_battalion,
                           daily_leaves_active_now_battalion=daily_leaves_active_now_battalion,
                           weekend_leaves_active_now_battalion=weekend_leaves_active_now_battalion,
                           total_on_leave_now_battalion=total_on_leave_now_battalion,
                           services_active_now_battalion=services_active_now_battalion,
                           current_time_for_display=now_localized_b
                           )

# --- Volunteer Module ---
@app.route('/volunteer', methods=['GET', 'POST'])
@login_required
def volunteer_home():
    if current_user.role != 'gradat':
        flash('Acces neautorizat la modulul de voluntariat.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST': # Creare activitate nouă
        activity_name = request.form.get('activity_name', '').strip()
        activity_description = request.form.get('activity_description', '').strip()
        activity_date_str = request.form.get('activity_date')

        if not activity_name or not activity_date_str:
            flash('Numele activității și data sunt obligatorii.', 'warning')
            # Re-render GET part
            activities = VolunteerActivity.query.filter_by(created_by_user_id=current_user.id).order_by(VolunteerActivity.activity_date.desc()).all()
            students_with_points = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.volunteer_points.desc(), Student.nume).all()
            today_str_for_form = date.today().strftime('%Y-%m-%d')
            return render_template('volunteer_home.html', activities=activities, students_with_points=students_with_points, today_str=today_str_for_form)

        try:
            activity_date_obj = datetime.strptime(activity_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Format dată invalid pentru activitate.', 'danger')
            activities = VolunteerActivity.query.filter_by(created_by_user_id=current_user.id).order_by(VolunteerActivity.activity_date.desc()).all()
            students_with_points = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.volunteer_points.desc(), Student.nume).all()
            today_str_for_form = date.today().strftime('%Y-%m-%d')
            return render_template('volunteer_home.html', activities=activities, students_with_points=students_with_points, today_str=today_str_for_form)

        new_activity = VolunteerActivity(
            name=activity_name,
            description=activity_description,
            activity_date=activity_date_obj,
            created_by_user_id=current_user.id
        )
        db.session.add(new_activity)
        try:
            db.session.commit()
            flash(f'Activitatea de voluntariat "{activity_name}" a fost creată cu succes.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la crearea activității: {str(e)}', 'danger')
        return redirect(url_for('volunteer_home'))

    # GET request
    activities = VolunteerActivity.query.filter_by(created_by_user_id=current_user.id).order_by(VolunteerActivity.activity_date.desc()).all()
    students_with_points = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.volunteer_points.desc(), Student.nume).all()
    today_str_for_form = get_localized_now().date().strftime('%Y-%m-%d') # Folosim data localizată

    return render_template('volunteer_home.html',
                           activities=activities,
                           students_with_points=students_with_points,
                           today_str=today_str_for_form)

@app.route('/volunteer/activity/<int:activity_id>', methods=['GET', 'POST'])
@login_required
def volunteer_activity_details(activity_id):
    activity = VolunteerActivity.query.get_or_404(activity_id)
    if current_user.role != 'gradat' or activity.created_by_user_id != current_user.id:
        flash('Acces neautorizat la această activitate de voluntariat.', 'danger')
        return redirect(url_for('volunteer_home'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_participants':
            selected_student_ids = set(request.form.getlist('participant_ids[]', type=int))

            # Remove participants not selected anymore
            current_participants_in_activity = ActivityParticipant.query.filter_by(activity_id=activity.id).all()
            for ap in current_participants_in_activity:
                if ap.student_id not in selected_student_ids:
                    # Before deleting, if points were awarded, subtract them from student's total.
                    # This logic might need refinement: what if points were awarded for *this specific* participation?
                    # For now, if a student is removed, their points from this activity are effectively "lost" from this AP record.
                    # The Student.volunteer_points should ideally be a sum from all their AP records.
                    student_obj = db.session.get(Student, ap.student_id)
                    if student_obj: # Subtract points if student exists
                         student_obj.volunteer_points = max(0, student_obj.volunteer_points - ap.points_awarded) # Ensure not negative
                    db.session.delete(ap)

            # Add new participants
            for student_id_to_add in selected_student_ids:
                exists = ActivityParticipant.query.filter_by(activity_id=activity.id, student_id=student_id_to_add).first()
                if not exists:
                    # Ensure the student belongs to the current gradat
                    student_check = Student.query.filter_by(id=student_id_to_add, created_by_user_id=current_user.id).first()
                    if student_check:
                        new_participant = ActivityParticipant(activity_id=activity.id, student_id=student_id_to_add, points_awarded=0)
                        db.session.add(new_participant)
                    else:
                        flash(f"Studentul cu ID {student_id_to_add} nu a putut fi adăugat (nu este gestionat de dvs).", "warning")

            try:
                db.session.commit()
                # Recalculate total points for all affected students
                all_involved_student_ids = selected_student_ids.union(set(ap.student_id for ap in current_participants_in_activity))
                for s_id in all_involved_student_ids:
                    stud = db.session.get(Student, s_id)
                    if stud:
                        stud.volunteer_points = db.session.query(func.sum(ActivityParticipant.points_awarded)).filter_by(student_id=s_id).scalar() or 0
                db.session.commit()
                flash('Lista de participanți a fost actualizată.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Eroare la actualizarea participanților: {str(e)}', 'danger')

        elif action == 'award_points':
            points_to_award_val = request.form.get('points_to_award', type=int)
            participant_ids_for_points = set(request.form.getlist('points_participant_ids[]', type=int))

            if points_to_award_val is None or points_to_award_val < 0:
                flash('Numărul de puncte de acordat este invalid.', 'warning')
            else:
                updated_count = 0
                for student_id_for_points in participant_ids_for_points:
                    participant_record = ActivityParticipant.query.filter_by(activity_id=activity.id, student_id=student_id_for_points).first()
                    if participant_record:
                        # Option 1: Add to existing points for this activity
                        # participant_record.points_awarded += points_to_award_val
                        # Option 2: Set points for this activity (if points are per activity, not cumulative for it)
                        participant_record.points_awarded = points_to_award_val
                        updated_count +=1
                    else:
                        flash(f"Studentul cu ID {student_id_for_points} nu este participant la această activitate pentru a primi puncte.", "warning")

                if updated_count > 0:
                    try:
                        db.session.commit()
                        # Recalculate total points for all students who received points
                        for s_id in participant_ids_for_points:
                            stud = db.session.get(Student, s_id)
                            if stud: # Check if student still exists
                                total_points = db.session.query(func.sum(ActivityParticipant.points_awarded)).filter_by(student_id=s_id).scalar()
                                stud.volunteer_points = total_points if total_points is not None else 0
                        db.session.commit()
                        flash(f'{points_to_award_val} puncte acordate pentru {updated_count} participanți selectați.', 'success')
                    except Exception as e:
                        db.session.rollback()
                        flash(f'Eroare la acordarea punctelor: {str(e)}', 'danger')
        else:
            flash('Acțiune necunoscută.', 'danger')

        return redirect(url_for('volunteer_activity_details', activity_id=activity.id))

    # GET request
    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()

    # Get current participant student IDs for this activity
    current_participant_ids = [ap.student_id for ap in ActivityParticipant.query.filter_by(activity_id=activity.id).all()]

    # Get detailed participant info (ActivityParticipant object + Student object)
    activity_participants_detailed_query = db.session.query(ActivityParticipant, Student).\
        join(Student, ActivityParticipant.student_id == Student.id).\
        filter(ActivityParticipant.activity_id == activity.id).all()

    # activity_participants_detailed will be a list of (ActivityParticipant, Student) tuples
    # The template already uses this structure in the loop: {% for participant, student_detail in activity_participants_detailed %}

    return render_template('volunteer_activity_details.html',
                           activity=activity,
                           students_managed=students_managed,
                           current_participant_ids=current_participant_ids,
                           activity_participants_detailed=activity_participants_detailed_query)

@app.route('/volunteer/generate', methods=['GET', 'POST'])
@login_required
def volunteer_generate_students():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    generated_students_list = None
    num_students_req_val = 5 # Default value for GET
    exclude_girls_val = False # Default value for GET

    if request.method == 'POST':
        try:
            num_students_req_val = int(request.form.get('num_students', 5))
            if num_students_req_val <= 0:
                flash("Numărul de studenți necesari trebuie să fie pozitiv.", "warning")
                num_students_req_val = 5 # Reset to default if invalid
        except ValueError:
            flash("Număr de studenți invalid.", "warning")
            num_students_req_val = 5 # Reset to default

        exclude_girls_val = 'exclude_girls' in request.form

        students_query = Student.query.filter_by(created_by_user_id=current_user.id)
        if exclude_girls_val:
            students_query = students_query.filter(Student.gender != 'F')

        generated_students_list = students_query.order_by(Student.volunteer_points.asc(), Student.nume.asc()).limit(num_students_req_val).all()

        if not generated_students_list:
            flash('Nu s-au găsit studenți conform criteriilor specificate sau nu aveți studenți în evidență.', 'info')

    return render_template('volunteer_generate_students.html',
                           generated_students=generated_students_list,
                           num_students_requested=num_students_req_val,
                           exclude_girls_opt=exclude_girls_val)

@app.route('/volunteer/activity/delete/<int:activity_id>', methods=['POST'], endpoint='delete_volunteer_activity')
@login_required
def delete_volunteer_activity(activity_id):
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('volunteer_home'))

    activity_to_delete = VolunteerActivity.query.get_or_404(activity_id)

    if activity_to_delete.created_by_user_id != current_user.id:
        flash('Nu aveți permisiunea să ștergeți această activitate de voluntariat.', 'danger')
        return redirect(url_for('volunteer_home'))

    activity_name_for_log = activity_to_delete.name
    details_before_activity_delete = model_to_dict(activity_to_delete)
    participants_details_before = []
    student_points_adjustments = {} # student_id: {old_total: X, points_removed: Y, new_total: Z}

    try:
        # Iterează prin participanți pentru a ajusta punctele și a colecta detalii pentru log
        for participant in activity_to_delete.participants: # activity.participants este o interogare lazy='dynamic'
            student = participant.student # Ar trebui să existe datorită FK
            if student:
                points_to_remove = participant.points_awarded

                participants_details_before.append({
                    "participant_id": participant.id,
                    "student_id": student.id,
                    "student_name": f"{student.nume} {student.prenume}",
                    "points_awarded_in_activity": points_to_remove,
                    "student_total_points_before_adj": student.volunteer_points
                })

                student.volunteer_points = max(0, student.volunteer_points - points_to_remove)

                student_points_adjustments[student.id] = {
                    "old_total": participants_details_before[-1]["student_total_points_before_adj"], # Ultima valoare adăugată
                    "points_removed": points_to_remove,
                    "new_total": student.volunteer_points
                }

            # Nu este nevoie să ștergem explicit participantul dacă cascade="all, delete-orphan" este setat
            # pe VolunteerActivity.participants și funcționează corect.
            # Dar dacă vrem să fim siguri sau dacă cascada nu e setată/funcțională:
            # db.session.delete(participant) # Acest lucru va fi gestionat de cascadă

        # Șterge activitatea (participanții ar trebui șterși prin cascadă)
        db.session.delete(activity_to_delete)

        # Log principal pentru ștergerea activității
        log_description = (
            f"User {current_user.username} deleted volunteer activity '{activity_name_for_log}' (ID: {activity_id}). "
            f"{len(participants_details_before)} participant records were associated. Points adjusted for students."
        )
        # Adăugăm și detaliile despre ajustarea punctelor la descriere sau ca un JSON separat
        # Poate fi prea mult pentru description, mai bine în details_before/after dacă e cazul

        log_action("DELETE_VOLUNTEER_ACTIVITY_SUCCESS",
                   target_model_name="VolunteerActivity",
                   target_id=activity_id,
                   details_before_dict={
                       "activity": details_before_activity_delete,
                       "participants_before_delete": participants_details_before,
                       "student_points_adjustments": student_points_adjustments
                   },
                   description=log_description)

        db.session.commit()
        flash(f'Activitatea de voluntariat "{activity_name_for_log}" și punctele asociate au fost șterse cu succes.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la ștergerea activității de voluntariat: {str(e)}', 'danger')
        log_action("DELETE_VOLUNTEER_ACTIVITY_FAIL",
                   target_model_name="VolunteerActivity",
                   target_id=activity_id,
                   details_before_dict=details_before_activity_delete, # Log ce s-a încercat să se șteargă
                   description=f"User {current_user.username} failed to delete volunteer activity '{activity_name_for_log}'. Error: {str(e)}")
        db.session.commit() # Commit log-ul de eroare

    return redirect(url_for('volunteer_home'))


# --- Management Studenți ---
@app.route('/gradat/students')
@app.route('/admin/students')
@login_required
def list_students():
    is_admin_view = current_user.role == 'admin' and request.path.startswith('/admin/')
    page = request.args.get('page', 1, type=int)
    per_page = 15

    students_query = Student.query
    # For populating filter dropdowns - consider optimizing if it becomes slow
    # These filters are primarily for admin view.
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
        students_query = students_query.options(joinedload(Student.creator)) # Admin might want to see creator info
        if filter_batalion: students_query = students_query.filter(Student.batalion == filter_batalion)
        if filter_companie: students_query = students_query.filter(Student.companie == filter_companie)
        if filter_pluton: students_query = students_query.filter(Student.pluton == filter_pluton)
        students_query = students_query.order_by(Student.batalion, Student.companie, Student.pluton, Student.nume, Student.prenume)
    elif current_user.role == 'gradat':
        students_query = students_query.filter_by(created_by_user_id=current_user.id)
        # Gradat might not need sub-filters for platoon/company as they manage specific students
        students_query = students_query.order_by(Student.nume, Student.prenume)
    elif current_user.role == 'comandant_companie':
        company_id = _get_commander_unit_id(current_user.username, "CmdC")
        if company_id:
            students_query = students_query.filter(Student.companie == company_id)
            if filter_pluton: students_query = students_query.filter(Student.pluton == filter_pluton) # Allow CmdC to filter by platoon
            students_query = students_query.order_by(Student.pluton, Student.nume, Student.prenume)
        else:
            flash('ID Companie nevalid pentru comandant.', 'danger')
            students_query = students_query.filter(Student.id == -1) # No results
    elif current_user.role == 'comandant_batalion':
        battalion_id = _get_commander_unit_id(current_user.username, "CmdB")
        if battalion_id:
            students_query = students_query.filter(Student.batalion == battalion_id)
            if filter_companie: students_query = students_query.filter(Student.companie == filter_companie) # Allow CmdB to filter by company
            if filter_pluton: students_query = students_query.filter(Student.pluton == filter_pluton)       # And platoon
            students_query = students_query.order_by(Student.companie, Student.pluton, Student.nume, Student.prenume)
        else:
            flash('ID Batalion nevalid pentru comandant.', 'danger')
            students_query = students_query.filter(Student.id == -1) # No results
    else: # Should not happen due to @login_required and role checks in other views
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

    # Determine title based on role
    view_title = "Listă Studenți"
    if is_admin_view: view_title = "Listă Generală Studenți (Admin)"
    elif current_user.role == 'gradat': view_title = "Listă Studenți Gestionați"
    elif current_user.role == 'comandant_companie': view_title = f"Listă Studenți Compania {_get_commander_unit_id(current_user.username, 'CmdC') or 'N/A'}"
    elif current_user.role == 'comandant_batalion': view_title = f"Listă Studenți Batalionul {_get_commander_unit_id(current_user.username, 'CmdB') or 'N/A'}"


    return render_template('list_students.html',
                           students=students_list,
                           students_pagination=students_pagination,
                           is_admin_view=is_admin_view, # Keep for template logic (e.g. showing creator)
                           search_term=search_term,
                           # Filters are available based on role now
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
            db.session.flush() # Assign ID to new_student for logging
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
                # Construct dict of attempted data for logging
                attempted_data = {
                    "nume": nume, "prenume": prenume, "grad_militar": grad_militar,
                    "id_unic_student": id_unic_student_form, "gender": gender, "pluton": pluton,
                    "companie": companie, "batalion": batalion,
                    "is_platoon_graded_duty": is_platoon_graded_duty_val,
                    "created_by_user_id": current_user.id
                }
                log_action("CREATE_STUDENT_FAIL", target_model_name="Student",
                           description=f"User {current_user.username} failed to add student. Error: {str(e)}",
                           details_after_dict=attempted_data) # Log attempted data in details_after
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
    details_before_edit = model_to_dict(s_edit) # Capture state before any changes

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
                           details_before_dict=details_before_edit, # Log original state
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
        if len(parts) < 7: # Grad Nume Prenume Gen Pluton Companie Batalion
            error_details.append(f"Linia {i+1} ('{line}'): Format incorect - prea puține câmpuri.")
            error_count += 1
            continue

        # Assuming format: Grad Nume Prenume Gen Pluton Companie Batalion
        # Grad could be one or more words
        # Nume is one word
        # Prenume is one word (or more, but this simple split won't handle it well without more complex parsing)
        # For simplicity, let's assume Nume and Prenume are single words for now,
        # and Grad takes up the initial part.
        # A more robust parser would be needed for multi-word names/ranks.

        # Tentative parsing:
        # Batalion is the last part
        # Companie is the second to last
        # Pluton is the third to last
        # Gen is the fourth to last
        # This leaves Grad, Nume, Prenume for the rest.
        # Let's assume Nume is parts[-5] and Prenume is parts[-6] if they exist,
        # and Grad is everything before that.

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
            # Check against GENDERS list, comparing uppercase input with uppercase GENDERS values
            # This handles "Nespecificat", "nespecificat", "NESPECIFICAT" etc.
            elif gender_input_upper in [g.upper() for g in GENDERS]:
                # Find the original casing from GENDERS to store in DB
                gender_db_val = next(g_val for g_val in GENDERS if g_val.upper() == gender_input_upper)
            else:
                error_details.append(f"Linia {i+1} ('{line}'): Gen '{gender_input_original}' invalid. Folosiți M, F sau Nespecificat.")
                error_count += 1
                continue

            # The remaining parts are for Grad, Nume, Prenume
            # Example: "Mm V Renț Francisc" -> parts_for_name_rank = ["Mm", "V", "Renț", "Francisc"]
            # Assume Prenume is the second to last of these, Nume is before Prenume.
            # This is a simplification.
            name_rank_parts = parts[:-4]
            if len(name_rank_parts) < 3: # Need at least Grad, Nume, Prenume
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

            # Basic check for existing student (by name and platoon/company) to avoid simple duplicates by this import
            # A more robust check might use id_unic_student if provided and unique
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
                is_platoon_graded_duty=False # Default, can be edited later
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
            db.session.rollback() # Rollback for this specific error if it occurred mid-student-creation
            continue

    if added_count > 0:
        try:
            db.session.commit()
            flash(f'{added_count} studenți au fost adăugați cu succes.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la salvarea studenților în baza de date: {str(e)}', 'danger')
            error_count += added_count # Consider them errors if commit failed
            added_count = 0

    if error_count > 0:
        flash(f'{error_count} linii nu au putut fi procesate sau au generat erori.', 'danger')
        if error_details:
            flash_detail_msg = "Detalii erori:<br>" + "<br>".join(error_details)
            if len(flash_detail_msg) > 500: # Limit flash message length
                flash_detail_msg = flash_detail_msg[:497] + "..."
            flash(flash_detail_msg, 'warning')

    return redirect(url_for('list_students'))

# Funcționalitatea 'Gradat Companie' a fost eliminată. Am șters ruta și funcția admin_toggle_company_grader_status.

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
        log_action("DELETE_STUDENT_SUCCESS", target_model_name="Student", target_id=student_id, # Use student_id from param as object is deleted
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

    now = get_localized_now() # Folosim ora localizată
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

    # For past_permissions, we need to be careful not to re-query without joinedload if base_query changes
    # It's better to fetch IDs and then query separately or ensure joinedload is consistently applied.
    # The current approach for past_permissions might be okay if base_query is reused,
    # but let's be explicit if we construct a new query.
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

        current_form_data_post = request.form # For repopulating form on error

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

        student_to_check = db.session.get(Student, int(student_id)) # Use db.session.get for clarity
        if not student_to_check or student_to_check.created_by_user_id != current_user.id:
            flash('Student invalid sau nu vă aparține.', 'danger')
            return render_template('add_edit_permission.html', form_title=form_title, permission=None, students=students_managed, form_data=current_form_data_post)

        # Conflict checking (remains largely the same)
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


        if permission: # Editing existing permission
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
        else: # Adding new permission
            permission = Permission(student_id=int(student_id), start_datetime=start_dt, end_datetime=end_dt,
                                   destination=destination, transport_mode=transport_mode, reason=reason,
                                   status='Aprobată', created_by_user_id=current_user.id)
            db.session.add(permission)
            action_type = "CREATE_PERMISSION_SUCCESS"
            flash_msg_text = 'Permisie adăugată cu succes!'
            # For create, details_before is None or {}
            # Description will be set after flush to get ID
            log_description = f"{action_description_prefix} created permission for {original_student_name_for_log}."


        try:
            db.session.flush() # Ensure permission object has ID if new, and updates are in session
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
                # For create fail, permission object might not have an ID yet if flush failed.
                # If it was an edit, permission.id is valid.
                target_id_for_fail_log = permission.id if permission and permission.id else None
                # Log attempted data for create fail
                attempted_data_on_fail = model_to_dict(permission) if permission else current_form_data_post

                log_action(fail_action_type, target_model_name="Permission", target_id=target_id_for_fail_log,
                           details_before_dict=log_details_before if permission_id else None,
                           details_after_dict=attempted_data_on_fail if not permission_id else model_to_dict(permission), # Log current state of 'permission' on edit fail
                           description=f"{action_description_prefix} failed to {action_type.split('_')[0].lower()} permission for {original_student_name_for_log}. Error: {str(e)}")
                db.session.commit()
            except Exception as log_e:
                app.logger.error(f"CRITICAL: Failed to commit failure log for {fail_action_type}: {str(log_e)}")
            return render_template('add_edit_permission.html', form_title=form_title, permission=permission if permission_id else None, students=students_managed, form_data=current_form_data_post)
        return redirect(url_for('list_permissions'))

    # GET request handling
    form_data_on_get = {} # Renamed from data_to_populate_form_with for clarity
    if permission: # Editing existing permission
        form_data_on_get = {
            'student_id': str(permission.student_id),
            'start_datetime': permission.start_datetime.strftime('%Y-%m-%dT%H:%M') if permission.start_datetime else '',
            'end_datetime': permission.end_datetime.strftime('%Y-%m-%dT%H:%M') if permission.end_datetime else '',
            'destination': permission.destination or '',
            'transport_mode': permission.transport_mode or '',
            'reason': permission.reason or ''
        }
    # If it's a POST request that failed validation and re-rendered, current_form_data_post (passed as form_data) will be used by template.
    # If it's a fresh GET for 'add', form_data_on_get remains empty, template shows empty fields.

    return render_template('add_edit_permission.html',
                           form_title=form_title,
                           permission=permission, # Pass the permission object itself for the template
                           students=students_managed,
                           form_data=form_data_on_get if request.method == 'GET' and permission else request.form if request.method == 'POST' else {})


def find_student_for_bulk_import(name_line, gradat_id):
    """
    Helper function to find a student based on a name line (Grad Nume Prenume).
    Uses unidecode for accent-insensitive matching.
    Prioritizes exact matches on (Grad, Nume, Prenume).
    Then tries partial matches on (Nume, Prenume) if Grad is also similar or not specified.
    """
    name_line_norm = unidecode(name_line.lower().strip())
    if not name_line_norm:
        return None, "Linie nume goală."

    students_managed = Student.query.filter_by(created_by_user_id=gradat_id).all()
    if not students_managed:
        return None, "Niciun student gestionat de acest gradat."

    # Try to extract rank for more precise matching
    parsed_grad_bulk = None
    student_name_str_bulk = name_line # Default to full line if no rank pattern matches
    for pattern in KNOWN_RANK_PATTERNS: # KNOWN_RANK_PATTERNS is global
        match = pattern.match(name_line)
        if match:
            parsed_grad_bulk = match.group(0).strip()
            student_name_str_bulk = pattern.sub("", name_line).strip()
            break

    normalized_search_name_bulk = unidecode(student_name_str_bulk.lower())

    matched_students = []
    # Pass 1: Exact match on normalized name and rank (if rank parsed)
    for s in students_managed:
        s_fullname_norm = unidecode(f"{s.nume} {s.prenume}".lower())
        s_grad_norm = unidecode(s.grad_militar.lower())

        if parsed_grad_bulk:
            parsed_grad_bulk_norm = unidecode(parsed_grad_bulk.lower())
            if normalized_search_name_bulk == s_fullname_norm and parsed_grad_bulk_norm == s_grad_norm:
                matched_students.append(s)
        else: # No rank in input, try to match only by name
            if normalized_search_name_bulk == s_fullname_norm:
                 matched_students.append(s)

    if len(matched_students) == 1: return matched_students[0], None
    if len(matched_students) > 1: return None, f"Potriviri multiple exacte pentru '{name_line}'"

    # Pass 2: More lenient matching (e.g., input name is part of DB name or vice-versa, rank is similar)
    # This is more complex and might lead to false positives, keeping it simpler for now.
    # For now, if exact match failed, we rely on the user providing very precise names.

    # Pass 2: Lenient match on name parts (Nume Prenume vs Prenume Nume), rank similarity
    # This pass tries to find a unique student if the exact match (Pass 1) failed.
    if not matched_students: # Only if Pass 1 found nothing
        potential_matches = []
        for s in students_managed:
            s_fullname_norm = unidecode(f"{s.nume} {s.prenume}".lower())
            s_fullname_reversed_norm = unidecode(f"{s.prenume} {s.nume}".lower())
            s_grad_norm = unidecode(s.grad_militar.lower())

            # Check if normalized_search_name_bulk (name from input without rank)
            # matches student's full name in either order
            name_match_direct = (normalized_search_name_bulk == s_fullname_norm)
            name_match_reversed = (normalized_search_name_bulk == s_fullname_reversed_norm)

            if name_match_direct or name_match_reversed:
                if parsed_grad_bulk: # If rank was parsed from input
                    parsed_grad_bulk_norm = unidecode(parsed_grad_bulk.lower())
                    # Check for rank similarity (e.g., "sdt" vs "sdt.", "cap" vs "cap.")
                    # A simple check: if parsed rank is a substring of DB rank or vice-versa
                    if parsed_grad_bulk_norm in s_grad_norm or s_grad_norm in parsed_grad_bulk_norm:
                        potential_matches.append(s)
                    # else: name matches, but rank doesn't, so it's not a good potential match
                else: # No rank in input, name match is enough to be a potential candidate
                    potential_matches.append(s)

        if len(potential_matches) == 1:
            return potential_matches[0], None # Found a single, reasonably good match
        elif len(potential_matches) > 1:
            # Construct a more informative error message for multiple lenient matches
            student_names_found = [f"{s.grad_militar} {s.nume} {s.prenume}" for s in potential_matches]
            return None, f"Potriviri multiple pentru '{name_line}': {', '.join(student_names_found)}. Clarificați gradul sau numele."


    # If still no single match after both passes
    if not matched_students and not potential_matches: # Check potential_matches from Pass 2
         return None, f"Studentul '{name_line}' nu a fost găsit. Verificați numele și gradul."
    elif len(matched_students) > 1 : # From Pass 1
         return None, f"Potriviri multiple exacte pentru '{name_line}'. Clarificați."


    # Fallback if logic is somehow bypassed, though it shouldn't be.
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
        if not name_line: # Skip empty lines used as separators
            i += 1
            continue

        # We need at least 3 lines for a valid entry (Name, Date, Destination)
        # but we will try to be more flexible.

        # Line 1: Student Name (mandatory)
        # Line 2: Datetime interval (mandatory)
        # Line 3: Destination (mandatory)
        # Line 4: Transport Mode (optional)
        # Line 5: Reason/Car Plate (optional)

        lines_for_this_entry = []

        # Consume lines until an empty line or end of input
        temp_i = i
        while temp_i < len(lines) and lines[temp_i].strip():
            lines_for_this_entry.append(lines[temp_i].strip())
            temp_i += 1

        num_actual_lines_for_entry = len(lines_for_this_entry)

        if num_actual_lines_for_entry < 3:
            if num_actual_lines_for_entry > 0: # If there was at least one line before running out
                 error_details.append(f"Intrare incompletă începând cu '{lines_for_this_entry[0]}'. Necesită cel puțin Nume, Interval, Destinație.")
                 error_count += 1
            # If num_actual_lines_for_entry is 0, it means we hit multiple empty lines, which is fine.
            i = temp_i # Advance past the consumed (or non-existent) lines
            if num_actual_lines_for_entry > 0 : i+=1 # also advance past the empty line that terminated the block
            continue


        name_line = lines_for_this_entry[0]
        datetime_line = lines_for_this_entry[1]
        destination_line = lines_for_this_entry[2]

        transport_mode_line = lines_for_this_entry[3] if num_actual_lines_for_entry > 3 else ""
        reason_car_plate_line = lines_for_this_entry[4] if num_actual_lines_for_entry > 4 else ""

        # Advance main loop counter by the number of non-empty lines processed for this entry + 1 for the empty separator line (if any)
        i = temp_i
        if temp_i < len(lines) and not lines[temp_i].strip(): # If terminated by an empty line
            i += 1


        student_obj, student_error = find_student_for_bulk_import(name_line, current_user.id)
        if student_error:
            error_details.append(f"Linia '{name_line}': {student_error}")
            error_count += 1
            # i already advanced by num_actual_lines_for_entry + possible empty line
            continue

        # Parse datetime
        try:
            # Regex to find DD.MM.YYYY HH:MM - DD.MM.YYYY HH:MM or DD.MM.YYYY HH:MM - HH:MM
            # This regex is more robust for variations in date specification for end time.
            dt_match = re.search(
                r"(\d{1,2}\.\d{1,2}\.\d{4})\s+(\d{1,2}:\d{2})\s*-\s*(?:(\d{1,2}\.\d{1,2}\.\d{4})\s+)?(\d{1,2}:\d{2})",
                datetime_line
            )
            if not dt_match:
                # Log the actual datetime_line that failed parsing for easier debugging
                app.logger.warning(f"Bulk Permission Import: Invalid datetime format for student '{name_line}'. Input: '{datetime_line}'. Expected 'DD.MM.YYYY HH:MM - [DD.MM.YYYY] HH:MM'.")
                raise ValueError("Format interval datetime invalid.") # Mesaj mai scurt pentru flash

            start_date_str, start_time_str, end_date_str_opt, end_time_str = dt_match.groups()

            start_dt = datetime.strptime(f"{start_date_str} {start_time_str}", '%d.%m.%Y %H:%M')

            if end_date_str_opt: # If end date is explicitly provided
                end_dt = datetime.strptime(f"{end_date_str_opt} {end_time_str}", '%d.%m.%Y %H:%M')
            else: # End date not provided, assume same day as start_dt or next day if end_time < start_time
                end_time_obj_parsed = datetime.strptime(end_time_str, '%H:%M').time()
                end_date_assumed = start_dt.date()
                # If end_time is on the next day (e.g. 22:00 - 02:00)
                if end_time_obj_parsed < start_dt.time():
                    end_date_assumed += timedelta(days=1)
                end_dt = datetime.combine(end_date_assumed, end_time_obj_parsed)

            if end_dt <= start_dt:
                app.logger.warning(f"Bulk Permission Import: End datetime not after start for student '{name_line}'. Start: {start_dt}, End: {end_dt}")
                raise ValueError("Data/ora de sfârșit trebuie să fie după data/ora de început.")

        except ValueError as ve:
            # Log original error if not one of the custom messages above
            if str(ve) not in ["Format interval datetime invalid.", "Data/ora de sfârșit trebuie să fie după data/ora de început."]:
                 app.logger.error(f"Bulk Permission Import: ValueError parsing datetime for student '{name_line}', line '{datetime_line}': {str(ve)}")
            error_details.append(f"Student '{name_line}': Eroare format dată/oră în '{datetime_line}' - {str(ve)}")
            error_count += 1
            # i already advanced
            continue

        parsed_destination = destination_line.strip()
        parsed_transport_mode = transport_mode_line.strip() if transport_mode_line else None
        parsed_reason = reason_car_plate_line.strip() if reason_car_plate_line else None


        # Conflict Checking
        # Ensure student_obj is not None before accessing student_obj.id
        if not student_obj: # Should have been caught by student_error, but as a safe guard
            error_details.append(f"Eroare internă: student_obj este None pentru linia '{name_line}' după ce student_error a fost None.")
            error_count += 1
            continue

        conflict = check_leave_conflict(student_obj.id, start_dt, end_dt, leave_type='permission')
        if conflict:
            error_details.append(f"Student '{name_line}': Conflict - {conflict}.")
            error_count += 1
            i += lines_this_entry
            continue

        # Create and add permission
        new_permission = Permission(
            student_id=student_obj.id,
            start_datetime=start_dt,
            end_datetime=end_dt,
            destination=parsed_destination,
            transport_mode=parsed_transport_mode, # Now supported
            reason=parsed_reason,
            status='Aprobată',
            created_by_user_id=current_user.id
        )

        try:
            db.session.add(new_permission)
            # Defer flush and commit until the end of the loop for bulk operations
            added_count += 1
        except Exception as e_add: # Should ideally not happen if just adding to session
            # If db.session.add() itself can fail, then a rollback might be needed here,
            # but typically it's the commit that fails.
            # For safety, if an unexpected error occurs here:
            db.session.rollback() # Rollback the current transaction if add fails.
            error_details.append(f"Student '{name_line}': Eroare la adăugare în sesiune DB - {str(e_add)}")
            error_count += 1
            # i is already advanced by the logic at the start of the loop iteration
            continue

        # i is advanced at the beginning of the loop iteration.


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
            if len(flash_detail_msg) > 1000: # Limit flash message length further
                flash_detail_msg = flash_detail_msg[:997] + "..."
            flash(flash_detail_msg, 'warning')

    if added_count > 0 or error_count > 0: # If anything was processed or attempted
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

    now = get_localized_now() # Folosim ora localizată
    # Fetch active and upcoming permissions only for the export
    permissions_to_export = Permission.query.options(joinedload(Permission.student)).filter(
        Permission.student_id.in_(student_ids_managed_by_gradat),
        Permission.status == 'Aprobată',
        Permission.end_datetime >= now # Active or upcoming
    ).join(Student).order_by(Student.nume, Student.prenume, Permission.start_datetime).all()

    if not permissions_to_export:
        flash('Nicio permisie activă sau viitoare de exportat.', 'info')
        return redirect(url_for('list_permissions'))

    document = Document()
    document.add_heading('Raport Permisii Studenți', level=1).alignment = WD_ALIGN_PARAGRAPH.CENTER

    # User and date info
    user_info_text = f"Raport generat de: {current_user.username}\nData generării: {datetime.now().strftime('%d-%m-%Y %H:%M')}"
    p_user = document.add_paragraph()
    p_user.add_run(user_info_text).italic = True
    p_user.alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_paragraph() # Spacer

    table = document.add_table(rows=1, cols=8) # Increased cols to 8
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
        row_cells[7].text = p.reason if p.reason else "-" # p.reason might contain car plate or other notes
        row_cells[7].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER # Center if it's just car plate

    # Set column widths (optional, but good for layout) - adjust for 8 columns
    # Old: {0: 0.5, 1: 0.8, 2: 2.0, 3: 1.2, 4: 1.2, 5: 2.0, 6: 1.0} # Sum = 8.7
    # New: NrCrt, Grad, Nume, Start, End, Dest, Transport, Obs/Auto
    # Total width around 8.5-9 inches for A4 portrait with margins
    widths = {
        0: Inches(0.4), # Nr. Crt.
        1: Inches(0.7), # Grad
        2: Inches(1.8), # Nume și Prenume
        3: Inches(1.1), # Data Început
        4: Inches(1.1), # Data Sfârșit
        5: Inches(1.5), # Destinația
        6: Inches(1.2), # Mijloc Transport
        7: Inches(1.2)  # Observații/Nr. Auto
    }
    # Apply widths
    for col_idx, width_val in widths.items():
        for row in table.rows:
            try:
                row.cells[col_idx].width = width_val
            except IndexError:
                app.logger.warning(f"IndexError setting width for col {col_idx} in export_permissions_word. Row has {len(row.cells)} cells.")


    # Change font for the whole document (optional)
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
        return redirect(url_for('list_permissions') if current_user.role == 'gradat' else url_for('admin_dashboard_route')) # Sau o pagină admin relevantă

    student_owner = db.session.get(Student, permission_to_delete.student_id)

    if current_user.role == 'gradat':
        if not student_owner or student_owner.created_by_user_id != current_user.id:
            flash('Nu aveți permisiunea să ștergeți această permisie.', 'danger')
            return redirect(url_for('list_permissions'))
        redirect_url = url_for('list_permissions')
    elif current_user.role == 'admin':
        # Admin poate șterge orice permisie, dar poate afișăm un warning dacă aparține altui gradat
        if student_owner and student_owner.creator and student_owner.creator.username != current_user.username: # Presupunând că admin nu e creator direct
             flash(f'Atenție: Ștergeți o permisie pentru studentul {student_owner.nume} {student_owner.prenume}, gestionat de {student_owner.creator.username}.', 'warning')
        redirect_url = request.referrer or url_for('admin_dashboard_route') # sau o listă de permisii admin, dacă există
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
    today_string_for_form = get_localized_now().date().strftime('%Y-%m-%d') # Folosim data localizată
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
    form_title = "Adaugă Învoire Zilnică"; daily_leave = None; today_string = get_localized_now().date().strftime('%Y-%m-%d') # Folosim data localizată
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

        # Removed the restrictive is_in_program and is_out_program checks.
        # The primary validation will be that end_datetime is after start_datetime.

        start_dt = datetime.combine(leave_date_obj, start_time_obj)
        effective_end_date = leave_date_obj
        # Determine if end_time implies the next day
        if end_time_obj < start_time_obj: # This condition means it spans midnight
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

def parse_leave_line(line_text): # Renamed from parse_leave_line_new for replacement
    parts = line_text.strip().split()
    grad = None
    parsed_start_time_obj = None
    parsed_end_time_obj = None
    normalized_name_search = None

    if not parts:
        return None, None, None, None

    name_parts = list(parts) # Make a mutable copy

    # Try to parse time range HH:MM-HH:MM from the end
    if len(name_parts) > 0:
        time_range_match = re.fullmatch(r"(\d{1,2}:\d{2})-(\d{1,2}:\d{2})", name_parts[-1])
        if time_range_match:
            try:
                parsed_start_time_obj = datetime.strptime(time_range_match.group(1), '%H:%M').time()
                parsed_end_time_obj = datetime.strptime(time_range_match.group(2), '%H:%M').time()
                name_parts.pop() # Remove the time string from name_parts
            except ValueError:
                # Invalid time format in range, reset times, it will be treated as part of name
                parsed_start_time_obj = None
                parsed_end_time_obj = None
                # name_parts remains as is, time string is part of the name

    if not name_parts: # If only time was provided, or all parts were consumed
        return None, None, None, None

    student_name_str = " ".join(name_parts)
    # Attempt to extract military rank
    for pattern in KNOWN_RANK_PATTERNS:
        match = pattern.match(student_name_str)
        if match:
            grad = match.group(0).strip()
            student_name_str = pattern.sub("", student_name_str).strip()
            break

    if student_name_str: # If there's any name left after stripping rank
        normalized_name_search = unidecode(student_name_str.lower())
    else: # Only rank was found, or empty string
        return None, grad, parsed_start_time_obj, parsed_end_time_obj # Might be only rank + time

    return normalized_name_search, grad, parsed_start_time_obj, parsed_end_time_obj

def parse_weekend_leave_line(line_text_raw):
    line_text = line_text_raw.strip()
    is_biserica_requested = False

    # 1. Check for "biserica" keyword and remove it
    # Handles "biserica" at the end, possibly preceded by a comma.
    biserica_keyword = "biserica"
    if line_text.lower().endswith(f" {biserica_keyword}"):
        is_biserica_requested = True
        line_text = line_text[:-len(f" {biserica_keyword}")].strip()
    elif line_text.lower().endswith(f",{biserica_keyword}"):
        is_biserica_requested = True
        line_text = line_text[:-len(f",{biserica_keyword}")].strip()
    elif line_text.lower() == biserica_keyword: # Line is ONLY "biserica"
        return "", [], True, "Linia conține doar 'biserica', fără student sau intervale."


    # 2. Extract all date-time interval strings first using a regex pattern
    # Pattern: DD.MM.YYYY HH:MM-HH:MM (flexible spacing around hyphen)
    interval_pattern = re.compile(r"(\d{1,2}\.\d{1,2}\.\d{4})\s+(\d{1,2}:\d{2})\s*-\s*(\d{1,2}:\d{2})")

    raw_interval_parts = [] # Store (date_str, start_str, end_str)

    # Find all matches and store their string parts
    for match in interval_pattern.finditer(line_text):
        raw_interval_parts.append(match.groups()) # (date_str, start_str, end_str)

    if not raw_interval_parts:
        student_name_part_if_no_intervals = line_text.replace(",", "").strip()
        if not student_name_part_if_no_intervals and not is_biserica_requested: # Empty line
             app.logger.debug(f"parse_weekend_leave_line: Skipping empty or biserica-only line: '{line_text_raw}'")
             return None, [], False, None # Signal to skip empty line processing
        app.logger.warning(f"parse_weekend_leave_line: No valid datetime intervals found in line: '{line_text_raw}'. Student part considered: '{student_name_part_if_no_intervals}'. Biserica: {is_biserica_requested}")
        return student_name_part_if_no_intervals, [], is_biserica_requested, "Niciun interval de timp valid (DD.MM.YYYY HH:MM-HH:MM) găsit."

    # Attempt to parse these string parts into datetime objects
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
                'raw_match': f"{date_str} {start_str}-{end_str}" # Store the raw match for removal later
            })
        except ValueError:
            return line_text, [], is_biserica_requested, f"Format dată/oră invalid în intervalul '{date_str} {start_str}-{end_str}'."

    # 3. Determine student name part by removing interval strings from the original line
    student_name_part = line_text
    # Iterate over a sorted list of raw matches by length (desc) to remove longer matches first (more specific)
    # This helps if one raw match string could be a substring of another, though less likely with this pattern.
    # For safety, or just iterate as found.
    raw_matches_to_remove = [item['raw_match'] for item in parsed_intervals] # Get all parts that were successfully parsed

    # Reconstruct the full matched strings as they appeared, to remove them accurately
    # The regex match objects themselves would be better for this if we captured their span.
    # For now, let's try replacing based on the reconstructed raw_match.
    # This part is tricky if formatting varies wildly (e.g. "01.01.2025 10:00 - 12:00" vs "01.01.2025 10:00-12:00")
    # The regex `\s*-\s*` handles spaces around hyphen.
    # We need to reconstruct the string that the regex actually matched.
    # Let's refine interval_pattern to capture the whole interval string for easier removal.

    # Re-defining interval_pattern to capture the whole thing for easier removal:
    full_interval_pattern = re.compile(r"(\d{1,2}\.\d{1,2}\.\d{4}\s+\d{1,2}:\d{2}\s*-\s*\d{1,2}:\d{2})")
    actual_matched_interval_strings = full_interval_pattern.findall(line_text)

    for matched_str in actual_matched_interval_strings:
        student_name_part = student_name_part.replace(matched_str, "")

    student_name_part = student_name_part.replace(",", "").strip() # Remove commas and strip whitespace

    if not student_name_part:
         # This could happen if the line ONLY contained intervals (and maybe "biserica")
        return "", parsed_intervals, is_biserica_requested, "Numele studentului lipsește (linia conține doar intervale/biserica)." if parsed_intervals else "Linie invalidă."


    # Sort intervals by date and start time (already parsed)
    parsed_intervals.sort(key=lambda x: (x['date_obj'], x['start_time_obj']))

    return student_name_part, parsed_intervals, is_biserica_requested, None


# Endpoint vechi pentru procesarea textului din modal, înlocuit de pagina dedicată gradat_page_import_weekend_leaves
# @app.route('/gradat/weekend_leaves/process_text', methods=['POST'], endpoint='gradat_process_weekend_leaves_text')
# @login_required
# def process_weekend_leaves_text():
#     # ... (codul vechi aici)
#     pass

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
    # students_managed_by_gradat = Student.query.filter_by(created_by_user_id=current_user.id).all() # Nu mai este necesar aici

    default_start_time_obj = time(15, 0)
    default_end_time_obj = time(19, 0)

    processed_count, error_count, already_exists_count = 0,0,0
    error_details_import_dl = [] # Listă pentru a stoca detalii despre erori

    for line_raw in lines:
        line_for_student_find = line_raw.strip()
        if not line_for_student_find: continue

        # Extrage orele din linie, dacă există, înainte de a trimite la find_student_for_bulk_import
        # parse_leave_line deja face asta și separă numele de oră.
        # Reutilizăm parse_leave_line pentru a extrage numele și orele.

        # `parse_leave_line` returnează: normalized_name_search, grad, parsed_start_time_obj, parsed_end_time_obj
        # normalized_name_search este numele fără grad.
        # grad este gradul extras.
        # Vom reconstrui "Nume Student Grad" pentru find_student_for_bulk_import dacă e posibil,
        # sau vom folosi linia originală dacă `parse_leave_line` nu separă bine.

        temp_name_norm, temp_grad, temp_start_time, temp_end_time = parse_leave_line(line_for_student_find)

        # Construim șirul pentru căutarea studentului. `find_student_for_bulk_import` se așteaptă la "Grad Nume Prenume" sau "Nume Prenume"
        # `parse_leave_line` returnează `temp_name_norm` ca "nume prenume" (sau ce a rămas după extragerea gradului și orei)
        # și `temp_grad` ca gradul.

        student_search_string = ""
        if temp_grad and temp_name_norm: # Avem și grad și nume
            # `temp_name_norm` este deja normalizat (lowercase, unidecode). `find_student_for_bulk_import` face și el normalizare.
            # Pentru a pasa corect, ar trebui să avem numele original.
            # `parse_leave_line` ar trebui să returneze și numele original ne-normalizat.
            # Modificare: Să folosim direct `line_for_student_find` pentru `find_student_for_bulk_import`
            # și să extragem orele separat.

            # Abordare mai simplă: extragem orele întâi, restul e numele + gradul.
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
                    pass # Orele nu sunt valide, vor fi tratate ca parte din nume sau se vor folosi cele default

            found_student, student_error = find_student_for_bulk_import(student_name_grad_part, current_user.id)

            if student_error:
                app.logger.warning(f"Daily Leave Text Import: Student find error for line '{line_raw}'. Error: {student_error}")
                error_details_import_dl.append(f"Linia '{line_raw}': {student_error}")
                error_count += 1
                continue
            # This 'else' block was problematic as find_student_for_bulk_import either returns a student or an error string.
            # If student_error is None, found_student should be valid.
            # The initial check for student_error should be sufficient.
            # else: # Student negăsit sau eroare la parsarea inițială
            #     app.logger.warning(f"Daily Leave Text Import: Could not identify student or invalid format for line '{line_raw}'.")
            #     error_details_import_dl.append(f"Linia '{line_raw}': Nu s-a putut identifica studentul sau format invalid.")
            #     error_count += 1
            #     continue
            if not found_student: # Should be caught by student_error, but as an explicit double check.
                app.logger.error(f"Daily Leave Text Import: found_student is None but student_error was also None for line '{line_raw}'. This indicates a logic flaw in find_student_for_bulk_import or here.")
                error_details_import_dl.append(f"Linia '{line_raw}': Eroare internă la identificarea studentului.")
                error_count += 1
                continue


        # Determine start and end times for the leave
        current_start_time = line_start_time_obj if line_start_time_obj else default_start_time_obj
        current_end_time = line_end_time_obj if line_end_time_obj else default_end_time_obj # Corrected from line_end_time

        # This case might be redundant if default_end_time_obj is always used when line_end_time_obj is None
        # However, if line_start_time_obj is provided but line_end_time_obj is not (e.g. malformed HH:MM- input),
        # it's safer to ensure a valid end time.
        if line_start_time_obj and not line_end_time_obj: # If only start time is given from regex, but end time failed parsing or wasn't there
            current_end_time = default_end_time_obj
            # Flash message might be too noisy if it happens often for default cases. Consider logging instead or only if truly ambiguous.
            # flash(f"Doar ora de început specificată pentru {found_student.nume} în '{line_raw}'. S-a folosit ora de sfârșit implicită ({default_end_time_obj.strftime('%H:%M')}).", "info")


        valid_schedule, validation_message = validate_daily_leave_times(current_start_time, current_end_time, apply_date_obj)
        if not valid_schedule:
            app.logger.warning(f"Daily Leave Text Import: Invalid schedule for student '{found_student.nume}' line '{line_raw}'. Message: {validation_message}")
            # flash(f"Interval orar invalid pentru {found_student.nume} ({validation_message}). Încercare ignorată pentru '{line_raw}'.", "warning")
            error_details_import_dl.append(f"Linia '{line_raw}' ({found_student.nume}): Interval orar invalid - {validation_message}.")
            error_count +=1
            continue

        start_dt_bulk = datetime.combine(apply_date_obj, current_start_time)
        effective_end_date_bulk = apply_date_obj
        if current_end_time < current_start_time : # Spans midnight
            effective_end_date_bulk += timedelta(days=1)
        end_dt_bulk = datetime.combine(effective_end_date_bulk, current_end_time)

        # Conflict checking (existing logic seems fine)
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

        # Check for existing identical leave
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
        form_data_on_get['duminica_biserica'] = weekend_leave.duminica_biserica # Populate church checkbox state
        selected_days_from_db = []
        # Helper to populate form_data_on_get for existing leave days
        day_fields_map = {
            'day1': (weekend_leave.day1_date, weekend_leave.day1_start_time, weekend_leave.day1_end_time, weekend_leave.day1_selected),
            'day2': (weekend_leave.day2_date, weekend_leave.day2_start_time, weekend_leave.day2_end_time, weekend_leave.day2_selected),
            'day3': (weekend_leave.day3_date, weekend_leave.day3_start_time, weekend_leave.day3_end_time, weekend_leave.day3_selected)
        }
        day_names_ro_map = {0: "Luni", 1: "Marti", 2: "Miercuri", 3: "Joi", 4: "Vineri", 5: "Sambata", 6: "Duminica"}

        for _field_prefix, (d_date, s_time, e_time, d_name_selected) in day_fields_map.items():
            if d_date and d_name_selected: # d_name_selected is the actual day name like "Vineri"
                # day_name_template_key = day_names_ro_map.get(d_date.weekday(), "Nespecificat").lower() # This was problematic if d_name_selected is the source of truth
                day_name_template_key = d_name_selected.lower() # Use the stored day name directly
                if day_name_template_key not in selected_days_from_db: # Ensure unique day names for selection
                    selected_days_from_db.append(d_name_selected) # Use original casing for selected_days[] list

                form_data_on_get[f'{day_name_template_key}_start_time'] = s_time.strftime('%H:%M') if s_time else ''
                form_data_on_get[f'{day_name_template_key}_end_time'] = e_time.strftime('%H:%M') if e_time else ''

        form_data_on_get['selected_days[]'] = selected_days_from_db # This will be used by template to check checkboxes
    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    upcoming_fridays_list = get_upcoming_fridays()
    if request.method == 'POST':
        student_id = request.form.get('student_id'); weekend_start_date_str = request.form.get('weekend_start_date'); selected_days = request.form.getlist('selected_days[]')
        reason = request.form.get('reason', '').strip()
        current_form_data_post = request.form # Used to repopulate form on error
        if not student_id or not weekend_start_date_str:
            flash('Studentul și data de început a weekendului (Vineri) sunt obligatorii.', 'warning')
            return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
        if not selected_days or len(selected_days) == 0 or len(selected_days) > 3: # Allow 1 to 3 days
            flash('Trebuie să selectați între 1 și 3 zile din weekend.', 'warning')
            return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
        try:
            friday_date_obj = datetime.strptime(weekend_start_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Format dată weekend invalid.', 'danger')
            return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)

        day_data = [] # To store processed day information before saving
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

        # Clear previous day data before setting new, especially for edits
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


        # Assign processed day_data to the model fields
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
        if len(day_data) >= 3: # Assign third day if present
            target_leave.day3_selected = day_data[2]['name']
            target_leave.day3_date = day_data[2]['date']
            target_leave.day3_start_time = day_data[2]['start']
            target_leave.day3_end_time = day_data[2]['end']

        if not weekend_leave: # If it's a new leave, add to session
            db.session.add(target_leave)

        try:
            db.session.commit()
            if len(selected_days) == 3:
                 flash(flash_msg + " Ați selectat 3 zile pentru învoire.", 'success') # Add warning if 3 days selected
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

    leave_list_text = request.form.get('weekend_leave_list_text', '').strip() # Assuming this will be the form field name
    if not leave_list_text:
        flash('Lista de învoiri este goală.', 'warning')
        return redirect(url_for('list_weekend_leaves'))

    lines = leave_list_text.strip().splitlines()
    processed_count = 0
    error_count = 0
    error_details_list = [] # More structured than just a list of strings

    day_names_map_ro_to_en = {"vineri": "Friday", "sambata": "Saturday", "duminica": "Sunday"} # For model's dayX_selected
    day_name_to_weekday = {"vineri": 4, "sambata": 5, "duminica": 6} # Monday is 0, Sunday is 6

    for line_raw in lines:
        line_content = line_raw.strip()
        if not line_content:
            continue

        student_name_str, parsed_intervals, is_biserica_req, error_msg = parse_weekend_leave_line(line_content)

        if error_msg and student_name_str is None and not parsed_intervals : # Skip empty line signal
            continue
        if error_msg:
            error_details_list.append({"line": line_content, "error": error_msg})
            error_count += 1
            continue

        if not parsed_intervals: # Should have been caught by error_msg, but as a safeguard
            error_details_list.append({"line": line_content, "error": "Niciun interval valid de procesat."})
            error_count +=1
            continue

        student_obj, student_error = find_student_for_bulk_import(student_name_str, current_user.id)
        if student_error:
            error_details_list.append({"line": line_content, "error": f"Student '{student_name_str}': {student_error}"})
            error_count += 1
            continue

        # --- Logic to determine weekend_start_date and map intervals to day1/2/3 ---
        if not parsed_intervals: # Should not happen if error_msg was None
            error_details_list.append({"line": line_content, "student": student_obj.nume, "error": "Eroare internă: Intervale goale după parsare reușită."})
            error_count += 1
            continue

        # Determine the primary weekend: find the Friday of the week of the first interval's date.
        first_interval_date = parsed_intervals[0]['date_obj']
        days_to_subtract_for_friday = (first_interval_date.weekday() - 4) % 7
        # (weekday - 4) gives offset from Friday. If it's negative, add 7.
        # E.g. Mon(0): (0-4)%7 = -4%7 = 3 -> Mon - 3 days is Fri of PREVIOUS week. This is not what we want.
        # We want Friday of the week *containing* the first_interval_date.
        # If first_interval_date is Mon, its Friday is +4 days. If Sun, its Friday is -2 days.
        weekend_start_date_obj = first_interval_date - timedelta(days=first_interval_date.weekday()) + timedelta(days=4)


        # Validate that all intervals fall within this determined weekend (Fri, Sat, Sun)
        # and map them to day1_ (Friday), day2_ (Saturday), day3_ (Sunday)

        current_weekend_leave_data = { # Temp storage for this student's leave
            "day1_date": None, "day1_start_time": None, "day1_end_time": None, "day1_selected": None,
            "day2_date": None, "day2_start_time": None, "day2_end_time": None, "day2_selected": None,
            "day3_date": None, "day3_start_time": None, "day3_end_time": None, "day3_selected": None,
            "intervals_for_conflict_check": []
        }

        distinct_days_processed = set()

        for interval in parsed_intervals:
            interval_date = interval['date_obj']

            # Check if interval_date is Fri, Sat, or Sun of the determined weekend_start_date_obj
            delta_days = (interval_date - weekend_start_date_obj).days
            day_slot_key = None # Will be 'day1', 'day2', or 'day3'
            day_name_ro = None

            if delta_days == 0 and interval_date.weekday() == 4: # Friday
                day_slot_key = "day1"
                day_name_ro = "Vineri"
            elif delta_days == 1 and interval_date.weekday() == 5: # Saturday
                day_slot_key = "day2"
                day_name_ro = "Sambata"
            elif delta_days == 2 and interval_date.weekday() == 6: # Sunday
                day_slot_key = "day3"
                day_name_ro = "Duminica"
            else:
                error_details_list.append({"line": line_content, "student": student_obj.nume, "error": f"Data {interval_date.strftime('%d.%m.%Y')} nu corespunde weekendului definit de prima dată ({weekend_start_date_obj.strftime('%d.%m.%Y')})."})
                error_count += 1; break # Break from this student's intervals

            if day_slot_key in distinct_days_processed : # Already have an interval for this day slot
                 error_details_list.append({"line": line_content, "student": student_obj.nume, "error": f"Intervale multiple specificate pentru aceeași zi ({day_name_ro}). Doar primul va fi considerat."})
                 # error_count +=1 # Optionally count this as an error or just a warning
                 continue # Skip this additional interval for the same day

            distinct_days_processed.add(day_slot_key)

            current_weekend_leave_data[f"{day_slot_key}_date"] = interval_date
            current_weekend_leave_data[f"{day_slot_key}_start_time"] = interval['start_time_obj']
            current_weekend_leave_data[f"{day_slot_key}_end_time"] = interval['end_time_obj']
            current_weekend_leave_data[f"{day_slot_key}_selected"] = day_name_ro # Store "Vineri", "Sambata", "Duminica"

            # For conflict checking:
            start_dt = datetime.combine(interval_date, interval['start_time_obj'])
            effective_end_date = interval_date
            if interval['end_time_obj'] < interval['start_time_obj']: effective_end_date += timedelta(days=1)
            end_dt = datetime.combine(effective_end_date, interval['end_time_obj'])
            current_weekend_leave_data["intervals_for_conflict_check"].append({'start': start_dt, 'end': end_dt, 'day_name': day_name_ro})

        if error_count > 0 and error_details_list[-1]["line"] == line_content: # If error occurred for this student, skip to next line
            continue

        if not distinct_days_processed:
            error_details_list.append({"line": line_content, "student": student_obj.nume, "error": "Niciun interval valid mapat la zilele weekendului."})
            error_count += 1; continue

        # --- Conflict Checking ---
        conflict_found_for_student = False
        for interval_to_check in current_weekend_leave_data["intervals_for_conflict_check"]:
            conflict = check_leave_conflict(student_obj.id, interval_to_check['start'], interval_to_check['end'], leave_type='weekend_leave')
            if conflict:
                error_details_list.append({"line": line_content, "student": student_obj.nume, "error": f"Conflict pentru {interval_to_check['day_name']}: {conflict}."})
                error_count += 1; conflict_found_for_student = True; break
        if conflict_found_for_student: continue

        # --- Create WeekendLeave object ---
        new_wl = WeekendLeave(
            student_id=student_obj.id,
            weekend_start_date=weekend_start_date_obj,
            day1_selected=current_weekend_leave_data['day1_selected'], day1_date=current_weekend_leave_data['day1_date'],
            day1_start_time=current_weekend_leave_data['day1_start_time'], day1_end_time=current_weekend_leave_data['day1_end_time'],
            day2_selected=current_weekend_leave_data['day2_selected'], day2_date=current_weekend_leave_data['day2_date'],
            day2_start_time=current_weekend_leave_data['day2_start_time'], day2_end_time=current_weekend_leave_data['day2_end_time'],
            day3_selected=current_weekend_leave_data['day3_selected'], day3_date=current_weekend_leave_data['day3_date'],
            day3_start_time=current_weekend_leave_data['day3_start_time'], day3_end_time=current_weekend_leave_data['day3_end_time'],
            duminica_biserica=(is_biserica_req and current_weekend_leave_data['day3_selected'] == "Duminica"), # Only if Sunday is actually selected
            status='Aprobată',
            created_by_user_id=current_user.id,
            reason=f"Procesare text: {line_content[:100]}" # Truncate reason if line is too long
        )
        db.session.add(new_wl)
        processed_count += 1

    # --- Commit and Flash Messages ---
    try:
        if processed_count > 0: # Only commit if there are successful items
            db.session.commit()
            flash(f'{processed_count} învoiri de weekend procesate și adăugate cu succes.', 'success')
        elif error_count == 0 and processed_count == 0 : # No lines or only empty lines
             flash('Nu au fost furnizate date de procesat.', 'info')


        if error_count > 0:
            flash(f'{error_count} linii nu au putut fi procesate sau au generat erori.', 'danger')
            # Construct detailed error message for flash
            error_flash_message = "Detalii erori:<br>"
            for err_detail in error_details_list[:5]: # Show first 5 errors
                error_flash_message += f"- Linia: '{err_detail['line'][:60]}...' Student: {err_detail.get('student','N/A')} Eroare: {err_detail['error']}<br>"
            if len(error_details_list) > 5:
                error_flash_message += f"... și încă {len(error_details_list) - 5} erori."
            flash(error_flash_message, 'warning')

        # Log the bulk operation attempt
        log_action("BULK_IMPORT_WEEKEND_LEAVES_COMPLETED",
                   description=f"User {current_user.username} ran bulk weekend leave import. Added: {processed_count}, Errors: {error_count}. Line count: {len(lines)}",
                   details_after_dict={"added_count": processed_count, "error_count": error_count, "total_lines_input": len(lines), "first_few_error_details": error_details_list[:3]})
        db.session.commit() # Commit the log

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

    # Fetch active and upcoming weekend leaves
    leaves_to_export = WeekendLeave.query.options(joinedload(WeekendLeave.student)).filter(
        WeekendLeave.student_id.in_(student_ids),
        WeekendLeave.status == 'Aprobată'
        # Further filter by is_overall_active_or_upcoming if only current/future are needed
        # For a general report, all approved might be fine, or sort them.
        # Let's fetch all approved and sort them, then decide if we only show active/upcoming ones.
    ).join(Student).order_by(Student.nume, Student.prenume, WeekendLeave.weekend_start_date).all()

    # Filter for only active or upcoming ones for the report
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

    table = document.add_table(rows=1, cols=6) # NrCrt, Grad, Nume, Weekend (Vineri), Intervale, Motiv
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

    # Approx widths: NrCrt(0.5), Grad(0.8), Nume(2.0), Vineri(1.0), Intervale(2.5), Motiv(1.5)
    widths = {0: 0.5, 1: 0.7, 2: 1.8, 3: 1.0, 4: 2.8, 5: 1.5} # Inches
    for col_idx, width_val in widths.items():
        for row in table.rows:
            if col_idx < len(row.cells): # Check if cell exists
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

    now = get_localized_now() # Folosim ora localizată

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

    default_times_for_js = { # Acestea sunt stringuri, nu necesită localizare directă aici
        "GSS": ("07:00", "07:00"), "SVM": ("05:50", "20:00"),
        "Intervenție": ("20:00", "00:00"),
        "Planton 1": ("22:00", "00:00"), "Planton 2": ("00:00", "02:00"),
        "Planton 3": ("02:00", "04:00"), "Altul": ("", "")
    }
    today_iso_str = get_localized_now().date().isoformat() # Pentru valoarea default a datei

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

        # Datele și orele sunt deja locale din formular, le combinăm
        start_dt_obj = datetime.combine(service_date_obj, start_time_obj) # Naive, local
        effective_end_date = service_date_obj
        if end_time_obj < start_time_obj:
            effective_end_date += timedelta(days=1)
        elif service_type == "GSS" and end_time_obj == start_time_obj: # GSS special case for 24h
            effective_end_date += timedelta(days=1)
        end_dt_obj = datetime.combine(effective_end_date, end_time_obj)

        if end_dt_obj <= start_dt_obj: # This check should now be generally correct
            flash('Intervalul orar al serviciului este invalid (sfârșitul trebuie să fie după început).', 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=today_iso_str, form_data=current_form_data)

        stud = Student.query.filter_by(id=student_id, created_by_user_id=current_user.id).first()
        if not stud:
            flash('Student selectat invalid sau nu vă aparține.', 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=today_iso_str, form_data=current_form_data)

        # check_service_conflict_for_student se așteaptă la datetime-uri naive locale
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
    elif service_assignment: # GET pentru editare
        data_to_populate_form_with = form_data_for_template

    return render_template('assign_service.html',
                           form_title=form_title,
                           service_assignment=service_assignment,
                           students=students,
                           service_types=SERVICE_TYPES,
                           default_times=default_times_for_js,
                           today_str=today_iso_str, # Folosim variabila actualizată
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
        return redirect(url_for('list_services')) # Or gradat_dashboard

    # Default times for JS, same as single assign
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

        services_data = []
        service_indices = sorted(list(set(key.split('_')[1] for key in request.form if key.startswith('service_type_'))))

        added_count = 0
        error_count = 0
        error_messages = []

        for index in service_indices:
            service_type = request.form.get(f'service_type_{index}')
            service_date_str = request.form.get(f'service_date_{index}')
            start_time_str = request.form.get(f'start_time_{index}')
            end_time_str = request.form.get(f'end_time_{index}')
            participates_str = request.form.get(f'participates_{index}') # Value will be 'on' or None
            notes = request.form.get(f'notes_{index}', '').strip()

            # Skip if essential fields are missing for this specific service entry
            if not all([service_type, service_date_str, start_time_str, end_time_str]):
                # If any field is present, it's a partial entry, consider it an error or just skip.
                # For now, we'll skip if any of these critical ones are missing.
                # But if user intended to fill it, they might want an error.
                # Let's assume if type is chosen, the rest were intended.
                if service_type: # If a type was chosen, assume user intended to fill this row
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
            elif service_type == "GSS" and end_time_obj == start_time_obj: # GSS special case for 24h
                effective_end_date += timedelta(days=1)
            end_dt_obj = datetime.combine(effective_end_date, end_time_obj)

            if end_dt_obj <= start_dt_obj:
                error_messages.append(f"Serviciul #{int(index)+1} ({service_type}): Interval orar invalid.")
                error_count += 1
                continue

            participates_bool = (participates_str == 'on')

            conflict_msg = check_service_conflict_for_student(stud.id, start_dt_obj, end_dt_obj, service_type, None) # None for assignment_id as it's new
            if conflict_msg:
                error_messages.append(f"Serviciul #{int(index)+1} ({service_type} pe {service_date_str}): Conflict - studentul are deja {conflict_msg}.")
                error_count += 1
                continue

            # If all checks pass, prepare to add
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
            if added_count > 0: # If some were added despite errors with others
                 try:
                    db.session.commit()
                    flash(f'{added_count} servicii au fost adăugate cu succes pentru {stud.nume} {stud.prenume}.', 'success')
                 except Exception as e:
                    db.session.rollback()
                    flash(f'Eroare la salvarea unor servicii: {str(e)}', 'danger')
                    # Log this commit failure
            else: # No services added, only errors
                db.session.rollback() # Ensure no partial transaction
            # Redirect back to the form, ideally repopulating student_id
            return redirect(url_for('assign_multiple_services', student_id_selected=stud.id))


        if added_count > 0:
            try:
                db.session.commit()
                flash(f'{added_count} servicii au fost adăugate cu succes pentru {stud.nume} {stud.prenume}!', 'success')
                return redirect(url_for('list_services'))
            except Exception as e:
                db.session.rollback()
                flash(f'Eroare la salvarea serviciilor: {str(e)}', 'danger')
                # Redirect back to form, repopulating student_id
                return redirect(url_for('assign_multiple_services', student_id_selected=stud.id))
        else: # No services added, no errors reported above (e.g., no service rows filled)
            flash('Niciun serviciu valid nu a fost introdus pentru a fi adăugat.', 'info')
            return redirect(url_for('assign_multiple_services', student_id_selected=stud.id if stud else None))

    # GET request
    student_id_selected_on_get = request.args.get('student_id_selected', type=int)
    today_iso_str_get = get_localized_now().date().isoformat() # Pentru valoarea default a datei în formular
    return render_template('assign_multiple_services.html',
                           students=students,
                           service_types=SERVICE_TYPES,
                           default_times_json=json.dumps(default_times_for_js), # Pass as JSON for JS
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
        # Poate afișa un template gol sau un mesaj specific
        return render_template('text_report_display.html', report_title=f"Raport Compania {company_id_str}", report_content="Niciun student în unitate.", report_datetime_str=report_datetime_str)

    company_presence_data = _calculate_presence_data(students_in_company, roll_call_datetime)

    report_lines = []
    report_lines.append(f"RAPORT OPERATIV - COMPANIA {company_id_str}")
    report_lines.append(f"Data și ora raportului: {report_datetime_str}")
    report_lines.append("-" * 30)
    report_lines.append(f"Efectiv control (Ec): {company_presence_data['efectiv_control']}")
    report_lines.append(f"Efectiv prezent (Ep): {company_presence_data['efectiv_prezent_total']}")
    report_lines.append(f"  - În formație: {company_presence_data['in_formation_count']}")
    report_lines.append(f"  - La Servicii: {company_presence_data['on_duty_count']}") # Changed label
    report_lines.append(f"  - Gradat Pluton (prezent): {company_presence_data['platoon_graded_duty_count']}")
    report_lines.append(f"Efectiv absent (Ea): {company_presence_data['efectiv_absent_total']}")
    report_lines.append("-" * 30)

    if company_presence_data['in_formation_students_details']:
        report_lines.append("\nPREZENȚI ÎN FORMAȚIE:")
        for detail in company_presence_data['in_formation_students_details']: report_lines.append(f"  - {detail}")

    if company_presence_data['on_duty_students_details']:
        report_lines.append("\nLA SERVICII:") # Changed label
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
    report_lines.append(f"    - La Servicii: {total_battalion_presence['on_duty_count']}") # Changed label
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
        report_lines.append(f"    La Servicii: {company_presence_data['on_duty_count']}") # Changed label
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

# --- Admin Action Log Viewer ---
@app.route('/admin/action_logs', endpoint='admin_action_logs')
@login_required
def admin_action_logs():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    page = request.args.get('page', 1, type=int)
    per_page = 20 # Or a configurable value

    # Basic query
    logs_query = ActionLog.query.options(joinedload(ActionLog.user)).order_by(ActionLog.timestamp.desc())

    # TODO: Add filtering based on request.args
    # filter_user_id = request.args.get('user_id')
    # filter_action_type = request.args.get('action_type')
    # filter_target_model = request.args.get('target_model')
    # filter_date_from = request.args.get('date_from')
    # filter_date_to = request.args.get('date_to')

    # if filter_user_id:
    #     logs_query = logs_query.filter(ActionLog.user_id == filter_user_id)
    # if filter_action_type:
    #     logs_query = logs_query.filter(ActionLog.action_type.ilike(f"%{filter_action_type}%"))
    # # ... etc. for other filters ...

    logs_pagination = logs_query.paginate(page=page, per_page=per_page, error_out=False)

    # For filter dropdowns (optional, can be added later)
    # users_for_filter = User.query.order_by(User.username).all()
    # action_types_for_filter = db.session.query(ActionLog.action_type).distinct().order_by(ActionLog.action_type).all()
    # target_models_for_filter = db.session.query(ActionLog.target_model).distinct().order_by(ActionLog.target_model).all()

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

        if not new_password or len(new_password) < 6: # Exemplu de politică simplă de parolă
            flash('Parola nouă trebuie să aibă minim 6 caractere.', 'warning')
            return redirect(url_for('admin_change_self_password'))

        if new_password != confirm_new_password:
            flash('Parolele noi nu se potrivesc.', 'warning')
            return redirect(url_for('admin_change_self_password'))

        details_before = {"user_id": current_user.id, "username": current_user.username, "action": "Attempt change own password"}
        current_user.set_password(new_password)
        try:
            log_action("ADMIN_CHANGE_OWN_PASSWORD_SUCCESS", target_model_name="User", target_id=current_user.id,
                       details_before_dict=details_before, # details_after nu arată parola
                       description=f"Admin {current_user.username} changed their own password successfully.")
            db.session.commit()
            flash('Parola a fost schimbată cu succes!', 'success')
            # Opțional, se poate face logout adminului după schimbarea parolei pentru a forța re-autentificare
            # logout_user()
            # flash('Parola a fost schimbată cu succes! Te rugăm să te autentifici din nou.', 'success')
            # return redirect(url_for('admin_login'))
            return redirect(url_for('admin_dashboard_route'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la schimbarea parolei: {str(e)}', 'danger')
            log_action("ADMIN_CHANGE_OWN_PASSWORD_FAIL", target_model_name="User", target_id=current_user.id,
                       details_before_dict=details_before,
                       description=f"Admin {current_user.username} failed to change their own password. Error: {str(e)}")
            db.session.commit() # Commit log-ul de eroare
            return redirect(url_for('admin_change_self_password'))

    return render_template('admin_change_password.html')

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

        target_user.set_personal_code(new_code) # Aceasta setează hash-ul și is_first_login = False

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
            # Log failure
            log_action("ADMIN_SET_USER_PERSONAL_CODE_FAIL", target_model_name="User", target_id=target_user.id,
                       details_before_dict=details_before, # Log state before attempted change
                       description=f"Admin {current_user.username} failed to set new personal code for {target_user.username}. Error: {str(e)}")
            db.session.commit()
            return render_template('admin_set_user_personal_code.html', target_user=target_user)

    return render_template('admin_set_user_personal_code.html', target_user=target_user)

# --- Admin UpdateTopic (Announcements) Management ---
AVAILABLE_STATUS_COLORS = ['primary', 'secondary', 'success', 'danger', 'warning', 'info', 'light', 'dark']

@app.route('/admin/updates', methods=['GET'], endpoint='admin_list_updates')
@login_required
def admin_list_updates():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    page = request.args.get('page', 1, type=int)
    per_page = 15 # Or your preferred number
    updates_pagination = UpdateTopic.query.join(User, UpdateTopic.user_id == User.id)\
        .options(joinedload(UpdateTopic.author))\
        .order_by(UpdateTopic.is_pinned.desc(), UpdateTopic.updated_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)

    return render_template('admin_list_updates.html',
                           updates_pagination=updates_pagination,
                           title="Management Anunțuri")

@app.route('/admin/updates/create', methods=['GET', 'POST'], endpoint='admin_create_update')
@login_required
def admin_create_update():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_list_updates'))

    form_data_to_pass = request.form if request.method == 'POST' else {}

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        status_color = request.form.get('status_color')
        is_pinned = 'is_pinned' in request.form
        is_visible = 'is_visible' in request.form

        if not title or not content:
            flash('Titlul și conținutul sunt obligatorii.', 'warning')
            return render_template('admin_edit_update_topic.html',
                                   title="Creează Anunț Nou",
                                   topic=None, # No topic object for create
                                   available_colors=AVAILABLE_STATUS_COLORS,
                                   form_data=request.form) # Repopulate with current form data

        if status_color == 'None' or not status_color:
            status_color = None # Store as None if "Niciuna" selected

        new_topic = UpdateTopic(
            title=title,
            content=content,
            user_id=current_user.id,
            status_color=status_color,
            is_pinned=is_pinned,
            is_visible=is_visible
        )
        db.session.add(new_topic)
        try:
            db.session.commit()
            flash(f'Anunțul "{title}" a fost creat cu succes.', 'success')
            return redirect(url_for('admin_list_updates'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la crearea anunțului: {str(e)}', 'danger')
            # form_data already contains current form input

    return render_template('admin_edit_update_topic.html',
                           title="Creează Anunț Nou",
                           topic=None, # Explicitly pass None for topic
                           available_colors=AVAILABLE_STATUS_COLORS,
                           form_data=form_data_to_pass) # Empty for GET, or form data for failed POST

@app.route('/admin/updates/edit/<int:topic_id>', methods=['GET', 'POST'], endpoint='admin_edit_update')
@login_required
def admin_edit_update(topic_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_list_updates'))

    topic_to_edit = db.session.get(UpdateTopic, topic_id)
    if not topic_to_edit:
        flash('Anunțul nu a fost găsit.', 'danger')
        return redirect(url_for('admin_list_updates'))

    form_data_on_get = { # Populate with existing topic data for GET
            'title': topic_to_edit.title,
            'content': topic_to_edit.content,
            'status_color': topic_to_edit.status_color or 'None',
            'is_pinned': topic_to_edit.is_pinned,
            'is_visible': topic_to_edit.is_visible
        } if request.method == 'GET' else request.form # Use request.form for POST repopulation

    if request.method == 'POST':
        topic_to_edit.title = request.form.get('title', '').strip()
        topic_to_edit.content = request.form.get('content', '').strip()
        status_color_form = request.form.get('status_color')
        topic_to_edit.is_pinned = 'is_pinned' in request.form
        topic_to_edit.is_visible = 'is_visible' in request.form

        if not topic_to_edit.title or not topic_to_edit.content:
            flash('Titlul și conținutul sunt obligatorii.', 'warning')
            # Pass current (failed) form data back to template
            return render_template('admin_edit_update_topic.html',
                                   title=f"Editare Anunț: {topic_to_edit.title[:30]}...",
                                   topic=topic_to_edit,
                                   available_colors=AVAILABLE_STATUS_COLORS,
                                   form_data=request.form)

        topic_to_edit.status_color = None if status_color_form == 'None' or not status_color_form else status_color_form
        topic_to_edit.updated_at = datetime.utcnow() # Manually update 'updated_at'

        try:
            db.session.commit()
            flash(f'Anunțul "{topic_to_edit.title}" a fost actualizat.', 'success')
            return redirect(url_for('admin_list_updates'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la actualizarea anunțului: {str(e)}', 'danger')
            # Pass current (failed) form data back

    # For GET, or for POST if validation failed and we re-render
    return render_template('admin_edit_update_topic.html',
                           title=f"Editare Anunț: {topic_to_edit.title[:30]}...",
                           topic=topic_to_edit,
                           available_colors=AVAILABLE_STATUS_COLORS,
                           form_data=form_data_on_get)


@app.route('/admin/updates/delete/<int:topic_id>', methods=['POST'], endpoint='admin_delete_update')
@login_required
def admin_delete_update(topic_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_list_updates'))
    topic = db.session.get(UpdateTopic, topic_id)
    if topic:
        try:
            db.session.delete(topic)
            db.session.commit()
            flash(f'Anunțul "{topic.title}" a fost șters.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la ștergerea anunțului: {str(e)}', 'danger')
    else:
        flash('Anunțul nu a fost găsit.', 'warning')
    return redirect(url_for('admin_list_updates'))

@app.route('/admin/updates/toggle_pin/<int:topic_id>', methods=['POST'], endpoint='admin_toggle_pin_update')
@login_required
def admin_toggle_pin_update(topic_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_list_updates'))
    topic = db.session.get(UpdateTopic, topic_id)
    if topic:
        topic.is_pinned = not topic.is_pinned
        topic.updated_at = datetime.utcnow()
        try:
            db.session.commit()
            flash(f'Statusul "Fixat" pentru anunțul "{topic.title}" a fost schimbat.', 'info')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la schimbarea statusului "Fixat": {str(e)}', 'danger')
    else:
        flash('Anunțul nu a fost găsit.', 'warning')
    return redirect(url_for('admin_list_updates'))

@app.route('/admin/updates/toggle_visibility/<int:topic_id>', methods=['POST'], endpoint='admin_toggle_visibility_update')
@login_required
def admin_toggle_visibility_update(topic_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('admin_list_updates'))
    topic = db.session.get(UpdateTopic, topic_id)
    if topic:
        topic.is_visible = not topic.is_visible
        topic.updated_at = datetime.utcnow() # Consider this an update
        try:
            db.session.commit()
            flash(f'Vizibilitatea pentru anunțul "{topic.title}" a fost schimbată.', 'info')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la schimbarea vizibilității: {str(e)}', 'danger')
    else:
        flash('Anunțul nu a fost găsit.', 'warning')
    return redirect(url_for('admin_list_updates'))

@app.route('/gradat/weekend_leave/bulk_add', methods=['GET', 'POST'], endpoint='gradat_bulk_add_weekend_leave')
@login_required
def gradat_bulk_add_weekend_leave():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.pluton, Student.nume).all()
    upcoming_fridays_list = get_upcoming_fridays() # Funcție existentă

    if request.method == 'POST':
        student_ids_selected = request.form.getlist('student_ids')
        weekend_start_date_str = request.form.get('weekend_start_date')
        selected_days_names = request.form.getlist('selected_days') # Numele zilelor: 'Vineri', 'Sambata', 'Duminica'
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
            if friday_date_obj.weekday() != 4: # Vineri
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

            # Validare interval (similar cu formularul individual)
            current_interval_start_dt = datetime.combine(actual_date_for_day, start_time_obj)
            effective_end_date_for_interval = actual_date_for_day
            if end_time_obj < start_time_obj:  # Trece în ziua următoare
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

        day_inputs_from_form.sort(key=lambda x: x['date']) # Sortează după dată

        added_count = 0
        skipped_due_to_conflict_count = 0
        error_details_conflict = []

        for student_id_str in student_ids_selected:
            student_id = int(student_id_str)
            # Verificare conflict pentru acest student cu intervalele selectate
            conflict_for_this_student = False
            for day_data_input in day_inputs_from_form:
                start_dt_check = datetime.combine(day_data_input['date'], day_data_input['start_time'])
                end_dt_check = datetime.combine(day_data_input['date'], day_data_input['end_time'])
                if day_data_input['end_time'] < day_data_input['start_time']: # trece in ziua urmatoare
                    end_dt_check += timedelta(days=1)

                # Simplificare: check_leave_conflict verifică și servicii. Pentru bulk, putem fi mai permisivi sau loga conflictele
                # Aici vom face o verificare de bază, dar ideal ar fi o strategie mai complexă.
                # Momentan, vom sări peste student dacă există *orice* conflict pe *oricare* din zilele selectate.
                conflict_reason = check_leave_conflict(student_id, start_dt_check, end_dt_check, leave_type='weekend_leave', existing_leave_id=None)
                if conflict_reason:
                    student_obj = db.session.get(Student, student_id)
                    error_details_conflict.append(f"Studentul {student_obj.nume} {student_obj.prenume}: conflict pe {day_data_input['name']} ({conflict_reason}). Învoirea nu a fost adăugată.")
                    conflict_for_this_student = True
                    break

            if conflict_for_this_student:
                skipped_due_to_conflict_count += 1
                continue

            # Creează învoirea
            new_leave = WeekendLeave(
                student_id=student_id,
                weekend_start_date=friday_date_obj,
                reason=reason_common,
                status='Aprobată',
                created_by_user_id=current_user.id,
                duminica_biserica=False # Standard, nu se setează din bulk add
            )

            # Atribuie zilele și orele
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
                    flash(err_detail, 'info') # Afișează fiecare conflict
            if added_count == 0 and skipped_due_to_conflict_count == 0 and len(student_ids_selected) > 0:
                 flash('Nicio învoire nu a fost adăugată. Verificați selecțiile și încercați din nou.', 'info')

            # Logare acțiune bulk
            log_action("BULK_ADD_WEEKEND_LEAVE",
                       description=f"User {current_user.username} attempted bulk weekend leave. Added: {added_count}, Skipped (conflict): {skipped_due_to_conflict_count} for weekend starting {friday_date_obj.isoformat()}.",
                       details_after_dict={"students_selected_count": len(student_ids_selected), "days_selected": selected_days_names, "conflicts_details": error_details_conflict[:5]}) # Log first 5 conflicts
            db.session.commit() # Commit log-ul separat

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
            # Datetime-urile din form sunt deja în ora locală. Le vom stoca ca naive.
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

            # Verificare conflict (folosind datetime-uri naive locale)
            # check_leave_conflict se așteaptă la datetime-uri naive
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
                status='Aprobată', # Implicit aprobată la adăugare bulk
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


# --- Istoric Învoiri Gradat ---
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

    # Parsare filtre din request
    perioada = request.args.get('perioada', 'ultimele_7_zile') # Default la ultimele 7 zile
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
        # end_date remains today_date
    elif perioada == 'ultimele_7_zile':
        start_date = today_date - timedelta(days=6)
        # end_date remains today_date
    elif perioada == 'luna_curenta':
        start_date = today_date.replace(day=1)
        # end_date remains today_date (or could be end of month)
        # For simplicity, filtering up to 'today' within the current month is fine.
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
    else: # Default la ultimele 7 zile dacă perioada e invalidă
        perioada = 'ultimele_7_zile'
        start_date = today_date - timedelta(days=6)
        end_date = today_date

    leaves_history = []

    # Define filter_start_dt_naive and filter_end_dt_naive for date range filtering
    # These represent the full day for comparison with datetime fields
    filter_start_dt_for_overlap = datetime.combine(start_date, time.min) if start_date else None
    filter_end_dt_for_overlap = datetime.combine(end_date, time.max) if end_date else None


    # Procesare Daily Leaves
    daily_leaves_query = DailyLeave.query.options(joinedload(DailyLeave.student)).filter(DailyLeave.student_id.in_(student_ids))
    if start_date and end_date :
        daily_leaves_query = daily_leaves_query.filter(DailyLeave.leave_date >= start_date, DailyLeave.leave_date <= end_date)

    for dl in daily_leaves_query.order_by(DailyLeave.leave_date.desc(), DailyLeave.start_time.desc()).all():
        leaves_history.append({
            "student_name": f"{dl.student.grad_militar} {dl.student.nume} {dl.student.prenume}",
            "tip": "Zilnică",
            "data_start_obj": dl.start_datetime, # Store actual datetime for sorting
            "data_start": dl.leave_date,
            "ora_start": dl.start_time,
            "ora_sfarsit": dl.end_time,
            "detalii": f"{dl.leave_type_display}",
            "motiv": dl.reason or "-",
            "status": dl.status
        })

    # Procesare Weekend Leaves
    weekend_leaves_query = WeekendLeave.query.options(joinedload(WeekendLeave.student)).filter(WeekendLeave.student_id.in_(student_ids))
    all_wl_gradat = weekend_leaves_query.order_by(WeekendLeave.weekend_start_date.desc()).all()

    for wl in all_wl_gradat:
        relevant_for_period = False
        first_interval_start_for_sort = None
        intervals_display_list = []

        for interval_idx, interval in enumerate(wl.get_intervals()):
            interval_start_naive = interval['start'].astimezone(EUROPE_BUCHAREST).replace(tzinfo=None)
            interval_end_naive = interval['end'].astimezone(EUROPE_BUCHAREST).replace(tzinfo=None)

            if interval_idx == 0: # For sorting, use the start of the first interval
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
                "data_start_obj": first_interval_start_for_sort if first_interval_start_for_sort else datetime.combine(wl.weekend_start_date, time.min), # Fallback for sorting
                "data_start": wl.weekend_start_date,
                "ora_start": None,
                "ora_sfarsit": None,
                "detalii": "; ".join(intervals_display_list) + (f", Biserica Duminică" if wl.duminica_biserica and any(d['day_name']=='Duminica' for d in wl.get_intervals()) else ""),
                "motiv": wl.reason or "-",
                "status": wl.status
            })

    # Procesare Permisii
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
            "data_start_obj": p.start_datetime, # Store actual datetime for sorting
            "data_start": p.start_datetime.date(),
            "ora_start": p.start_datetime.time(),
            "ora_sfarsit": p.end_datetime.time(),
            "detalii": p.destination or "N/A",
            "motiv": p.reason or "-",
            "status": p.status
        })

    # Sortare finală a listei combinate după data_start_obj (descendent)
    leaves_history.sort(key=lambda x: x['data_start_obj'], reverse=True)

    # Paginare manuală simplă (dacă se dorește) sau se poate folosi paginate() pe query-uri separate și apoi combina
    # Pentru simplitate, momentan fără paginare complexă pe lista combinată.

    return render_template('invoiri_istoric.html',
                           leaves_history=leaves_history,
                           title="Istoric Învoiri Pluton",
                           form_data=request.args, # Pentru a repopula filtrele
                           selected_period=perioada,
                           selected_start_custom=data_start_custom_str,
                           selected_end_custom=data_sfarsit_custom_str
                           )


# --- Admin Text Export Routes ---
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
    # Format: Grad Nume Prenume Gen Pluton Companie Batalion
    # Example: M.m.IV Renț Francisc M 1 1 1
    for s in students:
        line = f"{s.grad_militar} {s.nume} {s.prenume} {s.gender} {s.pluton} {s.companie} {s.batalion}"
        output_lines.append(line)

    text_content = "\n".join(output_lines)

    # Create a BytesIO object to hold the text data
    text_file = io.BytesIO()
    text_file.write(text_content.encode('utf-8'))
    text_file.seek(0) # Reset stream position

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
    # Format based on bulk import for permissions:
    # Line 1: Student Name (Grad Nume Prenume)
    # Line 2: Datetime interval (DD.MM.YYYY HH:MM - DD.MM.YYYY HH:MM or DD.MM.YYYY HH:MM - HH:MM)
    # Line 3: Destination
    # Line 4: Transport Mode (optional)
    # Line 5: Reason/Car Plate (optional)
    # --- Empty line separator ---

    for p in permissions:
        student_name_line = f"{p.student.grad_militar} {p.student.nume} {p.student.prenume}"

        # Formatare datetime pentru export: DD.MM.YYYY HH:MM - [DD.MM.YYYY ]HH:MM
        # Datetime-urile sunt stocate ca naive, reprezentând ora locală.
        start_date_str_export = p.start_datetime.strftime('%d.%m.%Y')
        start_time_str_export = p.start_datetime.strftime('%H:%M')

        end_date_str_export = p.end_datetime.strftime('%d.%m.%Y')
        end_time_str_export = p.end_datetime.strftime('%H:%M')

        if start_date_str_export == end_date_str_export:
            # Dacă datele sunt identice, se omite a doua dată
            datetime_line = f"{start_date_str_export} {start_time_str_export} - {end_time_str_export}"
        else:
            datetime_line = f"{start_date_str_export} {start_time_str_export} - {end_date_str_export} {end_time_str_export}"

        destination_line = p.destination if p.destination else "-" # "-" dacă lipsește, conform așteptărilor implicite

        # Pentru transport_mode și reason, dacă sunt goale, nu se adaugă linii vide,
        # ci se omit acele linii, conform structurii de import unde sunt opționale.
        transport_mode_line = p.transport_mode if p.transport_mode else None
        reason_line = p.reason if p.reason else None

        output_lines.append(student_name_line)
        output_lines.append(datetime_line)
        output_lines.append(destination_line)

        if transport_mode_line is not None:
            output_lines.append(transport_mode_line)
            # Reason line is only added if transport mode was also present and then reason itself is present
            if reason_line is not None:
                 output_lines.append(reason_line)
        elif reason_line is not None:
            # If transport is None, but reason is not, add an empty line for transport to maintain structure for reason
            output_lines.append("")
            output_lines.append(reason_line)

        output_lines.append("") # Empty line separator între intrări

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

    # Export Daily Leaves
    # Format pentru exportul învoirilor zilnice:
    # Similar cu formatul de procesare text: NumeStudent Grad [HH:MM-HH:MM] (data se subînțelege din contextul listei)
    # Pentru un export general, vom include și data.
    # Format: Grad Nume Prenume HH:MM-HH:MM (pentru o anumită dată, grupate)
    # Sau, mai simplu, fiecare învoire pe o linie separată:
    # Grad Nume Prenume, Data (DD.MM.YYYY), OrăStart-OrăStop, [Motiv]

    daily_leaves_by_date = {}
    all_daily_leaves = DailyLeave.query.join(Student).options(joinedload(DailyLeave.student)).order_by(DailyLeave.leave_date, Student.nume, DailyLeave.start_time).all()

    for dl in all_daily_leaves:
        date_str = dl.leave_date.strftime('%d.%m.%Y')
        if date_str not in daily_leaves_by_date:
            daily_leaves_by_date[date_str] = []

        student_name_part = f"{dl.student.grad_militar} {dl.student.nume} {dl.student.prenume}"
        time_part = f"{dl.start_time.strftime('%H:%M')}-{dl.end_time.strftime('%H:%M')}"
        # Format pentru importul de învoiri zilnice din text pare a fi:
        # Nume Prenume Grad HH:MM-HH:MM (fără dată explicită per linie, data e globală)
        # Sau Nume Prenume Grad (folosește ore implicite)
        # Pentru export, vom face: Grad Nume Prenume HH:MM-HH:MM
        # Motivul nu pare a fi parte din formatul de import din text.
        daily_leaves_by_date[date_str].append(f"{student_name_part} {time_part}")

    if daily_leaves_by_date:
        output_lines.append("--- ÎNVOIRI ZILNICE (grupate pe dată) ---")
        for date_group, leaves_in_group in sorted(daily_leaves_by_date.items()):
            output_lines.append(f"\nData: {date_group}")
            for leave_entry in leaves_in_group:
                output_lines.append(leave_entry)
        output_lines.append("\n")


    # Format export învoiri weekend:
    # Similar cu formatul de import:
    # NumeStudent Grad, DD.MM.YYYY HH:MM-HH:MM, DD.MM.YYYY HH:MM-HH:MM, [biserica]
    # Motivul nu pare a fi parte din formatul de import.
    all_weekend_leaves = WeekendLeave.query.join(Student).options(joinedload(WeekendLeave.student)).order_by(WeekendLeave.weekend_start_date, Student.nume).all()
    if all_weekend_leaves:
        output_lines.append("--- ÎNVOIRI WEEKEND ---")
        for wl in all_weekend_leaves:
            student_info = f"{wl.student.grad_militar} {wl.student.nume} {wl.student.prenume}"
            intervals_str_parts = []
            # Folosim get_intervals() care returnează intervalele sortate și corecte ca datetime-uri aware
            leave_intervals = wl.get_intervals()

            for interval in leave_intervals:
                # Formatăm data și ora pentru export ca naive (așa cum ar fi introduse)
                # get_intervals() returnează start/end ca aware, le convertim la Europe/Bucharest și apoi formatăm
                date_str = interval['start'].astimezone(EUROPE_BUCHAREST).strftime('%d.%m.%Y')
                start_time_str = interval['start'].astimezone(EUROPE_BUCHAREST).strftime('%H:%M')
                end_time_str = interval['end'].astimezone(EUROPE_BUCHAREST).strftime('%H:%M')
                intervals_str_parts.append(f"{date_str} {start_time_str}-{end_time_str}")

            intervals_full_str = ", ".join(intervals_str_parts)

            # Verificăm dacă "Duminica" este printre zilele selectate efectiv pentru învoire
            duminica_selectata_efectiv = False
            if wl.day3_selected == "Duminica" and wl.day3_date and wl.day3_start_time and wl.day3_end_time:
                duminica_selectata_efectiv = True
            elif wl.day2_selected == "Duminica" and wl.day2_date and wl.day2_start_time and wl.day2_end_time:
                 duminica_selectata_efectiv = True
            elif wl.day1_selected == "Duminica" and wl.day1_date and wl.day1_start_time and wl.day1_end_time:
                 duminica_selectata_efectiv = True

            biserica_str = ", biserica" if wl.duminica_biserica and duminica_selectata_efectiv else ""
            # Motivul nu este inclus în formatul de import, deci nu îl adăugăm nici la export.
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

# --- Admin Word Export Routes ---
@app.route('/admin/permissions/export_word', endpoint='admin_export_permissions_word')
@login_required
def admin_export_permissions_word():
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    now = get_localized_now()
    permissions_to_export = Permission.query.options(joinedload(Permission.student)).join(Student, Permission.student_id == Student.id).filter(
        Permission.status == 'Aprobată',
        Permission.end_datetime >= now  # Active or upcoming
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

# --- Company Commander Word Export Routes ---
@app.route('/company_commander/permissions/export_word', endpoint='company_commander_export_permissions_word')
@login_required
def company_commander_export_permissions_word():
    if current_user.role != 'comandant_companie':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    company_id_str = _get_commander_unit_id(current_user.username, "CmdC")
    if not company_id_str:
        flash('ID-ul companiei nu a putut fi determinat.', 'warning')
        return redirect(url_for('company_commander_dashboard'))

    student_ids_in_company = [s.id for s in Student.query.filter_by(companie=company_id_str).with_entities(Student.id).all()]
    if not student_ids_in_company:
        flash(f'Niciun student în compania {company_id_str} pentru a exporta permisii.', 'info')
        return redirect(url_for('company_commander_dashboard'))

    now = get_localized_now()
    permissions_to_export = Permission.query.options(joinedload(Permission.student)).join(Student, Permission.student_id == Student.id).filter(
        Permission.student_id.in_(student_ids_in_company),
        Permission.status == 'Aprobată',
        Permission.end_datetime >= now
    ).order_by(Student.nume, Student.prenume, Permission.start_datetime).all()

    if not permissions_to_export:
        flash(f'Nicio permisie activă sau viitoare de exportat pentru compania {company_id_str}.', 'info')
        return redirect(url_for('company_commander_dashboard'))

    document = Document()
    document.add_heading(f'Raport Permisii Compania {company_id_str}', level=1).alignment = WD_ALIGN_PARAGRAPH.CENTER
    user_info_text = f"Raport generat de: {current_user.username}\nData generării: {datetime.now().strftime('%d-%m-%Y %H:%M')}"
    p_user = document.add_paragraph(); p_user.add_run(user_info_text).italic = True; p_user.alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_paragraph()

    table = document.add_table(rows=1, cols=8) # Standard 8 columns
    table.style = 'Table Grid'; table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = table.rows[0].cells
    column_titles = ['Nr. Crt.', 'Grad', 'Nume și Prenume', 'Data Început', 'Data Sfârșit', 'Destinația', 'Mijloc Transport', 'Observații/Nr. Auto']
    for i, title in enumerate(column_titles):
        hdr_cells[i].text = title; hdr_cells[i].paragraphs[0].runs[0].font.bold = True; hdr_cells[i].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

    for idx, p in enumerate(permissions_to_export):
        row_cells = table.add_row().cells
        row_cells[0].text = str(idx + 1); row_cells[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[1].text = p.student.grad_militar
        row_cells[2].text = f"{p.student.nume} {p.student.prenume}"
        row_cells[3].text = p.start_datetime.strftime('%d.%m.%Y %H:%M'); row_cells[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[4].text = p.end_datetime.strftime('%d.%m.%Y %H:%M'); row_cells[4].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[5].text = p.destination if p.destination else "-"
        row_cells[6].text = p.transport_mode if p.transport_mode else "-"
        row_cells[7].text = p.reason if p.reason else "-"; row_cells[7].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

    widths = {0: Inches(0.4), 1: Inches(0.7), 2: Inches(1.8), 3: Inches(1.1), 4: Inches(1.1), 5: Inches(1.5), 6: Inches(1.2), 7: Inches(1.2)}
    for col_idx, width_val in widths.items():
        for row in table.rows:
            if col_idx < len(row.cells): row.cells[col_idx].width = width_val

    style = document.styles['Normal']; font = style.font; font.name = 'Calibri'; font.size = Pt(11)
    f = io.BytesIO(); document.save(f); f.seek(0)
    filename = f"Raport_Permisii_Compania_{company_id_str}_{date.today().strftime('%Y%m%d')}.docx"
    return send_file(f, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

@app.route('/company_commander/weekend_leaves/export_word', endpoint='company_commander_export_weekend_leaves_word')
@login_required
def company_commander_export_weekend_leaves_word():
    if current_user.role != 'comandant_companie':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    company_id_str = _get_commander_unit_id(current_user.username, "CmdC")
    if not company_id_str:
        flash('ID-ul companiei nu a putut fi determinat.', 'warning')
        return redirect(url_for('company_commander_dashboard'))

    student_ids_in_company = [s.id for s in Student.query.filter_by(companie=company_id_str).with_entities(Student.id).all()]
    if not student_ids_in_company:
        flash(f'Niciun student în compania {company_id_str} pentru a exporta învoiri de weekend.', 'info')
        return redirect(url_for('company_commander_dashboard'))

    leaves_to_export = WeekendLeave.query.options(joinedload(WeekendLeave.student)).join(Student, WeekendLeave.student_id == Student.id).filter(
        WeekendLeave.student_id.in_(student_ids_in_company),
        WeekendLeave.status == 'Aprobată'
    ).order_by(Student.nume, Student.prenume, WeekendLeave.weekend_start_date).all()

    leaves_to_export = [leave for leave in leaves_to_export if leave.is_overall_active_or_upcoming]

    if not leaves_to_export:
        flash(f'Nicio învoire de weekend activă sau viitoare de exportat pentru compania {company_id_str}.', 'info')
        return redirect(url_for('company_commander_dashboard'))

    document = Document()
    document.add_heading(f'Raport Învoiri Weekend Compania {company_id_str}', level=1).alignment = WD_ALIGN_PARAGRAPH.CENTER
    user_info_text = f"Raport generat de: {current_user.username}\nData generării: {datetime.now().strftime('%d-%m-%Y %H:%M')}"
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
    filename = f"Raport_Weekend_Compania_{company_id_str}_{date.today().strftime('%Y%m%d')}.docx"
    return send_file(f, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

# --- Battalion Commander Word Export Routes ---
@app.route('/battalion_commander/permissions/export_word', endpoint='battalion_commander_export_permissions_word')
@login_required
def battalion_commander_export_permissions_word():
    if current_user.role != 'comandant_batalion':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    battalion_id_str = _get_commander_unit_id(current_user.username, "CmdB")
    if not battalion_id_str:
        flash('ID-ul batalionului nu a putut fi determinat.', 'warning')
        return redirect(url_for('battalion_commander_dashboard'))

    student_ids_in_battalion = [s.id for s in Student.query.filter_by(batalion=battalion_id_str).with_entities(Student.id).all()]
    if not student_ids_in_battalion:
        flash(f'Niciun student în batalionul {battalion_id_str} pentru a exporta permisii.', 'info')
        return redirect(url_for('battalion_commander_dashboard'))

    now = get_localized_now()
    permissions_to_export = Permission.query.options(joinedload(Permission.student)).join(Student, Permission.student_id == Student.id).filter(
        Permission.student_id.in_(student_ids_in_battalion),
        Permission.status == 'Aprobată',
        Permission.end_datetime >= now
    ).order_by(Student.nume, Student.prenume, Permission.start_datetime).all()

    if not permissions_to_export:
        flash(f'Nicio permisie activă sau viitoare de exportat pentru batalionul {battalion_id_str}.', 'info')
        return redirect(url_for('battalion_commander_dashboard'))

    document = Document()
    document.add_heading(f'Raport Permisii Batalionul {battalion_id_str}', level=1).alignment = WD_ALIGN_PARAGRAPH.CENTER
    user_info_text = f"Raport generat de: {current_user.username}\nData generării: {datetime.now().strftime('%d-%m-%Y %H:%M')}"
    p_user = document.add_paragraph(); p_user.add_run(user_info_text).italic = True; p_user.alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_paragraph()

    table = document.add_table(rows=1, cols=8)
    table.style = 'Table Grid'; table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = table.rows[0].cells
    column_titles = ['Nr. Crt.', 'Grad', 'Nume și Prenume', 'Data Început', 'Data Sfârșit', 'Destinația', 'Mijloc Transport', 'Observații/Nr. Auto']
    for i, title in enumerate(column_titles):
        hdr_cells[i].text = title; hdr_cells[i].paragraphs[0].runs[0].font.bold = True; hdr_cells[i].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

    for idx, p in enumerate(permissions_to_export):
        row_cells = table.add_row().cells
        row_cells[0].text = str(idx + 1); row_cells[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[1].text = p.student.grad_militar
        row_cells[2].text = f"{p.student.nume} {p.student.prenume}"
        row_cells[3].text = p.start_datetime.strftime('%d.%m.%Y %H:%M'); row_cells[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[4].text = p.end_datetime.strftime('%d.%m.%Y %H:%M'); row_cells[4].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row_cells[5].text = p.destination if p.destination else "-"
        row_cells[6].text = p.transport_mode if p.transport_mode else "-"
        row_cells[7].text = p.reason if p.reason else "-"; row_cells[7].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

    widths = {0: Inches(0.4), 1: Inches(0.7), 2: Inches(1.8), 3: Inches(1.1), 4: Inches(1.1), 5: Inches(1.5), 6: Inches(1.2), 7: Inches(1.2)}
    for col_idx, width_val in widths.items():
        for row in table.rows:
            if col_idx < len(row.cells): row.cells[col_idx].width = width_val

    style = document.styles['Normal']; font = style.font; font.name = 'Calibri'; font.size = Pt(11)
    f = io.BytesIO(); document.save(f); f.seek(0)
    filename = f"Raport_Permisii_Batalion_{battalion_id_str}_{date.today().strftime('%Y%m%d')}.docx"
    return send_file(f, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

@app.route('/battalion_commander/weekend_leaves/export_word', endpoint='battalion_commander_export_weekend_leaves_word')
@login_required
def battalion_commander_export_weekend_leaves_word():
    if current_user.role != 'comandant_batalion':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    battalion_id_str = _get_commander_unit_id(current_user.username, "CmdB")
    if not battalion_id_str:
        flash('ID-ul batalionului nu a putut fi determinat.', 'warning')
        return redirect(url_for('battalion_commander_dashboard'))

    student_ids_in_battalion = [s.id for s in Student.query.filter_by(batalion=battalion_id_str).with_entities(Student.id).all()]
    if not student_ids_in_battalion:
        flash(f'Niciun student în batalionul {battalion_id_str} pentru a exporta învoiri de weekend.', 'info')
        return redirect(url_for('battalion_commander_dashboard'))

    leaves_to_export = WeekendLeave.query.options(joinedload(WeekendLeave.student)).join(Student, WeekendLeave.student_id == Student.id).filter(
        WeekendLeave.student_id.in_(student_ids_in_battalion),
        WeekendLeave.status == 'Aprobată'
    ).order_by(Student.nume, Student.prenume, WeekendLeave.weekend_start_date).all()

    leaves_to_export = [leave for leave in leaves_to_export if leave.is_overall_active_or_upcoming]

    if not leaves_to_export:
        flash(f'Nicio învoire de weekend activă sau viitoare de exportat pentru batalionul {battalion_id_str}.', 'info')
        return redirect(url_for('battalion_commander_dashboard'))

    document = Document()
    document.add_heading(f'Raport Învoiri Weekend Batalionul {battalion_id_str}', level=1).alignment = WD_ALIGN_PARAGRAPH.CENTER
    user_info_text = f"Raport generat de: {current_user.username}\nData generării: {datetime.now().strftime('%d-%m-%Y %H:%M')}"
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
    filename = f"Raport_Weekend_Batalion_{battalion_id_str}_{date.today().strftime('%Y%m%d')}.docx"
    return send_file(f, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')


# START JULES BLOCK - NEW AND MODIFIED FUNCTIONS (PROBLEMS 2 & 4)

# --- Commander Scoped List Views ---
@app.route('/commander/permissions', endpoint='view_scoped_permissions')
@login_required
def view_scoped_permissions():
    if current_user.role not in ['comandant_companie', 'comandant_batalion']:
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    student_ids_in_scope = []
    unit_id_str = ""
    report_title_detail = ""
    return_dashboard_url = 'dashboard'

    if current_user.role == 'comandant_companie':
        unit_id_str = _get_commander_unit_id(current_user.username, "CmdC")
        if unit_id_str:
            students_in_unit = Student.query.filter_by(companie=unit_id_str).with_entities(Student.id).all()
            student_ids_in_scope = [s[0] for s in students_in_unit]
            report_title_detail = f"Permisii Compania {unit_id_str}"
            return_dashboard_url = 'company_commander_dashboard'
        else:
            flash('ID Companie invalid.', 'danger'); return redirect(url_for('dashboard'))
    elif current_user.role == 'comandant_batalion':
        unit_id_str = _get_commander_unit_id(current_user.username, "CmdB")
        if unit_id_str:
            students_in_unit = Student.query.filter_by(batalion=unit_id_str).with_entities(Student.id).all()
            student_ids_in_scope = [s[0] for s in students_in_unit]
            report_title_detail = f"Permisii Batalionul {unit_id_str}"
            return_dashboard_url = 'battalion_commander_dashboard'
        else:
            flash('ID Batalion invalid.', 'danger'); return redirect(url_for('dashboard'))

    from sqlalchemy import false
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query_filter = Permission.student_id.in_(student_ids_in_scope) if student_ids_in_scope else false()
    query = Permission.query.options(
        joinedload(Permission.student),
        joinedload(Permission.creator)
    ).filter(query_filter)

    search_student_name = request.args.get('search_student_name', '').strip()
    filter_status = request.args.get('filter_status', '').strip()
    filter_date_type = request.args.get('filter_date_type', 'active_today').strip()

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

    now_localized = get_localized_now()
    today_start_naive = datetime.combine(now_localized.date(), time.min)
    today_end_naive = datetime.combine(now_localized.date(), time.max)
    now_naive_for_db_compare = now_localized.replace(tzinfo=None)

    if filter_date_type == 'active_today':
        query = query.filter(Permission.start_datetime <= today_end_naive, Permission.end_datetime >= today_start_naive, Permission.status == 'Aprobată')
    elif filter_date_type == 'active_now':
        query = query.filter(Permission.start_datetime <= now_naive_for_db_compare, Permission.end_datetime >= now_naive_for_db_compare, Permission.status == 'Aprobată')
    elif filter_date_type == 'upcoming':
        query = query.filter(Permission.start_datetime > now_naive_for_db_compare, Permission.status == 'Aprobată')
    elif filter_date_type == 'past_week':
        seven_days_ago_naive = (now_localized.date() - timedelta(days=7))
        query = query.filter(Permission.end_datetime >= datetime.combine(seven_days_ago_naive, time.min))

    query = query.order_by(Permission.start_datetime.desc())
    permissions_pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template('scoped_list_permissions.html',
                           permissions_pagination=permissions_pagination,
                           title=report_title_detail,
                           return_dashboard_url=return_dashboard_url)

@app.route('/commander/daily_leaves', endpoint='view_scoped_daily_leaves')
@login_required
def view_scoped_daily_leaves():
    if current_user.role not in ['comandant_companie', 'comandant_batalion']:
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    student_ids_in_scope = []
    unit_id_str = ""
    view_title = ""
    return_dashboard_url = 'dashboard'

    if current_user.role == 'comandant_companie':
        unit_id_str = _get_commander_unit_id(current_user.username, "CmdC")
        if unit_id_str:
            students_in_unit = Student.query.filter_by(companie=unit_id_str).with_entities(Student.id).all()
            student_ids_in_scope = [s[0] for s in students_in_unit]
            view_title = f"Învoiri Zilnice Compania {unit_id_str}"
            return_dashboard_url = 'company_commander_dashboard'
        else:
            flash('ID Companie invalid.', 'danger'); return redirect(url_for('dashboard'))
    elif current_user.role == 'comandant_batalion':
        unit_id_str = _get_commander_unit_id(current_user.username, "CmdB")
        if unit_id_str:
            students_in_unit = Student.query.filter_by(batalion=unit_id_str).with_entities(Student.id).all()
            student_ids_in_scope = [s[0] for s in students_in_unit]
            view_title = f"Învoiri Zilnice Batalionul {unit_id_str}"
            return_dashboard_url = 'battalion_commander_dashboard'
        else:
            flash('ID Batalion invalid.', 'danger'); return redirect(url_for('dashboard'))

    from sqlalchemy import false
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query_filter = DailyLeave.student_id.in_(student_ids_in_scope) if student_ids_in_scope else false()
    query = DailyLeave.query.options(
        joinedload(DailyLeave.student),
        joinedload(DailyLeave.creator)
    ).filter(query_filter)

    search_student_name = request.args.get('search_student_name', '').strip()
    filter_status = request.args.get('filter_status', '').strip()
    filter_date_str = request.args.get('filter_date', '').strip()

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
    if filter_date_str:
        try:
            filter_date_obj = datetime.strptime(filter_date_str, '%Y-%m-%d').date()
            query = query.filter(DailyLeave.leave_date == filter_date_obj)
        except ValueError:
            flash('Format dată invalid pentru filtrare. Folosiți YYYY-MM-DD.', 'warning')

    query = query.order_by(DailyLeave.leave_date.desc(), DailyLeave.start_time.desc())
    daily_leaves_pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template('scoped_list_daily_leaves.html',
                           daily_leaves_pagination=daily_leaves_pagination,
                           title=view_title,
                           return_dashboard_url=return_dashboard_url)

@app.route('/commander/weekend_leaves', endpoint='view_scoped_weekend_leaves')
@login_required
def view_scoped_weekend_leaves():
    if current_user.role not in ['comandant_companie', 'comandant_batalion']:
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    student_ids_in_scope = []
    unit_id_str = ""
    view_title = ""
    return_dashboard_url = 'dashboard'

    if current_user.role == 'comandant_companie':
        unit_id_str = _get_commander_unit_id(current_user.username, "CmdC")
        if unit_id_str:
            students_in_unit = Student.query.filter_by(companie=unit_id_str).with_entities(Student.id).all()
            student_ids_in_scope = [s[0] for s in students_in_unit]
            view_title = f"Învoiri Weekend Compania {unit_id_str}"
            return_dashboard_url = 'company_commander_dashboard'
        else:
            flash('ID Companie invalid.', 'danger'); return redirect(url_for('dashboard'))
    elif current_user.role == 'comandant_batalion':
        unit_id_str = _get_commander_unit_id(current_user.username, "CmdB")
        if unit_id_str:
            students_in_unit = Student.query.filter_by(batalion=unit_id_str).with_entities(Student.id).all()
            student_ids_in_scope = [s[0] for s in students_in_unit]
            view_title = f"Învoiri Weekend Batalionul {unit_id_str}"
            return_dashboard_url = 'battalion_commander_dashboard'
        else:
            flash('ID Batalion invalid.', 'danger'); return redirect(url_for('dashboard'))

    from sqlalchemy import false
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query_filter = WeekendLeave.student_id.in_(student_ids_in_scope) if student_ids_in_scope else false()
    query = WeekendLeave.query.options(
        joinedload(WeekendLeave.student),
        joinedload(WeekendLeave.creator)
    ).filter(query_filter)

    search_student_name = request.args.get('search_student_name', '').strip()
    filter_status = request.args.get('filter_status', '').strip()
    filter_weekend_start_date_str = request.args.get('filter_weekend_start_date', '').strip()

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
    if filter_weekend_start_date_str:
        try:
            filter_date_obj = datetime.strptime(filter_weekend_start_date_str, '%Y-%m-%d').date()
            query = query.filter(WeekendLeave.weekend_start_date == filter_date_obj)
        except ValueError:
            flash('Format dată invalid pentru filtrare (Vineri). Folosiți YYYY-MM-DD.', 'warning')

    query = query.order_by(WeekendLeave.weekend_start_date.desc(), WeekendLeave.student_id)
    weekend_leaves_pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template('scoped_list_weekend_leaves.html',
                           weekend_leaves_pagination=weekend_leaves_pagination,
                           title=view_title,
                           return_dashboard_url=return_dashboard_url)

@app.route('/commander/services', endpoint='view_scoped_services')
@login_required
def view_scoped_services():
    if current_user.role not in ['comandant_companie', 'comandant_batalion']:
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    student_ids_in_scope = []
    unit_id_str = ""
    view_title = ""
    return_dashboard_url = 'dashboard'

    if current_user.role == 'comandant_companie':
        unit_id_str = _get_commander_unit_id(current_user.username, "CmdC")
        if unit_id_str:
            students_in_unit = Student.query.filter_by(companie=unit_id_str).with_entities(Student.id).all()
            student_ids_in_scope = [s[0] for s in students_in_unit]
            view_title = f"Servicii Compania {unit_id_str}"
            return_dashboard_url = 'company_commander_dashboard'
        else:
            flash('ID Companie invalid.', 'danger'); return redirect(url_for('dashboard'))
    elif current_user.role == 'comandant_batalion':
        unit_id_str = _get_commander_unit_id(current_user.username, "CmdB")
        if unit_id_str:
            students_in_unit = Student.query.filter_by(batalion=unit_id_str).with_entities(Student.id).all()
            student_ids_in_scope = [s[0] for s in students_in_unit]
            view_title = f"Servicii Batalionul {unit_id_str}"
            return_dashboard_url = 'battalion_commander_dashboard'
        else:
            flash('ID Batalion invalid.', 'danger'); return redirect(url_for('dashboard'))

    from sqlalchemy import false
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query_filter = ServiceAssignment.student_id.in_(student_ids_in_scope) if student_ids_in_scope else false()
    query = ServiceAssignment.query.options(
        joinedload(ServiceAssignment.student),
        joinedload(ServiceAssignment.creator)
    ).filter(query_filter)

    search_student_name = request.args.get('search_student_name', '').strip()
    filter_service_type = request.args.get('filter_service_type', '').strip()
    filter_service_date_str = request.args.get('filter_service_date', '').strip()

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
    if filter_service_date_str:
        try:
            filter_date_obj = datetime.strptime(filter_service_date_str, '%Y-%m-%d').date()
            query = query.filter(ServiceAssignment.service_date == filter_date_obj)
        except ValueError:
            flash('Format dată invalid pentru filtrare. Folosiți YYYY-MM-DD.', 'warning')

    service_types_for_filter = SERVICE_TYPES

    query = query.order_by(ServiceAssignment.start_datetime.desc())
    services_pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template('scoped_list_services.html',
                           services_pagination=services_pagination,
                           title=view_title,
                           return_dashboard_url=return_dashboard_url,
                           service_types_for_filter=service_types_for_filter)


# --- Gradat New Bulk Import Pages ---
@app.route('/gradat/import/permissions', methods=['GET', 'POST'], endpoint='gradat_page_import_permissions')
@login_required
def gradat_page_import_permissions():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        permission_bulk_data = request.form.get('permission_bulk_data', '').strip()
        if not permission_bulk_data:
            flash('Nu au fost furnizate date pentru import.', 'warning')
            return render_template('gradat_import_permissions.html', permission_bulk_data=permission_bulk_data)

        lines = permission_bulk_data.splitlines()
        added_count = 0
        error_count = 0
        error_details = []
        processed_students_details = []

        i = 0
        while i < len(lines):
            name_line_from_block = lines[i].strip()
            if not name_line_from_block:
                i += 1
                continue

            current_block_lines = []
            temp_i = i
            while temp_i < len(lines) and lines[temp_i].strip():
                current_block_lines.append(lines[temp_i].strip())
                temp_i += 1

            i = temp_i
            if temp_i < len(lines) and not lines[temp_i].strip():
                i += 1

            if len(current_block_lines) < 3:
                if len(current_block_lines) > 0 :
                    err_msg = f"Intrare incompletă începând cu '{current_block_lines[0]}'. Necesită Nume, Interval, Destinație."
                    app.logger.warning(f"Bulk Permission Page Import: {err_msg}")
                    error_details.append({"line_content": current_block_lines[0], "error_message": err_msg})
                    error_count += 1
                continue

            name_line_parsed = current_block_lines[0]
            datetime_line = current_block_lines[1]
            destination_line = current_block_lines[2]
            transport_mode_line = current_block_lines[3] if len(current_block_lines) > 3 else ""
            reason_car_plate_line = current_block_lines[4] if len(current_block_lines) > 4 else ""

            student_obj, student_error = find_student_for_bulk_import(name_line_parsed, current_user.id)
            if student_error:
                app.logger.warning(f"Bulk Permission Page Import: Student find error for '{name_line_parsed}': {student_error}")
                error_details.append({"line_content": name_line_parsed, "error_message": student_error})
                error_count += 1
                continue

            try:
                dt_match = re.search(
                    r"(\d{1,2}\.\d{1,2}\.\d{4})\s+(\d{1,2}:\d{2})\s*-\s*(?:(\d{1,2}\.\d{1,2}\.\d{4})\s+)?(\d{1,2}:\d{2})",
                    datetime_line
                )
                if not dt_match:
                    app.logger.warning(f"Bulk Permission Page Import: Invalid datetime format for '{name_line_parsed}'. Input: '{datetime_line}'.")
                    raise ValueError("Format interval datetime invalid.")

                start_date_str, start_time_str, end_date_str_opt, end_time_str = dt_match.groups()
                start_dt = datetime.strptime(f"{start_date_str} {start_time_str}", '%d.%m.%Y %H:%M')
                end_time_obj_parsed = datetime.strptime(end_time_str, '%H:%M').time()

                if end_date_str_opt:
                    end_date_assumed = datetime.strptime(end_date_str_opt, '%d.%m.%Y').date()
                else:
                    end_date_assumed = start_dt.date()

                if not end_date_str_opt and end_time_obj_parsed < start_dt.time():
                     end_date_assumed += timedelta(days=1)
                end_dt = datetime.combine(end_date_assumed, end_time_obj_parsed)

                if end_dt <= start_dt:
                    app.logger.warning(f"Bulk Permission Page Import: End datetime not after start for '{name_line_parsed}'. Start: {start_dt}, End: {end_dt}")
                    raise ValueError("Data/ora de sfârșit trebuie să fie după data/ora de început.")

            except ValueError as ve:
                error_details.append({"line_content": f"{name_line_parsed}, {datetime_line}", "error_message": f"Eroare format dată/oră: {str(ve)}"})
                error_count += 1
                continue

            parsed_destination = destination_line.strip()
            parsed_transport_mode = transport_mode_line.strip() if transport_mode_line else None
            parsed_reason = reason_car_plate_line.strip() if reason_car_plate_line else None

            if not student_obj:
                app.logger.error(f"Bulk Permission Page Import: student_obj is None for '{name_line_parsed}' after student_error was None.")
                error_details.append({"line_content": name_line_parsed, "error_message": "Eroare internă la procesarea studentului."})
                error_count += 1
                continue

            conflict = check_leave_conflict(student_obj.id, start_dt, end_dt, leave_type='permission')
            if conflict:
                app.logger.info(f"Bulk Permission Page Import: Conflict for student '{name_line_parsed}': {conflict}")
                error_details.append({"line_content": name_line_parsed, "error_message": f"Conflict - {conflict}."})
                error_count += 1
                continue

            new_permission = Permission(
                student_id=student_obj.id, start_datetime=start_dt, end_datetime=end_dt,
                destination=parsed_destination, transport_mode=parsed_transport_mode,
                reason=parsed_reason, status='Aprobată', created_by_user_id=current_user.id
            )
            db.session.add(new_permission)
            added_count += 1
            processed_students_details.append(f"Permisie pt {student_obj.nume} {student_obj.prenume}: {start_dt.strftime('%d.%m %H:%M')} - {end_dt.strftime('%d.%m %H:%M')}")

        if added_count > 0:
            try:
                db.session.commit()
                flash(f'{added_count} permisii au fost adăugate cu succes.', 'success')
                log_action("BULK_IMPORT_PERMISSIONS_SUCCESS_PAGE", # Changed action type
                           description=f"User {current_user.username} bulk imported {added_count} permissions via page.",
                           details_after_dict={"added_count": added_count, "details": processed_students_details[:5]})
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash(f'Eroare la salvarea permisiilor în baza de date: {str(e)}', 'danger')
                app.logger.error(f"Bulk Permission Page Import: DB commit error: {str(e)}")
                error_count += added_count
                added_count = 0
                log_action("BULK_IMPORT_PERMISSIONS_FAIL_DB_PAGE", # Changed action type
                           description=f"User {current_user.username} bulk permission import (page) DB commit failed. Error: {str(e)}",
                           details_after_dict={"attempted_add_count": added_count, "error_count_at_fail": error_count})
                db.session.commit()

        if error_count > 0:
            flash(f'{error_count} intrări nu au putut fi procesate sau au generat erori. Verificați detaliile afișate.', 'danger')
            return render_template('gradat_import_permissions.html', permission_bulk_data=permission_bulk_data, error_details=error_details)

        if added_count == 0 and error_count == 0 and permission_bulk_data:
            flash('Nicio permisie validă de importat din datele furnizate. Verificați formatul.', 'info')
            return render_template('gradat_import_permissions.html', permission_bulk_data=permission_bulk_data)

        return redirect(url_for('list_permissions'))

    return render_template('gradat_import_permissions.html', permission_bulk_data='')

@app.route('/gradat/import/weekend_leaves', methods=['GET', 'POST'], endpoint='gradat_page_import_weekend_leaves')
@login_required
def gradat_page_import_weekend_leaves():
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        leave_list_text = request.form.get('weekend_leave_bulk_data', '').strip()
        if not leave_list_text:
            flash('Lista de învoiri este goală.', 'warning')
            return render_template('gradat_import_weekend_leaves.html', weekend_leave_bulk_data=leave_list_text, error_details=None)

        lines = leave_list_text.strip().splitlines()
        processed_count = 0
        error_count = 0
        error_details_list = []
        success_details_list = []

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

            if not student_obj: # Should be caught by student_error, but defensive check
                error_details_list.append({"line": line_content, "error": f"Eroare internă: Studentul '{student_name_str}' nu a putut fi procesat."})
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
            valid_intervals_for_this_student = True

            for interval in parsed_intervals:
                interval_date = interval['date_obj']
                delta_days = (interval_date - weekend_start_date_obj).days
                day_slot_key = None; day_name_ro = None

                if delta_days == 0 and interval_date.weekday() == 4: day_slot_key, day_name_ro = "day1", "Vineri"
                elif delta_days == 1 and interval_date.weekday() == 5: day_slot_key, day_name_ro = "day2", "Sambata"
                elif delta_days == 2 and interval_date.weekday() == 6: day_slot_key, day_name_ro = "day3", "Duminica"
                else:
                    error_details_list.append({"line": line_content, "student": student_obj.nume, "error": f"Data {interval_date.strftime('%d.%m.%Y')} nu corespunde weekendului."})
                    error_count += 1; valid_intervals_for_this_student = False; break

                if day_slot_key in distinct_days_processed :
                     error_details_list.append({"line": line_content, "student": student_obj.nume, "error": f"Intervale multiple pentru {day_name_ro}."})
                     valid_intervals_for_this_student = False; break
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

            if not valid_intervals_for_this_student: continue
            if not distinct_days_processed:
                error_details_list.append({"line": line_content, "student": student_obj.nume, "error": "Niciun interval valid mapat."})
                error_count += 1; continue

            conflict_found_for_student = False
            for interval_to_check in current_weekend_leave_data["intervals_for_conflict_check"]:
                conflict = check_leave_conflict(student_obj.id, interval_to_check['start'], interval_to_check['end'], leave_type='weekend_leave')
                if conflict:
                    error_details_list.append({"line": line_content, "student": student_obj.nume, "error": f"Conflict {interval_to_check['day_name']}: {conflict}."})
                    error_count += 1; conflict_found_for_student = True; break
            if conflict_found_for_student: continue

            new_wl = WeekendLeave(
                student_id=student_obj.id, weekend_start_date=weekend_start_date_obj,
                day1_selected=current_weekend_leave_data['day1_selected'], day1_date=current_weekend_leave_data['day1_date'],
                day1_start_time=current_weekend_leave_data['day1_start_time'], day1_end_time=current_weekend_leave_data['day1_end_time'],
                day2_selected=current_weekend_leave_data['day2_selected'], day2_date=current_weekend_leave_data['day2_date'],
                day2_start_time=current_weekend_leave_data['day2_start_time'], day2_end_time=current_weekend_leave_data['day2_end_time'],
                day3_selected=current_weekend_leave_data['day3_selected'], day3_date=current_weekend_leave_data['day3_date'],
                day3_start_time=current_weekend_leave_data['day3_start_time'], day3_end_time=current_weekend_leave_data['day3_end_time'],
                duminica_biserica=(is_biserica_req and current_weekend_leave_data['day3_selected'] == "Duminica"),
                status='Aprobată', created_by_user_id=current_user.id, reason=f"Import text: {line_content[:100]}"
            )
            db.session.add(new_wl)
            processed_count += 1
            success_details_list.append(f"Învoire weekend pentru {student_obj.nume} {student_obj.prenume} ({weekend_start_date_obj.strftime('%d.%m')}) adăugată.")

        if processed_count > 0:
            try:
                db.session.commit()
                flash(f'{processed_count} învoiri de weekend procesate și adăugate.', 'success')
                for detail in success_details_list: flash(detail, 'info') # Consider logging these instead of flashing
                log_action("BULK_IMPORT_WEEKEND_LEAVES_SUCCESS_PAGE",
                           description=f"User {current_user.username} bulk imported {processed_count} weekend leaves via page.",
                           details_after_dict={"added_count": processed_count, "success_details": success_details_list[:5]})
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash(f'Eroare la salvarea învoirilor de weekend: {str(e)}', 'danger')
                app.logger.error(f"Bulk Weekend Leave Page Import: DB commit error: {str(e)}")
                error_count += processed_count; processed_count = 0
                log_action("BULK_IMPORT_WEEKEND_LEAVES_FAIL_DB_PAGE",
                           description=f"User {current_user.username} bulk weekend leave (page) DB commit failed. Error: {str(e)}",
                           details_after_dict={"attempted_add_count": processed_count, "error_count_at_fail": error_count})
                db.session.commit()

        if error_count > 0:
            flash(f'{error_count} linii/intrări nu au putut fi procesate sau au generat erori.', 'danger')
            return render_template('gradat_import_weekend_leaves.html', weekend_leave_bulk_data=leave_list_text, error_details=error_details_list)

        if processed_count == 0 and error_count == 0 and leave_list_text:
            flash('Nicio învoire validă de importat. Verificați formatul.', 'info')

        return redirect(url_for('list_weekend_leaves'))

    return render_template('gradat_import_weekend_leaves.html', weekend_leave_bulk_data='')


# --- Presence Report Route ---
@app.route('/reports/presence', methods=['GET', 'POST'])
@login_required
def presence_report():
    if current_user.role not in ['gradat', 'admin', 'comandant_companie', 'comandant_batalion']:
        flash('Acces neautorizat pentru rolul dumneavoastră.', 'danger')
        return redirect(url_for('dashboard'))

    current_dt_str_for_form = get_localized_now().strftime('%Y-%m-%dT%H:%M')
    report_data_to_render = None

    if request.method == 'POST':
        report_type = request.form.get('report_type')
        custom_datetime_str = request.form.get('custom_datetime')
        datetime_to_check = None
        report_title_detail = ""

        if report_type == 'current':
            datetime_to_check = get_localized_now()
            report_title_detail = "Prezență Curentă"
        elif report_type == 'evening_roll_call':
            naive_dt = get_standard_roll_call_datetime()
            datetime_to_check = EUROPE_BUCHAREST.localize(naive_dt)
            report_title_detail = f"Apel de Seară ({datetime_to_check.strftime('%H:%M')})"
        elif report_type == 'company_report':
            naive_dt = datetime.combine(get_localized_now().date(), time(14, 20))
            datetime_to_check = EUROPE_BUCHAREST.localize(naive_dt)
            report_title_detail = "Raport Companie (14:20)"
        elif report_type == 'morning_check':
            target_d = get_localized_now().date()
            if custom_datetime_str:
                try:
                    target_d = datetime.strptime(custom_datetime_str, '%Y-%m-%dT%H:%M').date()
                except (ValueError, TypeError):
                    flash('Data custom specificată era invalidă, s-a folosit data curentă pentru raportul de dimineață.', 'warning')
            naive_dt = datetime.combine(target_d, time(7, 0))
            datetime_to_check = EUROPE_BUCHAREST.localize(naive_dt)
            report_title_detail = f"Prezență Dimineață ({target_d.strftime('%d.%m.%Y')} 07:00)"
        elif report_type == 'custom':
            try:
                naive_dt = datetime.strptime(custom_datetime_str, '%Y-%m-%dT%H:%M')
                datetime_to_check = EUROPE_BUCHAREST.localize(naive_dt)
                report_title_detail = f"Dată Specifică ({datetime_to_check.strftime('%d.%m.%Y %H:%M')})"
            except (ValueError, TypeError):
                flash('Format dată și oră custom invalid. Folosiți formatul corect.', 'danger')
                return render_template('presence_report.html', current_datetime_str=current_dt_str_for_form, report_data=None)
        else:
            flash('Tip de raport invalid selectat.', 'danger')
            return render_template('presence_report.html', current_datetime_str=current_dt_str_for_form, report_data=None)

        students_for_report = []
        report_base_title = "Raport Prezență"

        if current_user.role == 'gradat':
            students_for_report = Student.query.filter_by(created_by_user_id=current_user.id).all()
            gradat_pluton = students_for_report[0].pluton if students_for_report else "N/A"
            report_base_title = f"Raport Prezență Plutonul {gradat_pluton}"
        elif current_user.role == 'comandant_companie':
            company_id = _get_commander_unit_id(current_user.username, "CmdC")
            if company_id:
                students_for_report = Student.query.filter_by(companie=company_id).all()
                report_base_title = f"Raport Prezență Compania {company_id}"
            else:
                flash("Nu s-a putut determina ID-ul companiei.", "danger")
        elif current_user.role == 'comandant_batalion':
            battalion_id = _get_commander_unit_id(current_user.username, "CmdB")
            if battalion_id:
                students_for_report = Student.query.filter_by(batalion=battalion_id).all()
                report_base_title = f"Raport Prezență Batalionul {battalion_id}"
            else:
                flash("Nu s-a putut determina ID-ul batalionului.", "danger")
        elif current_user.role == 'admin': # Admin can also generate reports
            # For admin, maybe they select a unit or see all?
            # For now, let's assume admin sees all students if they access this.
            # This part can be refined with a selection UI for admin.
            students_for_report = Student.query.all()
            report_base_title = "Raport Prezență General (Admin)"


        if not students_for_report and current_user.role == 'gradat':
             flash('Nu aveți studenți în evidență pentru a genera raportul.', 'info')

        if students_for_report:
            report_data_calculated = _calculate_presence_data(students_for_report, datetime_to_check)
            report_data_to_render = {
                **report_data_calculated,
                "title": f"{report_base_title} - {report_title_detail}",
                "datetime_checked": datetime_to_check.strftime('%d %B %Y, %H:%M:%S')
            }
        elif not students_for_report and current_user.role != 'gradat' and not request.form.get('suppress_no_students_flash'):
            flash(f"Niciun student găsit pentru {current_user.role} {current_user.username} pentru a genera raportul.", "info")

    return render_template('presence_report.html',
                           current_datetime_str=current_dt_str_for_form,
                           report_data=report_data_to_render)


# This block seems to be intended for main execution,
# but was previously mis-indented.
# It should ideally be within an `if __name__ == '__main__':` block.

# print("--------------------------------------------------------")
# user_input = input("Do you want to attempt to apply database migrations? (yes/no): ")
# print("--------------------------------------------------------")

# if user_input.lower() == 'yes':
#     try:
#         print("Attempting to apply database migrations...")
#         # Assuming 'upgrade' comes from Flask-Migrate, it needs app context
#         # from flask_migrate import upgrade # Ensure this import is at the top if used here
#         # with app.app_context(): # Migrations need app context
#         #     upgrade()
#         print("Database migrations applied successfully or no new migrations were found.")
#     except Exception as e:
#         print(f"Error applying database migrations: {e}")
# else:
#     print("Skipping database migrations.")

# Initialize DB (for admin user creation, etc.)
# init_db() # This also needs app context if called outside a request or app setup

# It's recommended to run the app within an if __name__ == '__main__': block.
# The app.run() call is correctly placed within this block below.

# The database initialization and migration logic is best handled
# by Flask CLI commands (e.g., flask db init, flask db migrate, flask db upgrade)
# and/or a separate script to create the initial admin user if needed.
# Interactive prompts for these operations during app startup are generally avoided.
# These actions should be performed explicitly during setup or deployment.

if __name__ == '__main__':
    # --- Database Initialization and Migration ---
    # The following section for database migrations and initialization (init_db)
    # is commented out by default. It is NOT recommended to run these automatically
    # every time the application starts.

    # For database migrations:
    # Use Flask-Migrate CLI commands in your terminal:
    #   flask db migrate -m "description of changes"
    #   flask db upgrade
    # These commands should be run manually when database schema changes are made.

    # For initial database setup (creating tables and admin user):
    # The init_db() function can be called manually, for example, via a custom Flask CLI command
    # or a separate script. This is typically done once for initial setup or in development.
    #
    # Example of how one might run init_db() or migrations once for development (uncomment to use):
    with app.app_context():
        # To apply migrations:
        print("--- Attempting to apply database migrations... ---")
        try:
            from flask_migrate import upgrade as flask_upgrade
            flask_upgrade()
            print("DB migrations applied or up-to-date.")
        except Exception as e:
            print(f"Error during migration: {e}")

        # To initialize the database (create tables, admin user if not exists):
        print("--- Attempting to initialize database (admin user, etc.)... ---")
        init_db() # Make sure init_db() is defined and handles its operations correctly.
        print("DB initialization complete.")
        # pass # Use 'pass' if all operations above are commented out.

    # Start the Flask development server
    app.run(host='0.0.0.0', port=5001, debug=False)


# --- Admin Data Reset Routes ---
@app.route('/admin/reset/permissions', methods=['POST'])
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

[end of app.py]
