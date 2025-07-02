from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
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
                s_dt, e_dt = datetime.combine(d_date, s_time), datetime.combine(d_date, e_time)
                if e_dt < s_dt: e_dt += timedelta(days=1)
                intervals.append({"day_name": d_name, "start": s_dt, "end": e_dt})
        return sorted(intervals, key=lambda x: x['start'])
    @property
    def is_overall_active_or_upcoming(self):
        now = datetime.now()
        if self.status != 'Aprobată': return False
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
    d = start_date if start_date else date.today();
    while d.weekday() != 4: d += timedelta(days=1)
    return d

def get_upcoming_fridays(num_fridays=5):
    """
    Generates a list of upcoming (and potentially the current or immediate past) Fridays.
    Returns a list of dicts, each with 'value' (YYYY-MM-DD string) and 'display' (Month Day, Year string).
    """
    fridays_list = []
    today = date.today()
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

def get_student_status(student_obj_or_user_obj, datetime_check):
    is_student_object = isinstance(student_obj_or_user_obj, Student)
    if is_student_object:
        student_id_to_check = student_obj_or_user_obj.id
        active_service = ServiceAssignment.query.filter(ServiceAssignment.student_id == student_id_to_check, ServiceAssignment.start_datetime <= datetime_check, ServiceAssignment.end_datetime >= datetime_check).order_by(ServiceAssignment.start_datetime).first()
        if active_service: 
            return {"status_code": "on_duty", "reason": f"Serviciu ({active_service.service_type})", "until": active_service.end_datetime, "details": f"Serviciu: {active_service.service_type}", "object": active_service, "participates_in_roll_call": active_service.participates_in_roll_call }
        active_permission = Permission.query.filter(Permission.student_id == student_id_to_check, Permission.status == 'Aprobată', Permission.start_datetime <= datetime_check, Permission.end_datetime >= datetime_check).order_by(Permission.start_datetime).first()
        if active_permission: 
            return {"status_code": "absent_permission", "reason": "Permisie", "until": active_permission.end_datetime, "details": "Permisie", "object": active_permission }
        weekend_leaves = WeekendLeave.query.filter(WeekendLeave.student_id == student_id_to_check, WeekendLeave.status == 'Aprobată').all()
        for wl in weekend_leaves:
            for interval in wl.get_intervals():
                if interval['start'] <= datetime_check <= interval['end']: 
                    return {"status_code": "absent_weekend_leave", "reason": f"Învoire Weekend ({interval['day_name']})", "until": interval['end'], "details": f"Învoire Weekend: {interval['day_name']}", "object": wl }
        daily_leaves = DailyLeave.query.filter(DailyLeave.student_id == student_id_to_check, DailyLeave.status == 'Aprobată').all()
        for dl in daily_leaves:
            if dl.start_datetime <= datetime_check <= dl.end_datetime: 
                return {"status_code": "absent_daily_leave", "reason": f"Învoire Zilnică ({dl.leave_type_display})", "until": dl.end_datetime, "details": f"Învoire Zilnică: {dl.leave_type_display}", "object": dl }

        if hasattr(student_obj_or_user_obj, 'is_platoon_graded_duty') and student_obj_or_user_obj.is_platoon_graded_duty:
            return {"status_code": "platoon_graded_duty", "reason": "Gradat Pluton", "until": None, "details": "Activitate Gradat Pluton", "object": student_obj_or_user_obj }

        return {"status_code": "present", "reason": "Prezent în formație", "until": None, "details": "Prezent în formație", "object": student_obj_or_user_obj }
    elif isinstance(student_obj_or_user_obj, User):
        return {"status_code": "undefined_for_user_role", "reason": "Status de prezență nedefinit pentru un User. Doar Studenții au status de prezență.", "until": None, "details": "N/A"}
    else:
        return {"status_code": "unknown", "reason": "Tip obiect necunoscut", "until": None, "details": "Eroare internă"}

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

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        login_code = request.form.get('login_code')
        user = User.query.filter_by(unique_code=login_code).first()
        if user:
            if user.is_first_login:
                login_user(user); flash('Autentificare reușită! Setează-ți codul personal.', 'info'); return redirect(url_for('set_personal_code'))
            else: flash('Acest cod unic a fost deja folosit pentru prima autentificare. Te rugăm folosește codul personal setat.', 'warning'); return redirect(url_for('user_login'))
        users = User.query.filter(User.role != 'admin').all()
        found_user_by_personal_code = next((u for u in users if u.personal_code_hash and u.check_personal_code(login_code)), None)
        if found_user_by_personal_code:
            if found_user_by_personal_code.is_first_login: flash('Eroare de configurare cont. Contactează administratorul.', 'danger'); return redirect(url_for('user_login'))
            login_user(found_user_by_personal_code); flash('Autentificare reușită!', 'success'); return redirect(url_for('dashboard'))
        flash('Cod de autentificare invalid sau expirat.', 'danger'); return redirect(url_for('user_login'))
    return render_template('user_login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        user = User.query.filter_by(username=username, role='admin').first()
        if user and user.check_password(password): login_user(user); flash('Autentificare admin reușită!', 'success'); return redirect(url_for('dashboard'))
        else: flash('Nume de utilizator sau parolă admin incorecte.', 'danger'); return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); flash('Ai fost deconectat.', 'success'); return redirect(url_for('home'))

@app.route('/set_personal_code', methods=['GET', 'POST'])
@login_required
def set_personal_code():
    if not current_user.is_first_login: flash('Codul personal a fost deja setat.', 'info'); return redirect(url_for('dashboard'))
    if request.method == 'POST':
        personal_code, confirm_personal_code = request.form.get('personal_code'), request.form.get('confirm_personal_code')
        if not personal_code or len(personal_code) < 4: flash('Codul personal trebuie să aibă minim 4 caractere.', 'warning'); return redirect(url_for('set_personal_code'))
        if personal_code != confirm_personal_code: flash('Codurile personale nu se potrivesc.', 'warning'); return redirect(url_for('set_personal_code'))
        try:
            current_user.set_personal_code(personal_code); db.session.commit()
            flash_message = 'Codul personal a fost setat cu succes. Te rugăm să te autentifici din nou folosind noul cod.'
            logout_user(); flash(flash_message, 'success'); return redirect(url_for('user_login'))
        except Exception as e: db.session.rollback(); flash(f'A apărut o eroare la setarea codului personal: {str(e)}', 'danger'); return redirect(url_for('set_personal_code'))
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
    if current_user.role == 'admin': return redirect(url_for('admin_dashboard_route'))
    elif current_user.role == 'gradat':
        student_count = Student.query.filter_by(created_by_user_id=current_user.id).count()
        now = datetime.now()
        active_permissions_count = Permission.query.join(Student).filter(Student.created_by_user_id == current_user.id, Permission.status == 'Aprobată', Permission.start_datetime <= now, Permission.end_datetime >= now).count()
        active_dl_count = sum(1 for dl in DailyLeave.query.join(Student).filter(Student.created_by_user_id == current_user.id, DailyLeave.status == 'Aprobată').all() if dl.is_active)
        active_wl_count = sum(1 for wl in WeekendLeave.query.join(Student).filter(Student.created_by_user_id == current_user.id, WeekendLeave.status == 'Aprobată').all() if wl.is_any_interval_active_now)
        active_services_count = ServiceAssignment.query.join(Student).filter(Student.created_by_user_id == current_user.id, ServiceAssignment.start_datetime <= now, ServiceAssignment.end_datetime >= now).count()
        total_volunteer_activities = VolunteerActivity.query.filter_by(created_by_user_id=current_user.id).count()
        return render_template('gradat_dashboard.html', student_count=student_count, active_permissions_count=active_permissions_count, active_daily_leaves_count=active_dl_count, active_weekend_leaves_count=active_wl_count, active_services_count=active_services_count, total_volunteer_activities=total_volunteer_activities)
    elif current_user.role == 'comandant_companie': return redirect(url_for('company_commander_dashboard'))
    elif current_user.role == 'comandant_batalion': return redirect(url_for('battalion_commander_dashboard'))
    return render_template('dashboard.html', name=current_user.username)

# --- Admin User Management ---
@app.route('/admin/users/create', methods=['POST']) # Form is on admin_dashboard, so this handles POST
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
            db.session.commit()
            flash(f'Utilizatorul "{username}" ({role}) a fost creat cu succes! Cod unic de autentificare: {unique_code}', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la crearea utilizatorului: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard_route'))

    # GET request to this URL might redirect or show a specific form if desired later.
    # For now, as the form is on admin_dashboard, a GET here is not expected for form display.
    return redirect(url_for('admin_dashboard_route'))

@app.route('/admin/users/reset_code/<int:user_id>', methods=['POST'])
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

    new_unique_code = secrets.token_hex(8)
    while User.query.filter_by(unique_code=new_unique_code).first():
        new_unique_code = secrets.token_hex(8)

    user_to_reset.unique_code = new_unique_code
    user_to_reset.is_first_login = True
    user_to_reset.password_hash = None  # Clear old password if any
    user_to_reset.personal_code_hash = None # Clear personal code

    try:
        db.session.commit()
        flash(f'Codul pentru utilizatorul "{user_to_reset.username}" a fost resetat. Noul cod unic de autentificare: {new_unique_code}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la resetarea codului: {str(e)}', 'danger')
    return redirect(url_for('admin_dashboard_route'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('Utilizatorul nu a fost găsit.', 'danger')
        return redirect(url_for('admin_dashboard_route'))

    if user_to_delete.role == 'admin': # Prevent deleting admin accounts
        flash('Conturile de administrator nu pot fi șterse prin această interfață.', 'warning')
        return redirect(url_for('admin_dashboard_route'))

    username_deleted = user_to_delete.username # For flash message

    try:
        if user_to_delete.role == 'gradat':
            # Cascading delete should handle associated student data due to `ondelete='CASCADE'` in models:
            # Permission, DailyLeave, WeekendLeave, ServiceAssignment, ActivityParticipant
            # So, deleting the student should delete their related items.
            # And deleting the User (gradat) should ensure their created_students are handled.
            # However, the relation User.students_created does not have cascade delete by default for the students themselves.
            # We need to explicitly delete students created by this gradat.

            students_to_delete = Student.query.filter_by(created_by_user_id=user_to_delete.id).all()
            for student in students_to_delete:
                # Related items like Permissions, DailyLeaves etc., are deleted due to cascade on Student model
                db.session.delete(student)
            flash(f'Toți studenții ({len(students_to_delete)}) și datele asociate pentru gradatul {username_deleted} au fost șterse.', 'info')

        # Now delete the user
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'Utilizatorul "{username_deleted}" și toate datele asociate (dacă este cazul) au fost șterse cu succes.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la ștergerea utilizatorului {username_deleted}: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard_route'))

# --- Helper function to parse commander's unit ID ---
def _get_commander_unit_id(username, role_prefix):
    # Assumes username like "CmdC1", "CmdB12"
    # role_prefix should be "CmdC" or "CmdB"
    if username.startswith(role_prefix):
        unit_id_part = username[len(role_prefix):]
        if unit_id_part:  # Checks if the string is not empty
            return unit_id_part
    return None # Return None if prefix doesn't match or if ID part is empty

# --- Helper function to determine standard roll call time ---
def get_standard_roll_call_datetime(for_date=None):
    target_date = for_date if for_date else date.today()
    weekday = target_date.weekday() # Monday is 0 and Sunday is 6

    if 0 <= weekday <= 3: # Monday to Thursday
        roll_call_time = time(20, 0)
    else: # Friday to Sunday
        roll_call_time = time(22, 0)

    return datetime.combine(target_date, roll_call_time)

# --- Helper function to calculate presence data for a list of students ---
def _calculate_presence_data(student_list, check_datetime):
    efectiv_control = len(student_list)
    in_formation_list = []
    on_duty_list = []
    platoon_graded_duty_list = [] # Students who are 'platoon_graded_duty' and not otherwise absent/on duty
    absent_list = [] # List of strings with student name and reason

    for s in student_list:
        status_info = get_student_status(s, check_datetime)
        student_display_name = f"{s.grad_militar} {s.nume} {s.prenume}"

        if status_info["status_code"] == "present":
            in_formation_list.append(student_display_name)
        elif status_info["status_code"] == "on_duty":
            # For company/battalion reports, all students on duty are listed under "on duty",
            # regardless of their participation in roll call.
            on_duty_list.append(f"{student_display_name} - {status_info['reason']}")
        elif status_info["status_code"] == "platoon_graded_duty":
            # This status means they are present but have a special role.
            # They are not "absent" but might be reported separately from "in_formation_list"
            # For commander's view, they are part of Ep (Efectiv Prezent)
            platoon_graded_duty_list.append(f"{student_display_name} - {status_info['reason']}")
        elif status_info["status_code"] in ["absent_permission", "absent_daily_leave", "absent_weekend_leave"]:
            absent_list.append(f"{student_display_name} - {status_info['reason']}")
        # Other statuses like 'undefined_for_user_role', 'unknown' are ignored for these counts
        # or should be handled if they represent a form of absence.

    # Adjust counts: Platoon Graded Duty students are present.
    # The main "in_formation_count" for commander dashboards usually means "physically in ranks".
    # "on_duty_count" means those in service *and not at roll call*.
    # "platoon_graded_duty_count" are those present with that specific role.

    in_formation_count = len(in_formation_list)
    on_duty_count = len(on_duty_list) # These are specifically those NOT at roll call due to duty
    platoon_graded_duty_count = len(platoon_graded_duty_list)
    efectiv_absent_total = len(absent_list)

    # Ep = (in formation) + (on duty not at roll call) + (platoon graded duty)
    efectiv_prezent_total = in_formation_count + on_duty_count + platoon_graded_duty_count

    # Ensure EC = Ep + Ea, if not, there's a discrepancy (e.g. student without clear status)
    # This simplified model assumes all students fall into one of these categories.
    # If EC != Ep + Ea, it means some students were not categorized, which could be an issue.

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
    students_in_company = Student.query.filter_by(companie=company_id_str).all()

    total_company_presence = _calculate_presence_data(students_in_company, roll_call_datetime)

    platoons_data = {}
    # Group students by platoon
    platoons_in_company = sorted(list(set(s.pluton for s in students_in_company if s.pluton)))

    for pluton_id_str in platoons_in_company:
        students_in_pluton = [s for s in students_in_company if s.pluton == pluton_id_str]
        platoon_name = f"Plutonul {pluton_id_str}" # or just pluton_id_str if preferred
        platoons_data[platoon_name] = _calculate_presence_data(students_in_pluton, roll_call_datetime)

    return render_template('company_commander_dashboard.html',
                           company_id=company_id_str,
                           roll_call_time_str=roll_call_time_str,
                           total_company_presence=total_company_presence,
                           platoons_data=platoons_data)

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

    students_in_battalion = Student.query.filter_by(batalion=battalion_id_str).all()

    total_battalion_presence = _calculate_presence_data(students_in_battalion, roll_call_datetime)

    companies_data = {}
    companies_in_battalion = sorted(list(set(s.companie for s in students_in_battalion if s.companie)))

    for company_id_str_loop in companies_in_battalion: # Renamed to avoid conflict with outer scope if any
        students_in_company_loop = [s for s in students_in_battalion if s.companie == company_id_str_loop]
        company_name = f"Compania {company_id_str_loop}"
        companies_data[company_name] = _calculate_presence_data(students_in_company_loop, roll_call_datetime)

    return render_template('battalion_commander_dashboard.html',
                           battalion_id=battalion_id_str,
                           roll_call_time_str=roll_call_time_str,
                           total_battalion_presence=total_battalion_presence,
                           companies_data=companies_data)

# --- Presence Report Route ---
@app.route('/reports/presence', methods=['GET', 'POST'])
@login_required
def presence_report():
    if current_user.role not in ['gradat', 'admin', 'comandant_companie', 'comandant_batalion']: # Admin/Commanders might also want to see this for their unit? For now, primarily gradat.
        flash('Acces neautorizat pentru rolul dumneavoastră.', 'danger')
        return redirect(url_for('dashboard'))

    current_dt_str_for_form = datetime.now().strftime('%Y-%m-%dT%H:%M')
    report_data_to_render = None

    if request.method == 'POST':
        report_type = request.form.get('report_type')
        custom_datetime_str = request.form.get('custom_datetime')
        datetime_to_check = None
        report_title_detail = ""

        if report_type == 'current':
            datetime_to_check = datetime.now()
            report_title_detail = "Prezență Curentă"
        elif report_type == 'evening_roll_call':
            datetime_to_check = get_standard_roll_call_datetime() # Uses today's date by default
            report_title_detail = f"Apel de Seară ({datetime_to_check.strftime('%H:%M')})"
        elif report_type == 'company_report':
            datetime_to_check = datetime.combine(date.today(), time(14, 20))
            report_title_detail = "Raport Companie (14:20)"
        elif report_type == 'morning_check':
            # Use the date part from custom_datetime_str if available and valid, otherwise default to today
            target_d = date.today() # Default to today
            if custom_datetime_str: # If a custom date string is provided
                try:
                    # Attempt to parse the date part from the custom datetime input
                    target_d = datetime.strptime(custom_datetime_str, '%Y-%m-%dT%H:%M').date()
                except (ValueError, TypeError):
                    # If parsing fails, stick to the default (today)
                    flash('Data custom specificată era invalidă, s-a folosit data curentă pentru raportul de dimineață.', 'warning')
            datetime_to_check = datetime.combine(target_d, time(7, 0))
            report_title_detail = f"Prezență Dimineață ({target_d.strftime('%d.%m.%Y')} 07:00)"
        elif report_type == 'custom':
            try:
                datetime_to_check = datetime.strptime(custom_datetime_str, '%Y-%m-%dT%H:%M')
                report_title_detail = f"Dată Specifică ({datetime_to_check.strftime('%d.%m.%Y %H:%M')})"
            except (ValueError, TypeError):
                flash('Format dată și oră custom invalid. Folosiți formatul corect.', 'danger')
                # Return to form without report_data, current_dt_str_for_form will be used
                return render_template('presence_report.html', current_datetime_str=current_dt_str_for_form, report_data=None)
        else:
            flash('Tip de raport invalid selectat.', 'danger')
            return render_template('presence_report.html', current_datetime_str=current_dt_str_for_form, report_data=None)

        # Determine student list based on role
        students_for_report = []
        report_base_title = "Raport Prezență"

        if current_user.role == 'gradat':
            students_for_report = Student.query.filter_by(created_by_user_id=current_user.id).all()
            gradat_pluton = students_for_report[0].pluton if students_for_report else "N/A" # Assuming gradat manages one platoon
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
        # Admin might see all students or have a selection UI - for now, admin not generating this specific report via this UI

        if not students_for_report and current_user.role == 'gradat': # Only flash if gradat has no students
             flash('Nu aveți studenți în evidență pentru a genera raportul.', 'info')

        if students_for_report:
            report_data_calculated = _calculate_presence_data(students_for_report, datetime_to_check)
            report_data_to_render = {
                **report_data_calculated, # Spread the calculated data
                "title": f"{report_base_title} - {report_title_detail}",
                "datetime_checked": datetime_to_check.strftime('%d %B %Y, %H:%M:%S')
            }
        elif not students_for_report and current_user.role != 'gradat' and not request.form.get('suppress_no_students_flash'): # Avoid flash if no students for commanders unless explicitly generating
            flash(f"Niciun student găsit pentru {current_user.role} {current_user.username} pentru a genera raportul.", "info")


    return render_template('presence_report.html',
                           current_datetime_str=current_dt_str_for_form,
                           report_data=report_data_to_render)

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
    today_str_for_form = date.today().strftime('%Y-%m-%d')

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


# --- Management Studenți ---
@app.route('/gradat/students')
@app.route('/admin/students')
@login_required
def list_students():
    is_admin_view = current_user.role == 'admin' and request.path.startswith('/admin/')
    page = request.args.get('page', 1, type=int)
    per_page = 15

    students_query = Student.query
    if is_admin_view: # Admin might want to see creator info
        students_query = students_query.options(joinedload(Student.creator))

    search_term = request.args.get('search', '').strip()
    filter_batalion = request.args.get('batalion', '').strip()
    filter_companie = request.args.get('companie', '').strip()
    filter_pluton = request.args.get('pluton', '').strip()

    # For populating filter dropdowns - consider optimizing if it becomes slow
    all_students_for_filters = Student.query.with_entities(Student.batalion, Student.companie, Student.pluton).distinct().all()
    batalioane = sorted(list(set(s.batalion for s in all_students_for_filters if s.batalion)))
    companii = sorted(list(set(s.companie for s in all_students_for_filters if s.companie)))
    plutoane = sorted(list(set(s.pluton for s in all_students_for_filters if s.pluton)))

    if is_admin_view:
        if search_term:
            search_pattern = f"%{unidecode(search_term.lower())}%"
            students_query = students_query.filter(or_(
                func.lower(unidecode(Student.nume)).like(search_pattern),
                func.lower(unidecode(Student.prenume)).like(search_pattern),
                func.lower(unidecode(Student.id_unic_student)).like(search_pattern)
            ))
        if filter_batalion: students_query = students_query.filter(Student.batalion == filter_batalion)
        if filter_companie: students_query = students_query.filter(Student.companie == filter_companie)
        if filter_pluton: students_query = students_query.filter(Student.pluton == filter_pluton)
        students_query = students_query.order_by(Student.batalion, Student.companie, Student.pluton, Student.nume, Student.prenume)
    else: # Gradat view
        if current_user.role != 'gradat':
            flash('Acces neautorizat pentru rolul curent.', 'danger')
            return redirect(url_for('dashboard'))
        students_query = students_query.filter_by(created_by_user_id=current_user.id)
        if search_term:
            search_pattern = f"%{unidecode(search_term.lower())}%"
            students_query = students_query.filter(or_(
                func.lower(unidecode(Student.nume)).like(search_pattern),
                func.lower(unidecode(Student.prenume)).like(search_pattern),
                func.lower(unidecode(Student.id_unic_student)).like(search_pattern)
            ))
        students_query = students_query.order_by(Student.nume, Student.prenume)

    students_pagination = students_query.paginate(page=page, per_page=per_page, error_out=False)
    students_list = students_pagination.items

    return render_template('list_students.html',
                           students=students_list,
                           students_pagination=students_pagination,
                           is_admin_view=is_admin_view,
                           search_term=search_term,
                           filter_batalion=filter_batalion if is_admin_view else "",
                           filter_companie=filter_companie if is_admin_view else "",
                           filter_pluton=filter_pluton if is_admin_view else "",
                           batalioane=batalioane if is_admin_view else [],
                           companii=companii if is_admin_view else [],
                           plutoane=plutoane if is_admin_view else [],
                           title="Listă Studenți")

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
            db.session.commit()
            flash(f'Studentul {new_student.grad_militar} {new_student.nume} {new_student.prenume} a fost adăugat!', 'success')
            return redirect(url_for('list_students'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la salvarea studentului: {str(e)}', 'danger')
            return render_template('add_edit_student.html', form_title="Adăugare Student Nou", student=None, genders=GENDERS, form_data=request.form)

    return render_template('add_edit_student.html', form_title="Adăugare Student Nou", student=None, genders=GENDERS, form_data=None)

@app.route('/gradat/students/edit/<int:student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    if current_user.role != 'gradat':
        flash('Acces neautorizat.', 'danger')
        return redirect(url_for('home'))

    s_edit = Student.query.filter_by(id=student_id, created_by_user_id=current_user.id).first_or_404()

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
            return render_template('add_edit_student.html', form_title=f"Editare Student: {s_edit.grad_militar} {s_edit.nume}", student=s_edit, genders=GENDERS, form_data=request.form)

        if s_edit.gender not in GENDERS:
            flash('Valoare invalidă pentru gen.', 'warning')
            return render_template('add_edit_student.html', form_title=f"Editare Student: {s_edit.grad_militar} {s_edit.nume}", student=s_edit, genders=GENDERS, form_data=request.form)

        if new_id_unic and new_id_unic != s_edit.id_unic_student and Student.query.filter(Student.id_unic_student==new_id_unic, Student.id != s_edit.id).first():
            flash(f"Alt student cu ID unic '{new_id_unic}' există deja.", 'warning')
            return render_template('add_edit_student.html', form_title=f"Editare Student: {s_edit.grad_militar} {s_edit.nume}", student=s_edit, genders=GENDERS, form_data=request.form)

        s_edit.id_unic_student = new_id_unic

        try:
            db.session.commit()
            flash(f'Studentul {s_edit.grad_militar} {s_edit.nume} {s_edit.prenume} a fost actualizat!', 'success')
            return redirect(url_for('list_students'))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la actualizarea studentului: {str(e)}', 'danger')
            return render_template('add_edit_student.html', form_title=f"Editare Student: {s_edit.grad_militar} {s_edit.nume} {s_edit.prenume}", student=s_edit, genders=GENDERS, form_data=request.form)

    return render_template('add_edit_student.html', form_title=f"Editare Student: {s_edit.grad_militar} {s_edit.nume} {s_edit.prenume}", student=s_edit, genders=GENDERS, form_data=s_edit)

# Funcționalitatea 'Gradat Companie' a fost eliminată. Am șters ruta și funcția admin_toggle_company_grader_status.

@app.route('/gradat/delete_student/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if current_user.role not in ['admin', 'gradat']: flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    student_to_delete = Student.query.get_or_404(student_id)
    if current_user.role == 'gradat' and student_to_delete.created_by_user_id != current_user.id: flash('Nu puteți șterge studenți care nu vă sunt arondați.', 'danger'); return redirect(url_for('list_students'))
    if current_user.role == 'admin' and hasattr(student_to_delete, 'creator') and student_to_delete.creator and student_to_delete.creator.username != current_user.username : flash(f'Atenție: Ștergeți un student ({student_to_delete.nume} {student_to_delete.prenume}) care aparține gradatului {student_to_delete.creator.username}.', 'warning')
    try:
        student_name_for_flash = f"{student_to_delete.grad_militar} {student_to_delete.nume} {student_to_delete.prenume}"
        db.session.delete(student_to_delete); db.session.commit()
        flash(f'Studentul {student_name_for_flash} și toate datele asociate au fost șterse.', 'success')
    except Exception as e: db.session.rollback(); flash(f'Eroare la ștergerea studentului: {str(e)}', 'danger')
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

    now = datetime.now()
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
        student_id = request.form.get('student_id'); start_datetime_str = request.form.get('start_datetime'); end_datetime_str = request.form.get('end_datetime')
        reason = request.form.get('reason', '').strip()
        current_form_data_post = request.form
        if not student_id or not start_datetime_str or not end_datetime_str: flash('Studentul, data de început și data de sfârșit sunt obligatorii.', 'warning'); return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)
        try: start_dt = datetime.strptime(start_datetime_str, '%Y-%m-%dT%H:%M'); end_dt = datetime.strptime(end_datetime_str, '%Y-%m-%dT%H:%M')
        except ValueError: flash('Format dată/oră invalid.', 'danger'); return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)
        if end_dt <= start_dt: flash('Data de sfârșit trebuie să fie după data de început.', 'warning'); return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)
        student_to_check = Student.query.get(student_id)
        if student_to_check:
            conflicting_service = ServiceAssignment.query.filter(ServiceAssignment.student_id == student_id, ServiceAssignment.service_type == 'Intervenție', ServiceAssignment.start_datetime < end_dt, ServiceAssignment.end_datetime > start_dt).first()
            if conflicting_service: flash(f'Studentul {student_to_check.nume} {student_to_check.prenume} este în serviciu de "Intervenție" și nu poate primi permisie.', 'danger'); return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)

        general_conflict_msg = check_leave_conflict(student_id, start_dt, end_dt, 'permission', permission.id if permission else None)
        if general_conflict_msg:
            flash(f"Conflict detectat: Studentul are deja {general_conflict_msg}.", 'danger')
            return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)

        if permission:
            permission.student_id = int(student_id); permission.start_datetime = start_dt; permission.end_datetime = end_dt; permission.reason = reason
            flash('Permisie actualizată cu succes!', 'success')
        else:
            new_permission = Permission(student_id=int(student_id), start_datetime=start_dt, end_datetime=end_dt, reason=reason, status='Aprobată', created_by_user_id=current_user.id)
            db.session.add(new_permission); flash('Permisie adăugată cu succes!', 'success')
        try: db.session.commit()
        except Exception as e: db.session.rollback(); flash(f'Eroare la salvarea permisiei: {str(e)}', 'danger'); return render_template('add_edit_permission.html', form_title=form_title, permission=permission, students=students_managed, form_data=current_form_data_post)
        return redirect(url_for('list_permissions'))

    data_to_populate_form_with = {}
    if request.method == 'POST':
        data_to_populate_form_with = request.form
    elif permission:
        data_to_populate_form_with = {
            'student_id': str(permission.student_id),
            'start_datetime': permission.start_datetime.strftime('%Y-%m-%dT%H:%M') if permission.start_datetime else '',
            'end_datetime': permission.end_datetime.strftime('%Y-%m-%dT%H:%M') if permission.end_datetime else '',
            'reason': permission.reason or ''
        }
    else:
        data_to_populate_form_with = {}

    return render_template('add_edit_permission.html',
                           form_title=form_title,
                           permission=permission,
                           students=students_managed,
                           form_data=data_to_populate_form_with)

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

    try:
        db.session.delete(permission_to_delete)
        db.session.commit()
        flash(f'Permisia pentru {student_name_for_flash} ({permission_details_for_flash}) a fost ștearsă.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Eroare la ștergerea permisiei: {str(e)}', 'danger')

    return redirect(redirect_url)

# --- Rute pentru Învoiri Zilnice ---
@app.route('/gradat/daily_leaves')
@login_required
def list_daily_leaves():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    student_id_tuples = db.session.query(Student.id).filter_by(created_by_user_id=current_user.id).all()
    student_ids = [s[0] for s in student_id_tuples]
    today_string_for_form = date.today().strftime('%Y-%m-%d')
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
    form_title = "Adaugă Învoire Zilnică"; daily_leave = None; today_string = date.today().strftime('%Y-%m-%d')
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

@app.route('/gradat/daily_leaves/process_text', methods=['POST'])
@login_required
def process_daily_leaves_text():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    leave_list_text = request.form.get('leave_list_text'); apply_date_str = request.form.get('apply_date')
    if not leave_list_text or not apply_date_str: flash('Lista de învoiri și data de aplicare sunt obligatorii.', 'warning'); return redirect(url_for('list_daily_leaves'))
    try: apply_date_obj = datetime.strptime(apply_date_str, '%Y-%m-%d').date()
    except ValueError: flash('Format dată aplicare invalid.', 'danger'); return redirect(url_for('list_daily_leaves'))
    if apply_date_obj.weekday() > 3: flash('Învoirile din text pot fi aplicate doar pentru zile de Luni până Joi.', 'warning'); return redirect(url_for('list_daily_leaves'))

    lines = leave_list_text.strip().splitlines()
    students_managed_by_gradat = Student.query.filter_by(created_by_user_id=current_user.id).all()

    default_start_time_obj = time(15, 0) # Default start time if not specified in line
    default_end_time_obj = time(19, 0)   # Default end time if not specified in line

    processed_count, error_count, already_exists_count = 0,0,0
    not_found_or_ambiguous = []

    for line_raw in lines:
        line = line_raw.strip()
        if not line: continue

        parsed_name_norm, parsed_grad, line_start_time, line_end_time = parse_leave_line(line)

        if not parsed_name_norm:
            error_count +=1
            flash(f"Linie ignorată (format nume/student invalid): '{line_raw}'", "info")
            continue

        # Student matching logic (existing logic seems fine)
        matched_students = []
        for s in students_managed_by_gradat:
            s_name_norm = unidecode(f"{s.nume} {s.prenume}".lower())
            s_name_prenume_norm = unidecode(f"{s.prenume} {s.nume}".lower())
            name_match = (parsed_name_norm in s_name_norm) or \
                         (parsed_name_norm in s_name_prenume_norm) or \
                         (s_name_norm in parsed_name_norm) # Allow partial matches too

            grad_match = True # Assume grad matches if not specified in input line
            if parsed_grad:
                s_grad_norm = parsed_grad.lower().replace('.', '')
                db_s_grad_norm = s.grad_militar.lower().replace('.', '')
                grad_match = (s_grad_norm in db_s_grad_norm or db_s_grad_norm in s_grad_norm)

            if name_match and grad_match:
                matched_students.append(s)

        found_student = None
        if len(matched_students) == 1:
            found_student = matched_students[0]
        elif len(matched_students) > 1:
            not_found_or_ambiguous.append(f"{line_raw} (potriviri multiple: {', '.join([s.nume for s in matched_students])})")
            error_count += 1
            continue
        else:
            not_found_or_ambiguous.append(f"{line_raw} (student negăsit)")
            error_count += 1
            continue

        # Determine start and end times for the leave
        current_start_time = line_start_time if line_start_time else default_start_time_obj
        current_end_time = line_end_time if line_end_time else default_end_time_obj

        if line_start_time and not line_end_time: # If only start time is given, use default end time
            current_end_time = default_end_time_obj
            flash(f"Doar ora de început specificată pentru {found_student.nume} în '{line_raw}'. S-a folosit ora de sfârșit implicită ({default_end_time_obj.strftime('%H:%M')}).", "info")


        valid_schedule, validation_message = validate_daily_leave_times(current_start_time, current_end_time, apply_date_obj)
        if not valid_schedule:
            flash(f"Interval orar invalid pentru {found_student.nume} ({validation_message}). Încercare ignorată pentru '{line_raw}'.", "warning")
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
            flash(f'Studentul {found_student.nume} {found_student.prenume} este în "Intervenție". Învoire ignorată pentru '{line_raw}'.', 'warning')
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

    now = datetime.now()

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
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=date.today().isoformat(), form_data=current_form_data)

        try:
            service_date_obj = datetime.strptime(service_date_str, '%Y-%m-%d').date()
            start_time_obj = datetime.strptime(start_time_str, '%H:%M').time()
            end_time_obj = datetime.strptime(end_time_str, '%H:%M').time()
        except ValueError:
            flash('Format dată sau oră invalid.', 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=date.today().isoformat(), form_data=current_form_data)

        start_dt_obj = datetime.combine(service_date_obj, start_time_obj)
        effective_end_date = service_date_obj
        if end_time_obj < start_time_obj:
            effective_end_date += timedelta(days=1)
        end_dt_obj = datetime.combine(effective_end_date, end_time_obj)

        if end_dt_obj <= start_dt_obj:
            flash('Intervalul orar al serviciului este invalid (sfârșitul trebuie să fie după început).', 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=date.today().isoformat(), form_data=current_form_data)

        stud = Student.query.filter_by(id=student_id, created_by_user_id=current_user.id).first()
        if not stud:
            flash('Student selectat invalid sau nu vă aparține.', 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=date.today().isoformat(), form_data=current_form_data)

        conflict_msg = check_service_conflict_for_student(stud.id, start_dt_obj, end_dt_obj, service_type, assignment_id)
        if conflict_msg:
            flash(f"Conflict: studentul are deja {conflict_msg}", 'danger')
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=date.today().isoformat(), form_data=current_form_data)

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
            return render_template('assign_service.html', form_title=form_title, service_assignment=service_assignment, students=students, service_types=SERVICE_TYPES, default_times=default_times_for_js, today_str=date.today().isoformat(), form_data=current_form_data)

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
                           today_str=date.today().isoformat(),
                           form_data=data_to_populate_form_with)

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

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5001, debug=False)

[end of app.py]
