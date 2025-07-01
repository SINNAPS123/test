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
    if current_user.role != 'admin': flash('Acces neautorizat la panoul de administrare.', 'danger'); return redirect(url_for('dashboard'))
    total_users = User.query.count(); total_students = Student.query.count()
    return render_template('admin_dashboard.html', total_users=total_users, total_students=total_students)

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

# --- Management Studenți ---
@app.route('/gradat/students')
@app.route('/admin/students')
@login_required
def list_students():
    is_admin_view = current_user.role == 'admin' and request.path.startswith('/admin/')
    students_query = Student.query
    search_term = request.args.get('search', ''); filter_batalion = request.args.get('batalion', ''); filter_companie = request.args.get('companie', ''); filter_pluton = request.args.get('pluton', '')
    page = request.args.get('page', 1, type=int); per_page = 15
    all_students_for_filters = Student.query.all()
    batalioane = sorted(list(set(s.batalion for s in all_students_for_filters if s.batalion)))
    companii = sorted(list(set(s.companie for s in all_students_for_filters if s.companie)))
    plutoane = sorted(list(set(s.pluton for s in all_students_for_filters if s.pluton)))
    if is_admin_view:
        if search_term:
            search_pattern = f"%{unidecode(search_term.lower())}%"
            students_query = students_query.filter(or_(func.lower(unidecode(Student.nume)).like(search_pattern), func.lower(unidecode(Student.prenume)).like(search_pattern), func.lower(unidecode(Student.id_unic_student)).like(search_pattern)))
        if filter_batalion: students_query = students_query.filter(Student.batalion == filter_batalion)
        if filter_companie: students_query = students_query.filter(Student.companie == filter_companie)
        if filter_pluton: students_query = students_query.filter(Student.pluton == filter_pluton)
        students_pagination = students_query.order_by(Student.batalion, Student.companie, Student.pluton, Student.nume, Student.prenume).paginate(page=page, per_page=per_page, error_out=False)
        students_list = students_pagination.items
    else:
        if current_user.role != 'gradat': flash('Acces neautorizat pentru rolul curent.', 'danger'); return redirect(url_for('dashboard'))
        students_query = students_query.filter_by(created_by_user_id=current_user.id)
        if search_term:
            search_pattern = f"%{unidecode(search_term.lower())}%"
            students_query = students_query.filter(or_(func.lower(unidecode(Student.nume)).like(search_pattern), func.lower(unidecode(Student.prenume)).like(search_pattern), func.lower(unidecode(Student.id_unic_student)).like(search_pattern)))
        students_list = students_query.order_by(Student.nume, Student.prenume).all()
        students_pagination = None
    return render_template('list_students.html', students=students_list, students_pagination=students_pagination, is_admin_view=is_admin_view, search_term=search_term, filter_batalion=filter_batalion, filter_companie=filter_companie, filter_pluton=filter_pluton, batalioane=batalioane if is_admin_view else [], companii=companii if is_admin_view else [], plutoane=plutoane if is_admin_view else [], title="Listă Studenți", active_gradati_count=Student.query.filter_by(is_platoon_graded_duty=True).count() if is_admin_view else 0) # max_gradati_activi eliminat

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
            return render_template('add_edit_student.html', form_title=f"Editare Student: {s_edit.grad_militar} {s_edit.nume}", student=s_edit, genders=GENDERS, form_data=request.form)

    return render_template('add_edit_student.html', form_title=f"Editare Student: {s_edit.grad_militar} {s_edit.nume} {s_edit.prenume}", student=s_edit, genders=GENDERS, form_data=s_edit)

@app.route('/admin/student/toggle_company_grader/<int:student_id>', methods=['POST'])
@login_required
def admin_toggle_company_grader_status(student_id):
    if not current_user.role == 'admin': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    student = Student.query.get_or_404(student_id)
    flash("Funcționalitate 'Gradat Companie' eliminată/neimplementată.", "warning")
    return redirect(request.referrer or url_for('list_students'))

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
    student_ids_managed_by_gradat = db.session.query(Student.id).filter_by(created_by_user_id=current_user.id).scalar_all()
    if not student_ids_managed_by_gradat: return render_template('list_permissions.html', active_permissions=[], upcoming_permissions=[], past_permissions=[], title="Listă Permisii")
    now = datetime.now(); base_query = Permission.query.filter(Permission.student_id.in_(student_ids_managed_by_gradat))
    active_permissions = base_query.filter(Permission.status == 'Aprobată', Permission.start_datetime <= now, Permission.end_datetime >= now).order_by(Permission.start_datetime).all()
    upcoming_permissions = base_query.filter(Permission.status == 'Aprobată', Permission.start_datetime > now).order_by(Permission.start_datetime).all()
    active_upcoming_ids = [p.id for p in active_permissions] + [p.id for p in upcoming_permissions]
    past_or_cancelled_query = base_query
    if active_upcoming_ids: past_or_cancelled_query = past_or_cancelled_query.filter(Permission.id.notin_(active_upcoming_ids))
    past_permissions = past_or_cancelled_query.order_by(Permission.end_datetime.desc(), Permission.start_datetime.desc()).limit(30).all()
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
def delete_permission(permission_id): return "Delete Permission Placeholder"

# --- Rute pentru Învoiri Zilnice ---
@app.route('/gradat/daily_leaves')
@login_required
def list_daily_leaves():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    student_ids = db.session.query(Student.id).filter_by(created_by_user_id=current_user.id).scalar_all()
    today_string_for_form = date.today().strftime('%Y-%m-%d')
    if not student_ids: return render_template('list_daily_leaves.html', active_leaves=[], upcoming_leaves=[], past_leaves=[], title="Listă Învoiri Zilnice", today_str=today_string_for_form)
    all_relevant_leaves = DailyLeave.query.filter(DailyLeave.student_id.in_(student_ids)).order_by(DailyLeave.leave_date.desc(), DailyLeave.start_time.desc()).all()
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
        in_program_start, in_program_end = time(7,0), time(14,20); out_program_evening_start, out_program_morning_end = time(22,0), time(7,0)
        is_in_program = (in_program_start <= start_time_obj < in_program_end and in_program_start < end_time_obj <= in_program_end and start_time_obj < end_time_obj)
        is_out_program = ((start_time_obj >= out_program_evening_start or start_time_obj < out_program_morning_end) and (end_time_obj <= out_program_morning_end or end_time_obj > start_time_obj or start_time_obj > end_time_obj) and not (in_program_start <= start_time_obj < in_program_end and in_program_start < end_time_obj <= in_program_end) )
        if not (is_in_program or is_out_program): flash('Intervalul orar nu este valid. Permis: 07:00-14:20 sau 22:00-07:00 (poate trece în ziua următoare).', 'danger'); return render_template('add_edit_daily_leave.html', form_title=form_title, daily_leave=daily_leave, students=students_managed, today_str=today_string, form_data=current_form_data_post)
        start_dt = datetime.combine(leave_date_obj, start_time_obj); effective_end_date = leave_date_obj
        if end_time_obj < start_time_obj and is_out_program: effective_end_date += timedelta(days=1)
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
    parts = line_text.strip().split(); grad = None; time_str = None; normalized_name_search = None
    if not parts: return None, None, None
    if re.fullmatch(r"(\d{1,2}:\d{2})", parts[-1]): time_str = parts[-1]; name_parts = parts[:-1]
    else: name_parts = parts
    if not name_parts: return None, None, None
    student_name_str = " ".join(name_parts)
    for pattern in KNOWN_RANK_PATTERNS:
        match = pattern.match(student_name_str)
        if match: grad = match.group(0).strip(); student_name_str = pattern.sub("", student_name_str).strip(); break
    if student_name_str: normalized_name_search = unidecode(student_name_str.lower())
    return normalized_name_search, grad, time_str

@app.route('/gradat/daily_leaves/process_text', methods=['POST'])
@login_required
def process_daily_leaves_text():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    leave_list_text = request.form.get('leave_list_text'); apply_date_str = request.form.get('apply_date')
    if not leave_list_text or not apply_date_str: flash('Lista de învoiri și data de aplicare sunt obligatorii.', 'warning'); return redirect(url_for('list_daily_leaves'))
    try: apply_date_obj = datetime.strptime(apply_date_str, '%Y-%m-%d').date()
    except ValueError: flash('Format dată aplicare invalid.', 'danger'); return redirect(url_for('list_daily_leaves'))
    if apply_date_obj.weekday() > 3: flash('Învoirile din text pot fi aplicate doar pentru zile de Luni până Joi.', 'warning'); return redirect(url_for('list_daily_leaves'))
    lines = leave_list_text.strip().splitlines(); students_managed_by_gradat = Student.query.filter_by(created_by_user_id=current_user.id).all()
    default_start_time_obj = time(15, 0); default_end_time_obj = time(19, 0)
    processed_count, error_count, already_exists_count = 0,0,0; not_found_or_ambiguous = []
    for line_raw in lines:
        line = line_raw.strip();_ = _; __ = __
        if not line: continue
        parsed_name_norm, parsed_grad, parsed_time_str = parse_leave_line(line)
        if not parsed_name_norm: error_count +=1; flash(f"Linie ignorată (format nume invalid): '{line_raw}'", "info"); continue
        matched_students = []
        for s in students_managed_by_gradat:
            s_name_norm = unidecode(f"{s.nume} {s.prenume}".lower()); s_name_prenume_norm = unidecode(f"{s.prenume} {s.nume}".lower())
            name_match = (parsed_name_norm in s_name_norm) or (parsed_name_norm in s_name_prenume_norm) or (s_name_norm in parsed_name_norm)
            grad_match = True
            if parsed_grad: s_grad_norm = parsed_grad.lower().replace('.', ''); db_s_grad_norm = s.grad_militar.lower().replace('.', ''); grad_match = s_grad_norm in db_s_grad_norm or db_s_grad_norm in s_grad_norm
            if name_match and grad_match: matched_students.append(s)
        found_student = None
        if len(matched_students) == 1: found_student = matched_students[0]
        elif len(matched_students) > 1: not_found_or_ambiguous.append(f"{line_raw} (potriviri multiple)"); error_count += 1; continue
        else: not_found_or_ambiguous.append(f"{line_raw} (student negăsit)"); error_count += 1; continue
        current_start_time, current_end_time = default_start_time_obj, default_end_time_obj
        if parsed_time_str:
            try: current_end_time = datetime.strptime(parsed_time_str, '%H:%M').time()
            except ValueError: flash(f"Format oră invalid '{parsed_time_str}' pentru {found_student.nume}. Folosit interval default.", "warning")
        valid_schedule, _ = validate_daily_leave_times(current_start_time, current_end_time, apply_date_obj)
        if not valid_schedule: flash(f"Interval orar invalid pentru {found_student.nume}. Încercare ignorată.", "warning"); error_count +=1; continue
        start_dt_bulk = datetime.combine(apply_date_obj, current_start_time); effective_end_date_bulk = apply_date_obj
        if current_end_time < current_start_time : effective_end_date_bulk += timedelta(days=1)
        end_dt_bulk = datetime.combine(effective_end_date_bulk, current_end_time)
        active_intervention_service = ServiceAssignment.query.filter(ServiceAssignment.student_id == found_student.id, ServiceAssignment.service_type == 'Intervenție', ServiceAssignment.start_datetime < end_dt_bulk, ServiceAssignment.end_datetime > start_dt_bulk).first()
        if active_intervention_service: flash(f'Studentul {found_student.nume} e în "Intervenție". Învoire ignorată.', 'warning'); error_count += 1; continue
        existing_leave = DailyLeave.query.filter_by(student_id=found_student.id, leave_date=apply_date_obj, start_time=current_start_time, end_time=current_end_time, status='Aprobată').first()
        if existing_leave: already_exists_count +=1; continue
        new_leave = DailyLeave(student_id=found_student.id, leave_date=apply_date_obj, start_time=current_start_time, end_time=current_end_time, status='Aprobată', created_by_user_id=current_user.id, reason="Procesare text listă")
        db.session.add(new_leave); processed_count += 1
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
def delete_daily_leave(leave_id): return "Delete Daily Leave Placeholder"

# --- Rute pentru Învoiri Weekend ---
@app.route('/gradat/weekend_leaves')
@login_required
def list_weekend_leaves():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('dashboard'))
    student_ids = db.session.query(Student.id).filter_by(created_by_user_id=current_user.id).scalar_all()
    if not student_ids: return render_template('list_weekend_leaves.html', active_or_upcoming_leaves=[], past_leaves=[], title="Listă Învoiri Weekend")
    all_relevant_leaves = WeekendLeave.query.filter(WeekendLeave.student_id.in_(student_ids)).order_by(WeekendLeave.weekend_start_date.desc()).all()
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
        form_data_on_get['student_id'] = str(weekend_leave.student_id); form_data_on_get['weekend_start_date'] = weekend_leave.weekend_start_date.strftime('%Y-%m-%d')
        form_data_on_get['reason'] = weekend_leave.reason; selected_days_from_db = []
        day_names_ro = {0: "Luni", 1: "Marti", 2: "Miercuri", 3: "Joi", 4: "Vineri", 5: "Sambata", 6: "Duminica"}
        if weekend_leave.day1_date:
            day_name_ro1 = day_names_ro.get(weekend_leave.day1_date.weekday(), "Nespecificat"); selected_days_from_db.append(day_name_ro1)
            form_data_on_get[f'{day_name_ro1.lower()}_start_time'] = weekend_leave.day1_start_time.strftime('%H:%M') if weekend_leave.day1_start_time else ''
            form_data_on_get[f'{day_name_ro1.lower()}_end_time'] = weekend_leave.day1_end_time.strftime('%H:%M') if weekend_leave.day1_end_time else ''
        if weekend_leave.day2_date:
            day_name_ro2 = day_names_ro.get(weekend_leave.day2_date.weekday(), "Nespecificat")
            if day_name_ro2 not in selected_days_from_db : selected_days_from_db.append(day_name_ro2)
            form_data_on_get[f'{day_name_ro2.lower()}_start_time'] = weekend_leave.day2_start_time.strftime('%H:%M') if weekend_leave.day2_start_time else ''
            form_data_on_get[f'{day_name_ro2.lower()}_end_time'] = weekend_leave.day2_end_time.strftime('%H:%M') if weekend_leave.day2_end_time else ''
        form_data_on_get['selected_days[]'] = selected_days_from_db
    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    upcoming_fridays_list = get_upcoming_fridays()
    if request.method == 'POST':
        student_id = request.form.get('student_id'); weekend_start_date_str = request.form.get('weekend_start_date'); selected_days = request.form.getlist('selected_days[]')
        reason = request.form.get('reason', '').strip()
        current_form_data_post = request.form
        if not student_id or not weekend_start_date_str: flash('Studentul și data de început a weekendului (Vineri) sunt obligatorii.', 'warning'); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
        if not selected_days or len(selected_days) > 2: flash('Trebuie să selectați 1 sau 2 zile din weekend.', 'warning'); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
        try: friday_date_obj = datetime.strptime(weekend_start_date_str, '%Y-%m-%d').date()
        except ValueError: flash('Format dată weekend invalid.', 'danger'); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
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
            weekend_leave.day1_selected = None; weekend_leave.day1_date = None; weekend_leave.day1_start_time = None; weekend_leave.day1_end_time = None
            weekend_leave.day2_selected = None; weekend_leave.day2_date = None; weekend_leave.day2_start_time = None; weekend_leave.day2_end_time = None
            target_leave = weekend_leave; flash_msg = 'Învoire Weekend actualizată!'
        else: target_leave = WeekendLeave(created_by_user_id=current_user.id, status='Aprobată'); flash_msg = 'Învoire Weekend adăugată!'
        target_leave.student_id = int(student_id); target_leave.weekend_start_date = friday_date_obj; target_leave.reason = reason
        if len(day_data) >= 1: target_leave.day1_selected = day_data[0]['name']; target_leave.day1_date = day_data[0]['date']; target_leave.day1_start_time = day_data[0]['start']; target_leave.day1_end_time = day_data[0]['end']
        if len(day_data) == 2: target_leave.day2_selected = day_data[1]['name']; target_leave.day2_date = day_data[1]['date']; target_leave.day2_start_time = day_data[1]['start']; target_leave.day2_end_time = day_data[1]['end']
        if not weekend_leave: db.session.add(target_leave)
        try: db.session.commit(); flash(flash_msg, 'success')
        except Exception as e: db.session.rollback(); flash(f'Eroare la salvarea învoirii de weekend: {str(e)}', 'danger'); return render_template('add_edit_weekend_leave.html', form_title=form_title, weekend_leave=weekend_leave, students=students_managed, upcoming_weekends=upcoming_fridays_list, form_data=current_form_data_post)
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
def delete_weekend_leave(leave_id): return "Delete Weekend Leave Placeholder"

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

    upcoming_services = ServiceAssignment.query.filter(
                            ServiceAssignment.student_id.in_(student_ids),
                            ServiceAssignment.end_datetime >= now
                        ).order_by(ServiceAssignment.start_datetime.asc()).all()

    past_services = ServiceAssignment.query.filter(
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
    # ... (cod existent)
    return "Text Report Display Company Placeholder" # Placeholder

@app.route('/battalion_commander/report/text', methods=['GET'])
@login_required
def text_report_display_battalion():
    # ... (cod existent)
    return "Text Report Display Battalion Placeholder" # Placeholder

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5001, debug=False)

[end of app.py]
