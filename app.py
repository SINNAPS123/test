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
    pluton = db.Column(db.String(50), nullable=False) # Stocat ca string, ex: "1", "2"
    companie = db.Column(db.String(50), nullable=False) # Stocat ca string, ex: "1", "2"
    batalion = db.Column(db.String(50), nullable=False) # Stocat ca string, ex: "1", "2"
    gender = db.Column(db.String(10), default='Nespecificat', nullable=False)
    volunteer_points = db.Column(db.Integer, default=0, nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('students_created', lazy=True))
    def __repr__(self): return f'<Student {self.grad_militar} {self.nume} {self.prenume} - Pluton {self.pluton}>'

# ... (celelalte modele rămân la fel: Permission, DailyLeave, WeekendLeave, VolunteerActivity, ActivityParticipant, ServiceAssignment) ...
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
        if self.status != 'Aprobată': return False; now = datetime.now()
        return any(interval["end"] >= now for interval in self.get_intervals())
    @property
    def is_any_interval_active_now(self):
        if self.status != 'Aprobată': return False; now = datetime.now()
        return any(interval["start"] <= now <= interval["end"] for interval in self.get_intervals())
    @property
    def is_overall_past(self): return True if self.status == 'Anulată' else not self.is_overall_active_or_upcoming
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

# --- Funcții Helper pentru Conflicte și Prezență ---
# ... (get_student_status, check_leave_conflict, check_service_conflict_for_student rămân la fel) ...
def get_student_status(student, datetime_check):
    # 1. Verifică Servicii
    active_service = ServiceAssignment.query.filter(
        ServiceAssignment.student_id == student.id,
        ServiceAssignment.start_datetime <= datetime_check,
        ServiceAssignment.end_datetime >= datetime_check
    ).order_by(ServiceAssignment.start_datetime).first()
    if active_service:
        return {
            "status_code": "absent_service",
            "reason": f"Serviciu ({active_service.service_type})",
            "until": active_service.end_datetime,
            "details": f"Serviciu: {active_service.service_type}",
            "object": active_service
        }
    # 2. Verifică Permisii
    active_permission = Permission.query.filter(
        Permission.student_id == student.id, Permission.status == 'Aprobată',
        Permission.start_datetime <= datetime_check, Permission.end_datetime >= datetime_check
    ).order_by(Permission.start_datetime).first()
    if active_permission:
        return {
            "status_code": "absent_permission", "reason": "Permisie", "until": active_permission.end_datetime,
            "details": "Permisie", "object": active_permission
        }
    # 3. Verifică Învoiri Weekend
    weekend_leaves = WeekendLeave.query.filter(WeekendLeave.student_id == student.id, WeekendLeave.status == 'Aprobată').all()
    for wl in weekend_leaves:
        for interval in wl.get_intervals():
            if interval['start'] <= datetime_check <= interval['end']:
                return {
                    "status_code": "absent_weekend_leave", "reason": f"Învoire Weekend ({interval['day_name']})",
                    "until": interval['end'], "details": f"Învoire Weekend: {interval['day_name']}", "object": wl
                }
    # 4. Verifică Învoiri Zilnice
    daily_leaves = DailyLeave.query.filter(DailyLeave.student_id == student.id, DailyLeave.status == 'Aprobată').all()
    for dl in daily_leaves:
        if dl.start_datetime <= datetime_check <= dl.end_datetime:
             return {
                "status_code": "absent_daily_leave", "reason": f"Învoire Zilnică ({dl.leave_type_display})",
                "until": dl.end_datetime, "details": f"Învoire Zilnică: {dl.leave_type_display}", "object": dl
            }
    return {"status_code": "present", "reason": "Prezent", "until": None, "details": "Prezent", "object": None}

def check_leave_conflict(student_id, leave_start_dt, leave_end_dt, existing_leave_id=None, leave_type=None):
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
    if query_permissions.count() > (1 if leave_type == 'permission' and existing_leave_id else 0) : return "o permisie existentă"

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
@app.route('/')
def home(): return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin': return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'gradat': return redirect(url_for('gradat_dashboard'))
    elif current_user.role == 'comandant_companie': return redirect(url_for('company_commander_dashboard'))
    elif current_user.role == 'comandant_batalion': return redirect(url_for('battalion_commander_dashboard'))
    return render_template('dashboard.html', name=current_user.username) # Fallback

@app.route('/logout')
@login_required
def logout(): logout_user(); flash('Ai fost deconectat.', 'success'); return redirect(url_for('home'))

# --- Autentificare Admin ---
# ... (Rutele admin rămân la fel) ...
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
    return render_template('admin_dashboard.html', users=User.query.filter(User.role != 'admin').all())

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

# --- Autentificare Utilizator ---
# ... (Rutele de login utilizator rămân la fel) ...
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
# ... (Rutele gradat rămân la fel) ...
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

# --- Management Studenți (include gender) ---
@app.route('/gradat/students')
@login_required
def list_students():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    return render_template('list_students.html', students=Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume, Student.prenume).all())

@app.route('/gradat/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    if request.method == 'POST':
        form = request.form
        if not all([form.get(k) for k in ['nume', 'prenume', 'grad_militar', 'pluton', 'companie', 'batalion', 'gender']]): flash('Toate câmpurile marcate cu * sunt obligatorii (inclusiv genul).', 'warning')
        elif form.get('id_unic_student') and Student.query.filter_by(id_unic_student=form.get('id_unic_student')).first(): flash(f"ID unic '{form.get('id_unic_student')}' există deja.", 'warning')
        elif form.get('gender') not in GENDERS : flash('Valoare invalidă pentru gen.', 'warning')
        else:
            s = Student(nume=form.get('nume'), prenume=form.get('prenume'), grad_militar=form.get('grad_militar'),
                        id_unic_student=form.get('id_unic_student') or None,
                        pluton=form.get('pluton'), companie=form.get('companie'), batalion=form.get('batalion'),
                        gender=form.get('gender'), created_by_user_id=current_user.id)
            db.session.add(s); db.session.commit(); flash(f'Studentul {s.grad_militar} {s.nume} {s.prenume} a fost adăugat!', 'success'); return redirect(url_for('list_students'))
    return render_template('add_edit_student.html', form_title="Adăugare Student Nou", student=None, genders=GENDERS)

@app.route('/gradat/students/edit/<int:student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    s_edit = Student.query.filter_by(id=student_id, created_by_user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        form = request.form
        s_edit.nume, s_edit.prenume, s_edit.grad_militar, s_edit.pluton, s_edit.companie, s_edit.batalion = form.get('nume'), form.get('prenume'), form.get('grad_militar'), form.get('pluton'), form.get('companie'), form.get('batalion')
        s_edit.gender = form.get('gender')
        new_id_unic = form.get('id_unic_student')
        if not all([s_edit.nume, s_edit.prenume, s_edit.grad_militar, s_edit.pluton, s_edit.companie, s_edit.batalion, s_edit.gender]): flash('Toate câmpurile marcate cu * sunt obligatorii (inclusiv genul).', 'warning')
        elif s_edit.gender not in GENDERS: flash('Valoare invalidă pentru gen.', 'warning')
        else:
            if new_id_unic and new_id_unic != s_edit.id_unic_student and Student.query.filter(Student.id_unic_student==new_id_unic, Student.id != s_edit.id).first():
                flash(f"Alt student cu ID unic '{new_id_unic}' există deja.", 'warning'); return render_template('add_edit_student.html', form_title="Editare Student", student=s_edit, genders=GENDERS)
            s_edit.id_unic_student = new_id_unic or None; db.session.commit()
            flash(f'Studentul {s_edit.grad_militar} {s_edit.nume} {s_edit.prenume} a fost actualizat!', 'success'); return redirect(url_for('list_students'))
    return render_template('add_edit_student.html', form_title="Editare Student", student=s_edit, genders=GENDERS)

@app.route('/gradat/students/delete/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    s_del = Student.query.filter_by(id=student_id, created_by_user_id=current_user.id).first_or_404()
    msg = f'Studentul {s_del.grad_militar} {s_del.nume} {s_del.prenume} și înregistrările asociate au fost șterse.'
    db.session.delete(s_del); db.session.commit(); flash(msg, 'success'); return redirect(url_for('list_students'))

# --- Management Permisii, Învoiri (cu verificări de conflict adăugate) ---
@app.route('/gradat/permissions/add', methods=['GET', 'POST'])
@login_required
def add_permission():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    if not students: flash('Nu aveți studenți. Adăugați întâi studenți.', 'warning'); return redirect(url_for('list_students'))
    if request.method == 'POST':
        form = request.form
        s_id, s_dt_str, e_dt_str = form.get('student_id'), form.get('start_datetime'), form.get('end_datetime')
        if not s_id or not s_dt_str or not e_dt_str: flash('Studentul și datele de început/sfârșit sunt obligatorii.', 'warning')
        else:
            try:
                s_dt, e_dt = datetime.strptime(s_dt_str, '%Y-%m-%dT%H:%M'), datetime.strptime(e_dt_str, '%Y-%m-%dT%H:%M')
                if e_dt <= s_dt: flash('Data de sfârșit trebuie să fie după data de început.', 'warning')
                else:
                    stud = Student.query.filter_by(id=s_id, created_by_user_id=current_user.id).first()
                    if not stud: flash('Student invalid.', 'danger'); return redirect(url_for('list_permissions'))
                    conflict_msg = check_leave_conflict(stud.id, s_dt, e_dt, leave_type='permission')
                    if conflict_msg: flash(f"Conflict: studentul are deja {conflict_msg}", 'danger'); return render_template('add_edit_permission.html', form_title="Adăugare Permisie Nouă", permission=None, students=students, form_data=form)
                    p = Permission(student_id=s_id, start_datetime=s_dt, end_datetime=e_dt, reason=form.get('reason'), created_by_user_id=current_user.id)
                    db.session.add(p); db.session.commit(); flash(f'Permisie adăugată pentru {stud.nume}!', 'success'); return redirect(url_for('list_permissions'))
            except ValueError: flash('Format dată/oră invalid.', 'danger')
    return render_template('add_edit_permission.html', form_title="Adăugare Permisie Nouă", permission=None, students=students, form_data=request.form if request.method == 'POST' else None)

@app.route('/gradat/daily_leaves/add', methods=['GET', 'POST'])
@login_required
def add_daily_leave():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    if not students: flash('Nu aveți studenți pentru a adăuga învoiri.', 'warning'); return redirect(url_for('list_students'))
    if request.method == 'POST':
        form = request.form
        s_id, l_date_str, s_time_str, e_time_str = form.get('student_id'), form.get('leave_date'), form.get('start_time'), form.get('end_time')
        if not all([s_id, l_date_str, s_time_str, e_time_str]): flash('Studentul, data și orele sunt obligatorii.', 'warning')
        else:
            try:
                l_date_obj, s_time_obj, e_time_obj = datetime.strptime(l_date_str, '%Y-%m-%d').date(), datetime.strptime(s_time_str, '%H:%M').time(), datetime.strptime(e_time_str, '%H:%M').time()
                is_valid, msg = validate_daily_leave_times(s_time_obj, e_time_obj, l_date_obj)
                if not is_valid: flash(msg, 'danger')
                else:
                    stud = Student.query.filter_by(id=s_id, created_by_user_id=current_user.id).first()
                    if not stud: flash('Student invalid.', 'danger'); return redirect(url_for('list_daily_leaves'))
                    leave_start_dt = datetime.combine(l_date_obj, s_time_obj)
                    effective_end_date = l_date_obj
                    if e_time_obj < s_time_obj: effective_end_date += timedelta(days=1)
                    leave_end_dt = datetime.combine(effective_end_date, e_time_obj)
                    conflict_msg = check_leave_conflict(stud.id, leave_start_dt, leave_end_dt, leave_type='daily_leave')
                    if conflict_msg: flash(f"Conflict: studentul are deja {conflict_msg}", 'danger'); return render_template('add_edit_daily_leave.html', form_title="Adăugare Învoire Zilnică", daily_leave=None, students=students, today_str=date.today().isoformat(), form_data=form)
                    new_leave = DailyLeave(student_id=s_id, leave_date=l_date_obj, start_time=s_time_obj, end_time=e_time_obj, reason=form.get('reason'), created_by_user_id=current_user.id)
                    db.session.add(new_leave); db.session.commit(); flash(f'Învoire zilnică adăugată pentru {stud.nume}!', 'success'); return redirect(url_for('list_daily_leaves'))
            except ValueError: flash('Format dată/oră invalid.', 'danger')
    return render_template('add_edit_daily_leave.html', form_title="Adăugare Învoire Zilnică", daily_leave=None, students=students, today_str=date.today().isoformat(), form_data=request.form if request.method == 'POST' else None)

@app.route('/gradat/weekend_leaves/add', methods=['GET', 'POST'])
@login_required
def add_weekend_leave():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    if not students: flash('Nu aveți studenți.', 'warning'); return redirect(url_for('list_students'))
    upcoming_weekends = [{"value": (get_next_friday() + timedelta(weeks=i)).isoformat(), "text": f"Weekend {(get_next_friday() + timedelta(weeks=i)).strftime('%d.%m.%Y')} - {(get_next_friday() + timedelta(weeks=i, days=2)).strftime('%d.%m.%Y')}"} for i in range(4)]
    if request.method == 'POST':
        form = request.form; student_id, weekend_start_date_str, selected_days = form.get('student_id'), form.get('weekend_start_date'), request.form.getlist('selected_days[]')
        d1_s_str, d1_e_str, d2_s_str, d2_e_str = form.get('day1_start_time'), form.get('day1_end_time'), form.get('day2_start_time'), form.get('day2_end_time')
        if not student_id or not weekend_start_date_str: flash('Studentul și weekendul sunt obligatorii.', 'warning')
        elif not selected_days: flash('Selectați cel puțin o zi.', 'warning')
        elif len(selected_days) > 2: flash('Maxim două zile.', 'warning')
        else:
            try:
                wknd_friday = datetime.strptime(weekend_start_date_str, '%Y-%m-%d').date()
                if wknd_friday.weekday() != 4: flash('Weekendul trebuie să înceapă Vineri.', 'danger')
                else:
                    stud = Student.query.filter_by(id=student_id, created_by_user_id=current_user.id).first()
                    if not stud: flash('Student invalid.', 'danger'); return redirect(url_for('list_weekend_leaves'))
                    day_map = {'Vineri': 0, 'Sambata': 1, 'Duminica': 2}
                    processed_intervals = [] # Va stoca {'name', 'date', 'start_time_obj', 'end_time_obj'}

                    # Validare și procesare Ziua 1
                    if selected_days:
                        day1_name = selected_days[0]
                        day1_date_obj = wknd_friday + timedelta(days=day_map[day1_name])
                        day1_start_obj = datetime.strptime(d1_s_str, '%H:%M').time() if d1_s_str else None
                        day1_end_obj = datetime.strptime(d1_e_str, '%H:%M').time() if d1_e_str else None
                        if not day1_start_obj or not day1_end_obj: flash(f'Orele pentru {day1_name} sunt obligatorii.', 'warning'); raise ValueError(f"Missing time for {day1_name}")
                        if day1_end_obj <= day1_start_obj and not (day1_start_obj.hour >= 20 and day1_end_obj.hour <=9): flash(f'Interval orar invalid pentru {day1_name}.', 'warning'); raise ValueError(f"Invalid time for {day1_name}")

                        s_dt1 = datetime.combine(day1_date_obj, day1_start_obj)
                        e_dt1 = datetime.combine(day1_date_obj, day1_end_obj)
                        if e_dt1 < s_dt1: e_dt1 += timedelta(days=1)
                        conflict_msg1 = check_leave_conflict(stud.id, s_dt1, e_dt1, leave_type='weekend_leave')
                        if conflict_msg1: flash(f"Conflict {day1_name}: studentul are deja {conflict_msg1}", 'danger'); raise ValueError(f"Conflict {day1_name}")
                        processed_intervals.append({'name': day1_name, 'date': day1_date_obj, 'start': day1_start_obj, 'end': day1_end_obj})

                    # Validare și procesare Ziua 2
                    if len(selected_days) == 2:
                        day2_name = selected_days[1]
                        if day1_name == day2_name: flash('Nu selectați aceeași zi de două ori.', 'warning'); raise ValueError("Duplicate day selection")
                        day2_date_obj = wknd_friday + timedelta(days=day_map[day2_name])
                        day2_start_obj = datetime.strptime(d2_s_str, '%H:%M').time() if d2_s_str else None
                        day2_end_obj = datetime.strptime(d2_e_str, '%H:%M').time() if d2_e_str else None
                        if not day2_start_obj or not day2_end_obj: flash(f'Orele pentru {day2_name} sunt obligatorii.', 'warning'); raise ValueError(f"Missing time for {day2_name}")
                        if day2_end_obj <= day2_start_obj and not (day2_start_obj.hour >= 20 and day2_end_obj.hour <=9): flash(f'Interval orar invalid pentru {day2_name}.', 'warning'); raise ValueError(f"Invalid time for {day2_name}")

                        s_dt2 = datetime.combine(day2_date_obj, day2_start_obj)
                        e_dt2 = datetime.combine(day2_date_obj, day2_end_obj)
                        if e_dt2 < s_dt2: e_dt2 += timedelta(days=1)
                        conflict_msg2 = check_leave_conflict(stud.id, s_dt2, e_dt2, leave_type='weekend_leave')
                        if conflict_msg2: flash(f"Conflict {day2_name}: studentul are deja {conflict_msg2}", 'danger'); raise ValueError(f"Conflict {day2_name}")
                        processed_intervals.append({'name': day2_name, 'date': day2_date_obj, 'start': day2_start_obj, 'end': day2_end_obj})

                    # Creare înregistrare WeekendLeave
                    leave = WeekendLeave(student_id=student_id, weekend_start_date=wknd_friday, reason=form.get('reason'), created_by_user_id=current_user.id)
                    if processed_intervals:
                        leave.day1_selected = processed_intervals[0]['name']
                        leave.day1_date = processed_intervals[0]['date']
                        leave.day1_start_time = processed_intervals[0]['start']
                        leave.day1_end_time = processed_intervals[0]['end']
                    if len(processed_intervals) == 2:
                        leave.day2_selected = processed_intervals[1]['name']
                        leave.day2_date = processed_intervals[1]['date']
                        leave.day2_start_time = processed_intervals[1]['start']
                        leave.day2_end_time = processed_intervals[1]['end']

                    db.session.add(leave); db.session.commit(); flash(f'Învoire de weekend adăugată pentru {stud.nume}!', 'success'); return redirect(url_for('list_weekend_leaves'))
            except ValueError as e:
                if str(e).startswith("Conflict") or "time" in str(e) or "day" in str(e) : pass
                else: flash(str(e) or 'Format dată/oră invalid sau altă problemă de validare.', 'danger')
    return render_template('add_edit_weekend_leave.html', form_title="Adăugare Învoire Weekend", students=students, upcoming_weekends=upcoming_weekends, form_data=request.form if request.method == 'POST' else None)


# --- Rutele de listare și anulare pentru Permisii, Învoiri Zilnice, Învoiri Weekend rămân la fel ---
@app.route('/gradat/permissions')
@login_required
def list_permissions():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    perms_q = Permission.query.join(Student).filter(Permission.created_by_user_id == current_user.id, Student.id == Permission.student_id).order_by(Permission.start_datetime.desc())
    active_p = [p for p in perms_q if p.is_active]; upcoming_p = [p for p in perms_q if p.is_upcoming]; past_p = [p for p in perms_q if p.is_past]
    return render_template('list_permissions.html', active_permissions=active_p, upcoming_permissions=upcoming_p, past_permissions=past_p, now=datetime.now())

@app.route('/gradat/permissions/cancel/<int:permission_id>', methods=['POST'])
@login_required
def cancel_permission(permission_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    p_cancel = Permission.query.join(Student).filter(Permission.id == permission_id, Permission.created_by_user_id == current_user.id, Student.id == Permission.student_id).first_or_404()
    if p_cancel.status == 'Anulată': flash('Permisia este deja anulată.', 'info')
    elif p_cancel.end_datetime < datetime.now(): flash('Nu se poate anula o permisie expirată.', 'warning'); p_cancel.status = 'Expirată'; db.session.commit()
    else: p_cancel.status = 'Anulată'; db.session.commit(); flash(f'Permisia pentru {p_cancel.student.nume} a fost anulată.', 'success')
    return redirect(url_for('list_permissions'))

@app.route('/gradat/daily_leaves')
@login_required
def list_daily_leaves():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    leaves_q = DailyLeave.query.join(Student).filter(DailyLeave.created_by_user_id == current_user.id, Student.id == DailyLeave.student_id).order_by(DailyLeave.leave_date.desc(), DailyLeave.start_time.desc())
    active_l = [l for l in leaves_q if l.is_active]; upcoming_l = [l for l in leaves_q if l.is_upcoming]; past_l = [l for l in leaves_q if l.is_past]
    return render_template('list_daily_leaves.html', active_leaves=active_l, upcoming_leaves=upcoming_l, past_leaves=past_l)

@app.route('/gradat/daily_leaves/cancel/<int:leave_id>', methods=['POST'])
@login_required
def cancel_daily_leave(leave_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    l_cancel = DailyLeave.query.join(Student).filter(DailyLeave.id == leave_id, DailyLeave.created_by_user_id == current_user.id, Student.id == DailyLeave.student_id).first_or_404()
    if l_cancel.status == 'Anulată': flash('Învoirea este deja anulată.', 'info')
    elif l_cancel.end_datetime < datetime.now(): flash('Nu se poate anula o învoire expirată.', 'warning'); l_cancel.status = 'Expirată'; db.session.commit()
    else: l_cancel.status = 'Anulată'; db.session.commit(); flash(f'Învoirea pentru {l_cancel.student.nume} din {l_cancel.leave_date.strftime("%d-%m-%Y")} a fost anulată.', 'success')
    return redirect(url_for('list_daily_leaves'))

@app.route('/gradat/weekend_leaves')
@login_required
def list_weekend_leaves():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    leaves_q = WeekendLeave.query.join(Student).filter(WeekendLeave.created_by_user_id == current_user.id, Student.id == WeekendLeave.student_id).order_by(WeekendLeave.weekend_start_date.desc())
    active_or_upcoming_leaves = [l for l in leaves_q if l.is_overall_active_or_upcoming]; past_leaves = [l for l in leaves_q if l.is_overall_past and l not in active_or_upcoming_leaves]
    return render_template('list_weekend_leaves.html', active_or_upcoming_leaves=active_or_upcoming_leaves,past_leaves=past_leaves)

@app.route('/gradat/weekend_leaves/cancel/<int:leave_id>', methods=['POST'])
@login_required
def cancel_weekend_leave(leave_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    l_cancel = WeekendLeave.query.join(Student).filter(WeekendLeave.id == leave_id, WeekendLeave.created_by_user_id == current_user.id, Student.id == WeekendLeave.student_id).first_or_404()
    if l_cancel.status == 'Anulată': flash('Învoirea este deja anulată.', 'info')
    elif not l_cancel.is_overall_active_or_upcoming: flash('Nu se poate anula o învoire expirată.', 'warning');
    else: l_cancel.status = 'Anulată'; db.session.commit(); flash(f'Învoirea de weekend pentru {l_cancel.student.nume} a fost anulată.', 'success')
    return redirect(url_for('list_weekend_leaves'))

# --- Management Voluntariate ---
# ... (Rutele voluntariate rămân la fel) ...
@app.route('/gradat/volunteer', methods=['GET', 'POST'])
@login_required
def volunteer_home():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    if request.method == 'POST':
        name, description, activity_date_str = request.form.get('activity_name'), request.form.get('activity_description'), request.form.get('activity_date')
        if not name or not activity_date_str: flash('Numele activității și data sunt obligatorii.', 'warning')
        else:
            try:
                new_activity = VolunteerActivity(name=name, description=description, activity_date=datetime.strptime(activity_date_str, '%Y-%m-%d').date(), created_by_user_id=current_user.id)
                db.session.add(new_activity); db.session.commit(); flash(f'Activitatea "{name}" a fost creată.', 'success'); return redirect(url_for('volunteer_activity_details', activity_id=new_activity.id))
            except ValueError: flash('Format dată invalid.', 'danger')
    activities = VolunteerActivity.query.filter_by(created_by_user_id=current_user.id).order_by(VolunteerActivity.activity_date.desc()).all()
    students_with_points = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.volunteer_points.desc(), Student.nume).all()
    return render_template('volunteer_home.html', activities=activities, students_with_points=students_with_points, today_str=date.today().isoformat())

@app.route('/gradat/volunteer/activity/<int:activity_id>', methods=['GET', 'POST'])
@login_required
def volunteer_activity_details(activity_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    activity = VolunteerActivity.query.filter_by(id=activity_id, created_by_user_id=current_user.id).first_or_404()
    students_managed = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_participants':
            selected_ids = {int(sid) for sid in request.form.getlist('participant_ids[]')}
            current_ids = {p.student_id for p in activity.participants}
            to_add = selected_ids - current_ids; to_remove = current_ids - selected_ids
            for sid in to_remove:
                p_obj = ActivityParticipant.query.filter_by(activity_id=activity.id, student_id=sid).first()
                if p_obj: stud = Student.query.get(sid); stud.volunteer_points = max(0, stud.volunteer_points - p_obj.points_awarded); db.session.delete(p_obj)
            for sid in to_add:
                if Student.query.filter_by(id=sid, created_by_user_id=current_user.id).first(): db.session.add(ActivityParticipant(activity_id=activity.id, student_id=sid))
            db.session.commit(); flash('Participanți actualizați.', 'success')
        elif action == 'award_points':
            points_str, p_ids = request.form.get('points_to_award'), request.form.getlist('points_participant_ids[]')
            if not points_str or not p_ids: flash('Selectează participanții și punctele.', 'warning')
            else:
                try:
                    points = int(points_str)
                    if points < 0: flash('Punctele nu pot fi negative.', 'warning')
                    else:
                        updated = 0
                        for pid_str in p_ids:
                            p_obj = ActivityParticipant.query.filter_by(activity_id=activity.id, student_id=int(pid_str)).first()
                            if p_obj and p_obj.student.creator == current_user:
                                p_obj.student.volunteer_points = max(0, p_obj.student.volunteer_points - p_obj.points_awarded) + points
                                p_obj.points_awarded = points; updated += 1
                        db.session.commit()
                        if updated: flash(f'{updated} participant(i) au primit {points} puncte.', 'success')
                        else: flash('Nu s-au acordat puncte.', 'info')
                except ValueError: flash('Punctele trebuie să fie un număr.', 'danger')
        return redirect(url_for('volunteer_activity_details', activity_id=activity.id))
    current_participant_ids = {p.student_id for p in activity.participants}
    activity_participants_detailed = db.session.query(ActivityParticipant, Student).join(Student, ActivityParticipant.student_id == Student.id).filter(ActivityParticipant.activity_id == activity.id, Student.created_by_user_id == current_user.id).all()
    return render_template('volunteer_activity_details.html', activity=activity, students_managed=students_managed, current_participant_ids=current_participant_ids, activity_participants_detailed=activity_participants_detailed)

@app.route('/gradat/volunteer/generate_students', methods=['GET', 'POST'])
@login_required
def volunteer_generate_students():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    gen_studs, num_req, ex_girls = None, 0, False
    if request.method == 'POST':
        try:
            num_req = int(request.form.get('num_students', 0)); ex_girls = 'exclude_girls' in request.form
            if num_req <= 0: flash('Numărul de studenți trebuie să fie pozitiv.', 'warning')
            else:
                q = Student.query.filter_by(created_by_user_id=current_user.id)
                if ex_girls: q = q.filter(Student.gender != 'F')
                gen_studs = q.order_by(Student.volunteer_points.asc(), func.random()).limit(num_req).all()
                if not gen_studs: flash('Nu s-au găsit studenți conform criteriilor.', 'info')
        except ValueError: flash('Numărul de studenți trebuie să fie un număr.', 'danger')
    return render_template('volunteer_generate_students.html', generated_students=gen_studs, num_students_requested=num_req, exclude_girls_opt=ex_girls)

# --- Management Servicii ---
@app.route('/gradat/services')
@login_required
def list_services():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    today = date.today()
    upcoming_services = ServiceAssignment.query.join(Student).filter(ServiceAssignment.created_by_user_id == current_user.id,ServiceAssignment.end_datetime >= datetime.combine(today, time.min)).order_by(ServiceAssignment.start_datetime.asc()).all()
    past_services = ServiceAssignment.query.join(Student).filter(ServiceAssignment.created_by_user_id == current_user.id, ServiceAssignment.end_datetime < datetime.combine(today, time.min)).order_by(ServiceAssignment.start_datetime.desc()).limit(20).all()
    return render_template('list_services.html', upcoming_services=upcoming_services, past_services=past_services, service_types=SERVICE_TYPES)

@app.route('/gradat/services/assign', methods=['GET', 'POST'])
@login_required
def assign_service():
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    students = Student.query.filter_by(created_by_user_id=current_user.id).order_by(Student.nume).all()
    if not students: flash('Nu aveți studenți pentru a le asigna servicii.', 'warning'); return redirect(url_for('list_students'))
    if request.method == 'POST':
        form = request.form
        s_id, s_type, s_date_str, s_time_str, e_time_str = form.get('student_id'), form.get('service_type'), form.get('service_date'), form.get('start_time'), form.get('end_time')
        participates, notes = 'participates_in_roll_call' in form, form.get('notes')
        if not all([s_id, s_type, s_date_str, s_time_str, e_time_str]): flash('Toate câmpurile marcate * sunt obligatorii.', 'warning')
        else:
            try:
                s_date_obj, s_time_obj, e_time_obj = datetime.strptime(s_date_str, '%Y-%m-%d').date(), datetime.strptime(s_time_str, '%H:%M').time(), datetime.strptime(e_time_str, '%H:%M').time()
                s_dt_obj, e_dt_obj = datetime.combine(s_date_obj, s_time_obj), datetime.combine(s_date_obj, e_time_obj)
                if e_dt_obj <= s_dt_obj: e_dt_obj += timedelta(days=1)
                stud = Student.query.filter_by(id=s_id, created_by_user_id=current_user.id).first()
                if not stud: flash('Student invalid.', 'danger'); return redirect(url_for('list_services'))

                conflict_msg = check_service_conflict_for_student(stud.id, s_dt_obj, e_dt_obj, s_type)
                if conflict_msg: flash(f"Conflict: studentul are deja {conflict_msg}", 'danger')
                elif s_type in ['GSS', 'Intervenție'] and check_leave_conflict(stud.id, s_dt_obj, e_dt_obj):
                     flash(f"Conflict: Serviciul {s_type} nu poate fi asignat deoarece studentul are o învoire/permisie în acest interval.", 'danger')
                else:
                    assignment = ServiceAssignment(student_id=s_id, service_type=s_type, service_date=s_date_obj,start_datetime=s_dt_obj, end_datetime=e_dt_obj,participates_in_roll_call=participates, notes=notes, created_by_user_id=current_user.id)
                    db.session.add(assignment); db.session.commit()
                    flash(f'Serviciul {s_type} a fost asignat lui {stud.nume}.', 'success'); return redirect(url_for('list_services'))
            except ValueError: flash('Format dată/oră invalid.', 'danger')
    default_times = {"GSS": ("07:00", "07:00"), "SVM": ("05:50", "20:00"), "Intervenție": ("20:00", "00:00"), "Planton 1": ("22:00", "00:00"), "Planton 2": ("00:00", "02:00"), "Planton 3": ("02:00", "04:00")}
    return render_template('assign_service.html', students=students, service_types=SERVICE_TYPES, form_data=request.form if request.method == 'POST' else None, default_times=default_times, today_str=date.today().isoformat())

@app.route('/gradat/services/delete/<int:assignment_id>', methods=['POST'])
@login_required
def delete_service_assignment(assignment_id):
    if current_user.role != 'gradat': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))
    assign_del = ServiceAssignment.query.filter_by(id=assignment_id, created_by_user_id=current_user.id).first_or_404()
    db.session.delete(assign_del); db.session.commit()
    flash(f'Serviciul pentru {assign_del.student.nume} a fost șters.', 'success')
    return redirect(url_for('list_services'))

# --- Generare Prezență ---
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
        ec = len(students); ep = 0; ea_list = []
        for stud in students:
            s_info = get_student_status(stud, dt_check)
            if s_info['status_code'] == 'present': ep += 1
            else:
                is_abs_from_formation = True
                if s_info['status_code'] == 'absent_service' and s_info['object'] and s_info['object'].participates_in_roll_call and report_type == 'evening_roll_call':
                    ep +=1; is_abs_from_formation = False
                if is_abs_from_formation:
                    detail = f"{stud.grad_militar} {stud.nume} {stud.prenume} - {s_info['reason']}"
                    if s_info['until']: detail += f" (până la {s_info['until'].strftime('%d.%m %H:%M')})"
                    ea_list.append(detail)
        report_data = {"title": report_title, "datetime_checked": report_time_str, "efectiv_control": ec, "efectiv_prezent": ep, "efectiv_absent_count": len(ea_list), "efectiv_absent_list": sorted(ea_list)}
    return render_template('presence_report.html', report_data=report_data, current_datetime_str=datetime.now().strftime("%Y-%m-%dT%H:%M"))

# --- Rute Comandanți (Noi) ---
def get_aggregated_presence_data(students_query, datetime_check):
    """Funcție helper pentru a calcula efectivele pentru o listă de studenți."""
    efectiv_control = students_query.count()
    efectiv_prezent = 0
    absent_details_by_unit = {} # { 'Pluton X': ['Detalii absent 1', ...], 'Compania Y': [...] }

    for student in students_query.all():
        status_info = get_student_status(student, datetime_check)
        unit_key = f"Pluton {student.pluton}" # Cheia pentru agregare (poate fi și companie)

        if status_info['status_code'] == 'present':
            efectiv_prezent += 1
        else:
            is_absent_from_formation = True
            if status_info['status_code'] == 'absent_service' and status_info['object'] and status_info['object'].participates_in_roll_call:
                # Aici trebuie să decidem cum contorizăm pentru comandanți.
                # Presupunem că și ei îi văd "prezenți" în efectivul general dacă participă la apelul unității.
                efectiv_prezent += 1
                is_absent_from_formation = False

            if is_absent_from_formation:
                absent_detail = f"{student.grad_militar} {student.nume} {student.prenume} ({student.pluton}) - {status_info['reason']}"
                if status_info['until']: absent_detail += f" (până la {status_info['until'].strftime('%d.%m %H:%M')})"

                if unit_key not in absent_details_by_unit: absent_details_by_unit[unit_key] = []
                absent_details_by_unit[unit_key].append(absent_detail)

    return {
        "efectiv_control": efectiv_control,
        "efectiv_prezent": efectiv_prezent,
        "efectiv_absent_count": efectiv_control - efectiv_prezent, # Recalculăm pe baza celor prezenți
        "absent_details_by_unit": {k: sorted(v) for k, v in absent_details_by_unit.items()} # Sortăm fiecare listă de absenți
    }

@app.route('/comandant/companie/dashboard')
@login_required
def company_commander_dashboard():
    if current_user.role != 'comandant_companie': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))

    # Extragem ID-ul companiei din username (ex: CmdC1 -> companie_id = "1")
    match = re.match(r"CmdC(\d+)", current_user.username)
    if not match: flash('Format username invalid pentru comandant companie.', 'danger'); return redirect(url_for('home'))
    company_id_str = match.group(1)

    students_in_company = Student.query.filter_by(companie=company_id_str)

    # Calculăm efectivele pentru momentul curent (apel de seară)
    now = datetime.now()
    roll_call_time = now.replace(hour=20 if now.weekday() < 4 else 22, minute=0, second=0, microsecond=0)

    presence_data = get_aggregated_presence_data(students_in_company, roll_call_time)

    # Statistici suplimentare (opțional)
    total_on_permission = Permission.query.join(Student).filter(Student.companie == company_id_str, Permission.status == 'Aprobată', Permission.start_datetime <= now, Permission.end_datetime >= now).count()
    # ... alte statistici ...

    return render_template('company_commander_dashboard.html',
                           company_id=company_id_str,
                           presence_data=presence_data,
                           roll_call_time_str=roll_call_time.strftime('%d.%m.%Y %H:%M'),
                           total_on_permission=total_on_permission)

@app.route('/comandant/batalion/dashboard')
@login_required
def battalion_commander_dashboard():
    if current_user.role != 'comandant_batalion': flash('Acces neautorizat.', 'danger'); return redirect(url_for('home'))

    match = re.match(r"CmdB(\d+)", current_user.username)
    if not match: flash('Format username invalid pentru comandant batalion.', 'danger'); return redirect(url_for('home'))
    battalion_id_str = match.group(1)

    students_in_battalion = Student.query.filter_by(batalion=battalion_id_str)

    now = datetime.now()
    roll_call_time = now.replace(hour=20 if now.weekday() < 4 else 22, minute=0, second=0, microsecond=0)

    # Agregare pe companii
    companies_data = {}
    distinct_companies = db.session.query(Student.companie).filter(Student.batalion == battalion_id_str).distinct().all()

    for comp in distinct_companies:
        company_id = comp[0]
        students_in_company = Student.query.filter_by(batalion=battalion_id_str, companie=company_id)
        companies_data[f"Compania {company_id}"] = get_aggregated_presence_data(students_in_company, roll_call_time)

    # Total batalion
    total_battalion_presence = get_aggregated_presence_data(students_in_battalion, roll_call_time)


    return render_template('battalion_commander_dashboard.html',
                           battalion_id=battalion_id_str,
                           companies_data=companies_data, # Date agregate pe companii
                           total_battalion_presence=total_battalion_presence, # Totalul pe batalion
                           roll_call_time_str=roll_call_time.strftime('%d.%m.%Y %H:%M'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)
