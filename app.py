from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta, timezone
from werkzeug.utils import secure_filename
import os
import uuid
import re
from dotenv import load_dotenv
from dateutil.parser import parse

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'supersecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mensa_nag.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['UPLOAD_FOLDER'] = 'Uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)

# Custom Jinja2 filter for datetime parsing
def as_datetime(value):
    return parse(value)
app.jinja_env.filters['as_datetime'] = as_datetime

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    membership_number = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    confirmation_token = db.Column(db.String(100))
    role = db.Column(db.String(20), default='member')  # member, subcommittee, coordinator
    activities = db.relationship('UserActivity', backref='user', lazy=True)
    options = db.relationship('UserOption', backref='user', lazy=True)
    payments = db.relationship('Payment', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password, rounds=14).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def validate_password(self, password):
        if len(password) < 8 or not re.search(r'[A-Z]', password) or \
           not re.search(r'[a-z]', password) or not re.search(r'\d', password) or \
           not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True

    def update_payment_status(self):
        total_paid = sum(p.amount for p in self.payments)
        for uo in sorted(self.options, key=lambda x: x.selected_at):
            if total_paid >= uo.option.price:
                uo.status = 'paid'
                total_paid -= uo.option.price
            else:
                uo.status = 'pending'
                break
        for ua in sorted(self.activities, key=lambda x: x.selected_at):
            if ua.status != 'expired' and total_paid >= ua.activity.price:
                ua.status = 'paid'
                total_paid -= ua.activity.price
            else:
                ua.status = 'pending' if ua.status != 'expired' else 'expired'
        db.session.commit()

class EventOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

class UserOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('event_option.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    selected_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    option = db.relationship('EventOption', backref='user_options')

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    timeslots = db.Column(db.Text)
    slots = db.Column(db.Integer, default=0)
    expiration_days = db.Column(db.Integer, default=7)

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    selected_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expiration_date = db.Column(db.DateTime)
    activity = db.relationship('Activity', backref='user_activities')

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    file = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Initialize database and seed data
with app.app_context():
    db.create_all()
    coord = User.query.filter_by(membership_number='36572').first()
    if not coord:
        coord = User(full_name='Mike Combrink', membership_number='36572', email='maaikc@gmail.com', confirmed=True, role='coordinator')
        coord.set_password('defaultpassword')
        db.session.add(coord)
    if not EventOption.query.first():
        db.session.add(EventOption(name='Accommodation with Meals', price=500.0))
        db.session.add(EventOption(name='Gala Dinner', price=100.0))
        db.session.add(EventOption(name='Breakfast', price=50.0))
        db.session.add(EventOption(name='Lunch', price=60.0))
        db.session.add(EventOption(name='Dinner', price=80.0))
    db.session.commit()

# Helper functions
def check_expirations(user_id=None):
    now = datetime.now(timezone.utc)
    query = UserActivity.query.filter_by(status='pending').filter(UserActivity.expiration_date < now)
    if user_id:
        query = query.filter_by(user_id=user_id)
    for ua in query.all():
        ua.status = 'expired'
    db.session.commit()

def get_attendees_count(activity_id):
    return UserActivity.query.filter_by(activity_id=activity_id).filter(
        UserActivity.status.in_(['pending', 'paid'])
    ).count()

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        membership_number = request.form['membership_number']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html')
        user = User(full_name=full_name, membership_number=membership_number, email=email, confirmation_token=str(uuid.uuid4()))
        if not user.validate_password(password):
            flash('Password must be 8+ characters with uppercase, lowercase, number, and special character.')
            return render_template('register.html')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        msg = Message('Confirm Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Click to confirm: {url_for("confirm_email", token=user.confirmation_token, _external=True)}'
        mail.send(msg)
        flash('Confirmation email sent.')
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    user = User.query.filter_by(confirmation_token=token).first()
    if user:
        user.confirmed = True
        user.confimation_token = None
        db.session.commit()
        session['user_id'] = user.id
        flash('Email confirmed. You are registered for the weekend.')
        return redirect(url_for('options'))
    flash('Invalid token.')
    return redirect(url_for('index'))

@app.route('/options', methods=['GET', 'POST'])
def options():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    options = EventOption.query.all()
    if request.method == 'POST':
        selected_option_ids = request.form.getlist('options')
        UserOption.query.filter_by(user_id=user.id).delete()
        for opt_id in selected_option_ids:
            opt = db.session.get(EventOption, int(opt_id))
            if opt:
                user_option = UserOption(user_id=user.id, option_id=opt.id)
                db.session.add(user_option)
        db.session.commit()
        user.update_payment_status()
        return redirect(url_for('dashboard'))
    return render_template('options.html', options=options)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        membership_number = request.form['membership_number']
        password = request.form['password']
        user = User.query.filter_by(membership_number=membership_number).first()
        if user and user.confirmed and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        flash('Invalid credentials or unconfirmed membership.')
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        if user.check_password(old_password):
            user.set_password(new_password)
            db.session.commit()
            flash('Password changed successfully.')
            return redirect(url_for('dashboard'))
        flash('Incorrect old password.')
    return render_template('change_password.html')

@app.route('/toggle_subcommittee', methods=['POST'])
def toggle_subcommittee():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if not user.confirmed:
        flash('You must confirm your email before enabling sub-committee access.')
        return redirect(url_for('dashboard'))
    # Toggle role between 'member' and 'subcommittee' (for testing)
    user.role = 'subcommittee' if user.role == 'member' else 'member'
    db.session.commit()
    flash(f'Sub-committee access {"enabled" if user.role == "subcommittee" else "disabled"}.')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    check_expirations(session['user_id'])
    user = db.session.get(User, session['user_id'])
    activities = Activity.query.all()
    selected_activities = [ua.activity_id for ua in user.activities if ua.status in ['pending', 'paid']]
    selected_options = [{'id': uo.option.id, 'name': uo.option.name, 'price': f'{uo.option.price:.2f}', 'status': uo.status} for uo in user.options]
    activities_json = [
        {
            'id': act.id,
            'name': act.name,
            'location': act.location,
            'price': f'{act.price:.2f}',
            'timeslots': act.timeslots,
            'slots': act.slots,
            'expiration_days': act.expiration_days
        } for act in activities
    ]
    return render_template('dashboard.html', user=user, activities=activities_json, selected=selected_activities, get_attendees_count=get_attendees_count, options=selected_options)

@app.route('/select_activity/<int:activity_id>', methods=['POST'])
def select_activity(activity_id):
    if 'user_id' not in session:
        return 'Unauthorized', 401
    activity = db.session.get(Activity, activity_id)
    if activity.slots > 0 and get_attendees_count(activity_id) >= activity.slots:
        return 'Fully booked', 400
    user = db.session.get(User, session['user_id'])
    ua = UserActivity.query.filter_by(user_id=user.id, activity_id=activity_id).first()
    if ua:
        if ua.status == 'expired':
            ua.status = 'pending'
            ua.selected_at = datetime.now(timezone.utc)
            ua.expiration_date = ua.selected_at + timedelta(days=activity.expiration_days)
        else:
            db.session.delete(ua)
    else:
        ua = UserActivity(user_id=user.id, activity_id=activity_id, status='pending', expiration_date=datetime.now(timezone.utc) + timedelta(days=activity.expiration_days))
        db.session.add(ua)
    db.session.commit()
    user.update_payment_status()
    return 'OK'

@app.route('/upload_payment', methods=['POST'])
def upload_payment():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if 'file' in request.files and 'amount' in request.form:
        file = request.files['file']
        amount = float(request.form['amount'])
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            payment = Payment(user_id=user.id, amount=amount, file=filename)
            db.session.add(payment)
            db.session.commit()
            user.update_payment_status()
            flash('Payment confirmation uploaded.')
        else:
            flash('Invalid file type.')
    else:
        flash('Missing file or amount.')
    return redirect(url_for('dashboard'))

@app.route('/activity_report', methods=['GET', 'POST'])
def activity_report():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role not in ['subcommittee', 'coordinator']:
        flash('Access denied. Sub-committee or coordinator role required.')
        return redirect(url_for('dashboard'))
    activities = Activity.query.all()
    selected_activity = None
    report = []
    if request.method == 'POST':
        activity_id = request.form.get('activity_id')
        if activity_id:
            selected_activity = db.session.get(Activity, int(activity_id))
            if selected_activity:
                user_activities = UserActivity.query.filter_by(activity_id=selected_activity.id).filter(
                    UserActivity.status.in_(['pending', 'paid'])
                ).all()
                report = [
                    {
                        'user_name': ua.user.full_name,
                        'status': ua.status.capitalize(),
                        'expiration_date': ua.expiration_date.strftime('%Y-%m-%d') if ua.status == 'pending' and ua.expiration_date else 'N/A'
                    } for ua in user_activities
                ]
    return render_template('activity_report.html', activities=activities, selected_activity=selected_activity, report=report)

@app.route('/admin_activities', methods=['GET', 'POST'])
def admin_activities():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role not in ['subcommittee', 'coordinator']:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if 'add' in request.form:
            name = request.form['name']
            location = request.form['location']
            price = float(request.form['price'])
            timeslots = request.form['timeslots']
            slots = int(request.form['slots'])
            expiration_days = int(request.form.get('expiration_days', 7))
            activity = Activity(name=name, location=location, price=price, timeslots=timeslots, slots=slots, expiration_days=expiration_days)
            db.session.add(activity)
        elif 'edit' in request.form:
            act_id = int(request.form['id'])
            activity = db.session.get(Activity, act_id)
            activity.name = request.form['name']
            activity.location = request.form['location']
            activity.price = float(request.form['price'])
            activity.timeslots = request.form['timeslots']
            activity.slots = int(request.form['slots'])
            activity.expiration_days = int(request.form.get('expiration_days', 7))
        elif 'delete' in request.form:
            act_id = int(request.form['id'])
            activity = db.session.get(Activity, act_id)
            db.session.delete(activity)
        db.session.commit()
    activities = Activity.query.all()
    return render_template('admin_activities.html', activities=activities)

@app.route('/admin_options', methods=['GET', 'POST'])
def admin_options():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role not in ['subcommittee', 'coordinator']:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if 'add' in request.form:
            name = request.form['name']
            price = float(request.form['price'])
            option = EventOption(name=name, price=price)
            db.session.add(option)
        elif 'edit' in request.form:
            opt_id = int(request.form['id'])
            option = db.session.get(EventOption, opt_id)
            option.name = request.form['name']
            option.price = float(request.form['price'])
        elif 'delete' in request.form:
            opt_id = int(request.form['id'])
            option = db.session.get(EventOption, opt_id)
            db.session.delete(option)
        db.session.commit()
    options = EventOption.query.all()
    return render_template('admin_options.html', options=options)

@app.route('/admin_users')
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role != 'coordinator':
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/grant_subcommittee/<int:user_id>')
def grant_subcommittee(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    coord = db.session.get(User, session['user_id'])
    if coord.role != 'coordinator':
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    target = db.session.get(User, user_id)
    if target:
        target.role = 'subcommittee'
        db.session.commit()
        flash('Sub-committee access granted.')
    return redirect(url_for('admin_users'))

@app.route('/reports/master')
def report_master():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role not in ['subcommittee', 'coordinator']:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    check_expirations()
    users = User.query.all()
    report = []
    for u in users:
        selections = [o.option.name for o in u.options if o.status in ['pending', 'paid']] + \
                     [ua.activity.name for ua in u.activities if ua.status in ['pending', 'paid']]
        payable = sum(o.option.price for o in u.options if o.status in ['pending', 'paid']) + \
                  sum(ua.activity.price for ua in u.activities if ua.status in ['pending', 'paid'])
        paid = sum(o.option.price for o in u.options if o.status == 'paid') + \
               sum(ua.activity.price for ua in u.activities if ua.status == 'paid')
        report.append({
            'user': u,
            'selections': selections,
            'payable': f'{payable:.2f}',
            'paid': f'{paid:.2f}'
        })
    return render_template('report_master.html', report=report)

@app.route('/reports/summary')
def report_summary():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role not in ['subcommittee', 'coordinator']:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    check_expirations()
    options = EventOption.query.all()
    activities = Activity.query.all()
    report = []
    for opt in options:
        registered = UserOption.query.filter_by(option_id=opt.id).filter(UserOption.status.in_(['pending', 'paid'])).count()
        paid = UserOption.query.filter_by(option_id=opt.id).filter(UserOption.status == 'paid').count()
        report.append({'name': opt.name, 'registered': registered, 'paid': paid})
    for act in activities:
        registered = UserActivity.query.filter_by(activity_id=act.id).filter(UserActivity.status.in_(['pending', 'paid'])).count()
        paid = UserActivity.query.filter_by(activity_id=act.id).filter(UserActivity.status == 'paid').count()
        report.append({'name': act.name, 'registered': registered, 'paid': paid})
    return render_template('report_summary.html', report=report)

@app.route('/reports/activity/<int:activity_id>')
def report_activity(activity_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role not in ['subcommittee', 'coordinator']:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    check_expirations()
    activity = db.session.get(Activity, activity_id)
    if not activity:
        flash('Activity not found.')
        return redirect(url_for('dashboard'))
    user_activities = UserActivity.query.filter_by(activity_id=activity_id).filter(UserActivity.status.in_(['pending', 'paid'])).all()
    report = [{'user': ua.user.full_name, 'paid': ua.status == 'paid'} for ua in user_activities]
    return render_template('report_activity.html', activity=activity, report=report)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)