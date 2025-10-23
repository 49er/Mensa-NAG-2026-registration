from flask import Flask, request, redirect, url_for, flash, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import pytz
from dateutil.parser import parse
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mensa_nag.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['UPLOAD_FOLDER'] = 'Uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)

# Custom Jinja filter for datetime parsing
def as_datetime(value):
    try:
        return parse(value).replace(tzinfo=pytz.UTC)
    except:
        return value
app.jinja_env.filters['as_datetime'] = as_datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    membership_number = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    confirmation_token = db.Column(db.String(100))
    role = db.Column(db.String(20), default='member')
    last_login = db.Column(db.DateTime)
    session_id = db.Column(db.String(100))  # Track session for logged-in users
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

class EventOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('event_options', lazy=True))

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    timeslots = db.Column(db.String(500), nullable=False)  # Format: start1,end1;start2,end2
    slots = db.Column(db.Integer, nullable=False)  # 0 for unlimited
    expiration_days = db.Column(db.Integer, nullable=False)

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('user_activities', lazy=True))
    activity = db.relationship('Activity', backref=db.backref('user_activities', lazy=True))

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.now(pytz.UTC))
    user = db.relationship('User', backref=db.backref('payments', lazy=True))

@app.before_request
def update_last_login():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            user.last_login = datetime.now(pytz.UTC)
            user.session_id = session.sid  # Track session ID
            db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        membership_number = request.form['membership_number']
        email = request.form['email']
        password = request.form['password']
        user = User(full_name=full_name, membership_number=membership_number, email=email, confirmation_token=os.urandom(16).hex(), role='member')
        user.set_password(password)
        if membership_number == '36572':
            user.role = 'coordinator'
            user.confirmed = True
        db.session.add(user)
        db.session.commit()
        msg = Message('Confirm Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Click to confirm: {url_for("confirm_email", token=user.confirmation_token, _external=True)}'
        try:
            mail.send(msg)
            flash('Registration successful! Please check your email to confirm.')
        except Exception as e:
            flash('Registration successful, but email sending failed. Contact support.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    user = User.query.filter_by(confirmation_token=token).first()
    if user:
        user.confirmed = True
        user.confirmation_token = None
        db.session.commit()
        flash('Email confirmed! You can now log in.')
    else:
        flash('Invalid or expired token.')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        user = User.query.filter((User.email == identifier) | (User.membership_number == identifier)).first()
        if user and user.confirmed and user.check_password(password):
            session['user_id'] = user.id
            user.last_login = datetime.now(pytz.UTC)
            user.session_id = session.sid
            db.session.commit()
            return redirect(url_for('dashboard'))
        flash('Invalid credentials or unconfirmed membership.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            user.session_id = None
            db.session.commit()
    session.pop('user_id', None)
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        if 'subcommittee' in request.form:
            user.role = 'subcommittee' if request.form['subcommittee'] == 'on' else 'member'
            db.session.commit()
        elif 'option' in request.form:
            option_id = int(request.form['option'])
            existing = EventOption.query.filter_by(user_id=user.id, id=option_id).first()
            if not existing:
                option = EventOption.query.get(option_id)
                if option:
                    user.event_options.append(option)
                    db.session.commit()
        elif 'activity' in request.form:
            activity_id = int(request.form['activity'])
            activity = Activity.query.get(activity_id)
            if activity and (activity.slots == 0 or len(activity.user_activities) < activity.slots):
                user_activities = UserActivity.query.filter_by(user_id=user.id).all()
                conflict = False
                new_timeslots = activity.timeslots.split(';')
                for ua in user_activities:
                    existing_timeslots = ua.activity.timeslots.split(';')
                    for new_slot in new_timeslots:
                        new_start, new_end = map(parse, new_slot.split(','))
                        for existing_slot in existing_timeslots:
                            existing_start, existing_end = map(parse, existing_slot.split(','))
                            if (new_start < existing_end + timedelta(hours=1) and new_end > existing_start) and activity.location != ua.activity.location:
                                conflict = True
                                break
                        if conflict:
                            break
                    if conflict:
                        break
                if not conflict:
                    user_activity = UserActivity(user_id=user.id, activity_id=activity_id)
                    db.session.add(user_activity)
                    db.session.commit()
        elif 'payment' in request.form:
            file = request.files['payment_file']
            if file and '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                payment = Payment(user_id=user.id, filename=filename)
                db.session.add(payment)
                db.session.commit()
    activities = Activity.query.all()
    options = EventOption.query.filter_by(user_id=None).all()
    user_activities = UserActivity.query.filter_by(user_id=user.id).all()
    user_options = EventOption.query.filter_by(user_id=user.id).all()
    payments = Payment.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, activities=activities, options=options, user_activities=user_activities, user_options=user_options, payments=payments)

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
    options = EventOption.query.filter_by(user_id=None).all()
    return render_template('admin_options.html', options=options)

@app.route('/logged_in_users')
def logged_in_users():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role != 'coordinator':
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    active_users = User.query.filter(User.session_id != None).all()
    return render_template('logged_in_users.html', active_users=active_users)

@app.route('/reports/master')
def report_master():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role != 'coordinator':
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('report_master.html', users=users)

@app.route('/reports/summary')
def report_summary():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role != 'coordinator':
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    activities = Activity.query.all()
    return render_template('report_summary.html', activities=activities)

@app.route('/activity_report')
def activity_report():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = db.session.get(User, session['user_id'])
    if user.role not in ['subcommittee', 'coordinator']:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    activities = Activity.query.all()
    return render_template('report_activity.html', activities=activities)

if __name__ == '__main__':
    app.run(debug=True)