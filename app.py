from flask import Flask, render_template, request, redirect, session, flash, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler
import os
import io
import csv
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors

# Models
from models import db, User, Equipment, MaintenanceLog, Metric, Alert, Document, Threshold

# ---------------- UTILITIES ----------------
def calculate_next_due(reminder_date, recurrence):
    """
    Calculate next due date based on recurrence.
    Expects reminder_date as 'YYYY-MM-DD' string.
    """
    date = datetime.strptime(reminder_date, '%Y-%m-%d')
    if recurrence == 'daily':
        return (date + timedelta(days=1)).strftime('%Y-%m-%d')
    elif recurrence == 'weekly':
        return (date + timedelta(weeks=1)).strftime('%Y-%m-%d')
    elif recurrence == 'monthly':
        # Approximate month as 30 days to avoid external deps
        return (date + timedelta(days=30)).strftime('%Y-%m-%d')
    elif recurrence == 'quarterly':
        return (date + timedelta(days=90)).strftime('%Y-%m-%d')
    elif recurrence == 'biweekly':
        return (date + timedelta(weeks=2)).strftime('%Y-%m-%d')
    elif recurrence == 'yearly':
        return (date + timedelta(days=365)).strftime('%Y-%m-%d')
    else:
        return reminder_date  # custom/no auto calc

def allowed_file(filename, allowed_exts):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_exts

# ---------------- APP SETUP ----------------
app = Flask(__name__)

# Config
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_secret')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads')
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'jpg', 'png', 'txt'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Init DB
db.init_app(app)

# ---------------- CUSTOM JINJA2 FILTERS ----------------
@app.template_filter('strptime')
def strptime_filter(date_string, format_string='%Y-%m-%d'):
    """Parse a date string and return a datetime object."""
    if not date_string:
        return None
    try:
        # Extract first 10 characters if longer (YYYY-MM-DD format)
        date_str = date_string[:10] if len(date_string) > 10 else date_string
        return datetime.strptime(date_str, format_string)
    except (ValueError, TypeError):
        return None

@app.template_filter('strftime')
def strftime_filter(date_obj, format_string='%B %d, %Y'):
    """Format a datetime object."""
    if not date_obj:
        return 'N/A'
    try:
        if isinstance(date_obj, datetime):
            return date_obj.strftime(format_string)
        return str(date_obj)
    except (ValueError, TypeError, AttributeError):
        return str(date_obj) if date_obj else 'N/A'

@app.template_filter('format_date')
def format_date_filter(date_string, output_format='%B %d, %Y'):
    """Parse a date string and format it."""
    if not date_string:
        return 'N/A'
    try:
        # Extract first 10 characters if longer (YYYY-MM-DD format)
        date_str = date_string[:10] if len(date_string) > 10 else date_string
        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
        return date_obj.strftime(output_format)
    except (ValueError, TypeError):
        return date_string

# ---------------- SCHEDULER ----------------
def check_alerts():
    with app.app_context():
        today_str = datetime.today().strftime('%Y-%m-%d')
        
        # Maintenance reminders
        due_logs = MaintenanceLog.query.filter_by(reminder_date=today_str).all()
        for log in due_logs:
            alert = Alert(
                equipment_id=log.equipment_id,
                title="Maintenance Reminder Due",
                message=f"Maintenance due: {log.issue}",
                severity="Medium",
                status="Active"
            )
            db.session.add(alert)
        
        # Critical pending issues
        critical_logs = MaintenanceLog.query.filter_by(priority="Critical", status="Pending").all()
        for log in critical_logs:
            alert = Alert(
                equipment_id=log.equipment_id,
                title="Critical Maintenance Issue",
                message=f"Critical issue: {log.issue}",
                severity="High",
                status="Active"
            )
            db.session.add(alert)
        
        # Performance threshold monitoring
        thresholds = Threshold.query.filter_by(enabled=True).all()
        for threshold in thresholds:
            # Get latest metric for this threshold
            latest_metric = Metric.query.filter_by(
                user_id=threshold.user_id,
                equipment_id=threshold.equipment_id,
                name=threshold.metric_name
            ).order_by(Metric.timestamp.desc()).first()
            
            if latest_metric:
                alert_triggered = False
                if threshold.min_value is not None and latest_metric.value < threshold.min_value:
                    alert_triggered = True
                    message = f"{threshold.metric_name} below threshold: {latest_metric.value} {latest_metric.unit} (min: {threshold.min_value})"
                elif threshold.max_value is not None and latest_metric.value > threshold.max_value:
                    alert_triggered = True
                    message = f"{threshold.metric_name} above threshold: {latest_metric.value} {latest_metric.unit} (max: {threshold.max_value})"
                
                if alert_triggered:
                    alert = Alert(
                        equipment_id=threshold.equipment_id,
                        title=f"Performance Threshold Alert",
                        message=message,
                        severity=threshold.severity,
                        status="Active"
                    )
                    db.session.add(alert)
        
        db.session.commit()

scheduler = BackgroundScheduler()
# Run daily at midnight
scheduler.add_job(func=check_alerts, trigger="cron", hour=0, minute=0)
scheduler.start()

# ---------------- AUTH DECORATORS ----------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please login first!", "error")
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                flash("Please login first!", "error")
                return redirect('/login')
            user = User.query.get(session['user'])
            if not user or (user.role != role and user.role != 'Admin'):
                flash("Access denied!", "error")
                return redirect('/dashboard')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_or_technician_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please login first!", "error")
            return redirect('/login')
        user = User.query.get(session['user'])
        if not user or user.role not in ['Admin', 'Technician']:
            flash("Access denied! Admin or Technician role required.", "error")
            return redirect('/dashboard')
        return f(*args, **kwargs)
    return decorated_function

# ---------------- ROUTES ----------------
@app.route('/')
def home():
    return redirect('/login')

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            email = request.form['email'].strip().lower()
            password = request.form['password']
            role = request.form.get('role', 'User')

            if not name or not email or not password:
                flash("All fields are required!", "error")
                return redirect('/register')

            if User.query.filter_by(email=email).first():
                flash("Email already registered!", "error")
                return redirect('/register')

            password_hash = generate_password_hash(password)
            user = User(name=name, email=email, password_hash=password_hash, role=role)
            db.session.add(user)
            db.session.commit()

            flash("Registration successful!", "success")
            return redirect('/login')
        except Exception as e:
            print("Register error:", e)
            db.session.rollback()
            flash("Registration failed!", "error")

    return render_template('register.html')

# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email'].strip().lower()
            password = request.form['password']

            user = User.query.filter_by(email=email).first()

            if user and check_password_hash(user.password_hash, password):
                session['user'] = user.id
                flash("Login successful!", "success")
                return redirect('/dashboard')

            flash("Invalid credentials!", "error")
        except Exception as e:
            print("Login error:", e)
            flash("Login failed!", "error")

    return render_template('login.html')

# LOGOUT
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect('/login')

# DASHBOARD
@app.route('/dashboard')
@login_required
def dashboard():
    uid = session['user']

    # Build equipment query with filters
    eq_query = Equipment.query.filter_by(user_id=uid)
    status_filter = request.args.get('status', '').strip()
    if status_filter:
        eq_query = eq_query.filter(Equipment.status == status_filter)
    
    total_eq = eq_query.count()
    
    # Build maintenance queries with filters
    log_query = MaintenanceLog.query.join(Equipment).filter(Equipment.user_id == uid)
    priority_filter = request.args.get('priority', '').strip()
    if priority_filter:
        log_query = log_query.filter(MaintenanceLog.priority == priority_filter)
    
    pending = log_query.filter(MaintenanceLog.status != "Completed").count()
    completed = log_query.filter(MaintenanceLog.status == "Completed").count()
    critical = log_query.filter(MaintenanceLog.priority == "Critical").count()

    recent = log_query.order_by(MaintenanceLog.id.desc()).limit(5).all()

    today = datetime.today().strftime('%Y-%m-%d')
    due = MaintenanceLog.query.join(Equipment).filter(
        Equipment.user_id == uid,
        MaintenanceLog.reminder_date <= today
    ).all()

    # Build alerts query with filters
    alert_query = Alert.query.join(Equipment).filter(
        Equipment.user_id == uid,
        Alert.status == 'Active'
    )
    severity_filter = request.args.get('severity', '').strip()
    if severity_filter:
        alert_query = alert_query.filter(Alert.severity == severity_filter)
    
    alerts = alert_query.all()

    return render_template(
        'dashboard.html',
        total_eq=total_eq,
        pending=pending,
        completed=completed,
        critical=critical,
        recent=recent,
        due=due,
        alerts=alerts,
        today=today
    )

# ADD EQUIPMENT
@app.route('/equipment/add', methods=['GET', 'POST'])
@login_required
@admin_or_technician_required
def equipment_add():
    if request.method == 'POST':
        try:
            eq = Equipment(
                user_id=session['user'],
                name=request.form['name'],
                model=request.form['model'],
                category=request.form['category'],
                purchase_date=request.form['purchase_date'],
                warranty=request.form['warranty'],
                location=request.form['location'],
                status=request.form['status'],
                notes=request.form['notes']
            )
            db.session.add(eq)
            db.session.commit()

            flash("Equipment added successfully!", "success")
            return redirect('/equipment')
        except Exception as e:
            print("Equipment add error:", e)
            db.session.rollback()
            flash("Failed to add equipment!", "error")

    return render_template('equipment_add.html')

# LIST EQUIPMENT
@app.route('/equipment')
@login_required
def equipment_list():
    query = Equipment.query.filter_by(user_id=session['user'])
    
    # Search filter
    search = request.args.get('search', '').strip()
    if search:
        query = query.filter(
            (Equipment.name.ilike(f'%{search}%')) |
            (Equipment.model.ilike(f'%{search}%'))
        )
    
    # Category filter
    category = request.args.get('category', '').strip()
    if category:
        query = query.filter(Equipment.category == category)
    
    # Status filter
    status = request.args.get('status', '').strip()
    if status:
        query = query.filter(Equipment.status == status)
    
    # Sorting
    sort = request.args.get('sort', 'id_desc')
    if sort == 'id_asc':
        query = query.order_by(Equipment.id.asc())
    elif sort == 'name_asc':
        query = query.order_by(Equipment.name.asc())
    elif sort == 'name_desc':
        query = query.order_by(Equipment.name.desc())
    else:  # id_desc (default)
        query = query.order_by(Equipment.id.desc())
    
    assets = query.all()
    return render_template('equipment_list.html', assets=assets)

# EQUIPMENT DETAIL
@app.route('/equipment/<int:id>')
@login_required
def equipment_detail(id):
    asset = Equipment.query.get_or_404(id)

    if asset.user_id != session['user']:
        flash("Access Denied", "error")
        return redirect('/equipment')

    return render_template('equipment_detail.html', asset=asset)

# EDIT EQUIPMENT
@app.route('/equipment/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_or_technician_required
def equipment_edit(id):
    asset = Equipment.query.get_or_404(id)
    
    if asset.user_id != session['user']:
        flash("Access Denied", "error")
        return redirect('/equipment')
    
    if request.method == 'POST':
        try:
            asset.name = request.form['name']
            asset.model = request.form['model']
            asset.category = request.form['category']
            asset.purchase_date = request.form['purchase_date']
            asset.warranty = request.form['warranty']
            asset.location = request.form['location']
            asset.status = request.form['status']
            asset.notes = request.form['notes']
            
            db.session.commit()
            flash("Equipment updated successfully!", "success")
            return redirect(f'/equipment/{id}')
        except Exception as e:
            print("Equipment edit error:", e)
            db.session.rollback()
            flash("Failed to update equipment!", "error")
    
    return render_template('equipment_edit.html', asset=asset)

# DELETE EQUIPMENT
@app.route('/equipment/<int:id>/delete', methods=['POST'])
@login_required
@admin_or_technician_required
def equipment_delete(id):
    asset = Equipment.query.get_or_404(id)
    
    if asset.user_id != session['user']:
        flash("Access Denied", "error")
        return redirect('/equipment')
    
    try:
        # Delete related documents, logs, metrics, thresholds, alerts
        MaintenanceLog.query.filter_by(equipment_id=id).delete()
        Document.query.filter_by(equipment_id=id).delete()
        Metric.query.filter_by(equipment_id=id).delete()
        Threshold.query.filter_by(equipment_id=id).delete()
        Alert.query.filter_by(equipment_id=id).delete()
        
        db.session.delete(asset)
        db.session.commit()
        flash("Equipment deleted successfully!", "success")
    except Exception as e:
        print("Equipment delete error:", e)
        db.session.rollback()
        flash("Failed to delete equipment!", "error")
    
    return redirect('/equipment')

# LIST MAINTENANCE
@app.route('/maintenance')
@login_required
def maintenance_list():
    # Get maintenance logs for current user
    logs = MaintenanceLog.query.join(Equipment).filter(Equipment.user_id == session['user']).order_by(MaintenanceLog.date.desc()).all()

    # Get today's date for reminders
    today = datetime.today().strftime('%Y-%m-%d')

    # Get due reminders (next_due <= today and status != 'completed')
    due = MaintenanceLog.query.join(Equipment).filter(
        Equipment.user_id == session['user'],
        MaintenanceLog.next_due <= today,
        MaintenanceLog.status != 'completed'
    ).order_by(MaintenanceLog.next_due).all()

    # Format dates for display
    for log in logs:
        if log.date:
            try:
                # Parse the date string and format it
                date_obj = datetime.strptime(log.date, '%Y-%m-%d')
                log.formatted_date = date_obj.strftime('%b %d, %Y')
            except (ValueError, AttributeError):
                log.formatted_date = log.date  # fallback to original
        else:
            log.formatted_date = 'N/A'

    for d in due:
        if d.date:
            try:
                date_obj = datetime.strptime(d.date, '%Y-%m-%d')
                d.formatted_date = date_obj.strftime('%b %d, %Y')
            except (ValueError, AttributeError):
                d.formatted_date = d.date
        else:
            d.formatted_date = 'N/A'

    return render_template('maintenance_list.html', logs=logs, due=due, today=today)

# ADD MAINTENANCE
@app.route('/maintenance/add/<int:equipment_id>', methods=['GET', 'POST'])
@login_required
@admin_or_technician_required
def maintenance_add(equipment_id):
    asset = Equipment.query.get_or_404(equipment_id)

    if asset.user_id != session['user']:
        flash("Access Denied", "error")
        return redirect('/equipment')

    if request.method == 'POST':
        try:
            log = MaintenanceLog(
                equipment_id=equipment_id,
                issue=request.form['issue'],
                type=request.form['type'],
                priority=request.form['priority'],
                status=request.form['status'],
                cost=float(request.form.get('cost', 0) or 0),
                date=datetime.today().strftime('%Y-%m-%d'),
                technician=request.form['technician'],
                parts_replaced=request.form['parts_replaced'],
                remarks=request.form['remarks'],
                notes=request.form['notes'],
                recurrence=request.form.get('recurrence'),
                reminder_date=request.form.get('reminder_date')
            )
            # Calculate next_due based on recurrence
            if log.recurrence and log.reminder_date:
                log.next_due = calculate_next_due(log.reminder_date, log.recurrence)

            db.session.add(log)
            db.session.commit()

            flash("Maintenance log saved!", "success")
            return redirect('/maintenance')
        except Exception as e:
            print("Maintenance add error:", e)
            db.session.rollback()
            flash("Failed to save log!", "error")

    return render_template('maintenance_add.html', asset=asset)

# SELECT EQUIPMENT FOR MAINTENANCE
@app.route('/maintenance/add', methods=['GET', 'POST'])
@login_required
def maintenance_add_select():
    if request.method == 'POST':
        equipment_id = request.form.get('equipment_id')
        if equipment_id:
            return redirect(f'/maintenance/add/{equipment_id}')
        else:
            flash("Please select equipment", "error")
    
    # Get all equipment for this user
    assets = Equipment.query.filter_by(user_id=session['user']).all()
    return render_template('maintenance_select_equipment.html', assets=assets)

# REPORTS
@app.route('/reports')
@login_required
def reports():
    uid = session['user']

    # Build query with filters
    query = MaintenanceLog.query.join(Equipment).filter(Equipment.user_id == uid)
    
    # Equipment filter
    equipment_id = request.args.get('equipment_id', type=int)
    if equipment_id:
        query = query.filter(MaintenanceLog.equipment_id == equipment_id)
    
    # Date range filters
    start_date = request.args.get('start_date', '').strip()
    if start_date:
        query = query.filter(MaintenanceLog.date >= start_date)
    
    end_date = request.args.get('end_date', '').strip()
    if end_date:
        query = query.filter(MaintenanceLog.date <= end_date)
    
    # Technician filter
    technician = request.args.get('technician', '').strip()
    if technician:
        query = query.filter(MaintenanceLog.technician.ilike(f'%{technician}%'))
    
    # Type filter
    maintenance_type = request.args.get('type', '').strip()
    if maintenance_type:
        query = query.filter(MaintenanceLog.type == maintenance_type)
    
    # Priority filter
    priority = request.args.get('priority', '').strip()
    if priority:
        query = query.filter(MaintenanceLog.priority == priority)
    
    # Status filter
    status = request.args.get('status', '').strip()
    if status:
        query = query.filter(MaintenanceLog.status == status)
    
    logs = query.order_by(MaintenanceLog.id.desc()).all()

    # Get stored metrics or calculate if not available
    metrics = Metric.query.filter_by(user_id=uid).all()
    if not metrics:
        # Calculate metrics if not stored
        total_cost = sum(log.cost or 0 for log in logs)
        completed_count = sum(1 for log in logs if log.status == 'Completed')
        pending_count = sum(1 for log in logs if log.status == 'Pending')
        equipment_count = Equipment.query.filter_by(user_id=uid).count()
        active_equipment = Equipment.query.filter_by(user_id=uid, status='Active').count()
    else:
        # Use stored metrics
        total_cost = next((m.value for m in metrics if m.name == 'Total Maintenance Cost'), 0)
        completed_count = next((m.value for m in metrics if m.name == 'Maintenance Completed'), 0)
        pending_count = next((m.value for m in metrics if m.name == 'Pending Tasks'), 0)
        equipment_count = next((m.value for m in metrics if m.name == 'Total Equipment'), 0)
        active_equipment = next((m.value for m in metrics if m.name == 'Active Equipment'), 0)

    # Get active alerts
    alerts = Alert.query.join(Equipment).filter(
        Equipment.user_id == uid,
        Alert.status == 'Active'
    ).order_by(Alert.created_at.desc()).all()

    # Get equipment list for filtering
    assets = Equipment.query.filter_by(user_id=uid).all()

    # Format dates for display
    for log in logs:
        if log.date:
            try:
                date_obj = datetime.strptime(log.date, '%Y-%m-%d')
                log.formatted_date = date_obj.strftime('%b %d, %Y')
            except (ValueError, AttributeError):
                log.formatted_date = log.date
        else:
            log.formatted_date = 'N/A'

    return render_template(
        'reports.html',
        logs=logs,
        total_cost=total_cost,
        completed_count=completed_count,
        pending_count=pending_count,
        equipment_count=equipment_count,
        active_equipment=active_equipment,
        alerts=alerts,
        assets=assets
    )

# EXPORT REPORTS
@app.route('/reports/export/pdf')
@login_required
def export_pdf():
    uid = session['user']
    
    # Get filter parameters
    equipment_id = request.args.get('equipment_id', type=int)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    technician = request.args.get('technician')
    maintenance_type = request.args.get('type')
    
    # Build query
    query = MaintenanceLog.query.join(Equipment).filter(Equipment.user_id == uid)
    
    if equipment_id:
        query = query.filter(MaintenanceLog.equipment_id == equipment_id)
    if start_date:
        query = query.filter(MaintenanceLog.date >= start_date)
    if end_date:
        query = query.filter(MaintenanceLog.date <= end_date)
    if technician:
        query = query.filter(MaintenanceLog.technician.ilike(f'%{technician}%'))
    if maintenance_type:
        query = query.filter(MaintenanceLog.type == maintenance_type)
    
    logs = query.order_by(MaintenanceLog.date.desc()).all()
    
    # Create PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    title = Paragraph("Maintenance Report", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))
    
    # Summary
    summary_data = [
        ["Total Records", len(logs)],
        ["Total Cost", f"₹{sum(log.cost or 0 for log in logs):.2f}"],
        ["Completed", sum(1 for log in logs if log.status == 'Completed')],
        ["Pending", sum(1 for log in logs if log.status == 'Pending')],
    ]
    
    summary_table = Table(summary_data, colWidths=[200, 200])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Detailed logs
    if logs:
        headers = ["Date", "Equipment", "Issue", "Type", "Priority", "Status", "Cost", "Technician"]
        data = [headers]
        
        for log in logs:
            equipment = Equipment.query.get(log.equipment_id)
            data.append([
                log.date,
                equipment.name if equipment else "Unknown",
                log.issue[:30] + "..." if len(log.issue) > 30 else log.issue,
                log.type,
                log.priority,
                log.status,
                f"₹{log.cost:.2f}" if log.cost else "₹0.00",
                log.technician or "N/A"
            ])
        
        table = Table(data, colWidths=[60, 80, 100, 60, 60, 60, 60, 80])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]))
        elements.append(table)
    
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'maintenance_report_{datetime.now().strftime("%Y%m%d")}.pdf',
        mimetype='application/pdf'
    )

@app.route('/reports/export/excel')
@login_required
def export_excel():
    uid = session['user']
    
    # Get filter parameters
    equipment_id = request.args.get('equipment_id', type=int)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    technician = request.args.get('technician')
    maintenance_type = request.args.get('type')
    
    # Build query
    query = MaintenanceLog.query.join(Equipment).filter(Equipment.user_id == uid)
    
    if equipment_id:
        query = query.filter(MaintenanceLog.equipment_id == equipment_id)
    if start_date:
        query = query.filter(MaintenanceLog.date >= start_date)
    if end_date:
        query = query.filter(MaintenanceLog.date <= end_date)
    if technician:
        query = query.filter(MaintenanceLog.technician.ilike(f'%{technician}%'))
    if maintenance_type:
        query = query.filter(MaintenanceLog.type == maintenance_type)
    
    logs = query.order_by(MaintenanceLog.date.desc()).all()
    
    # Create CSV
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    
    # Headers
    writer.writerow([
        'Date', 'Equipment', 'Model', 'Issue', 'Type', 'Priority', 'Status', 
        'Cost', 'Technician', 'Parts Replaced', 'Remarks', 'Notes'
    ])
    
    # Data
    for log in logs:
        equipment = Equipment.query.get(log.equipment_id)
        writer.writerow([
            log.date,
            equipment.name if equipment else "Unknown",
            equipment.model if equipment else "",
            log.issue,
            log.type,
            log.priority,
            log.status,
            log.cost or 0,
            log.technician or "",
            log.parts_replaced or "",
            log.remarks or "",
            log.notes or ""
        ])
    
    buffer.seek(0)
    csv_data = buffer.getvalue()
    
    # Create response
    response = io.BytesIO()
    response.write(csv_data.encode('utf-8'))
    response.seek(0)
    
    return send_file(
        response,
        as_attachment=True,
        download_name=f'maintenance_report_{datetime.now().strftime("%Y%m%d")}.csv',
        mimetype='text/csv'
    )

# UPLOAD DOCUMENT
@app.route('/equipment/<int:id>/upload', methods=['POST'])
@login_required
def upload_document(id):
    asset = Equipment.query.get_or_404(id)
    if asset.user_id != session['user']:
        flash("Access Denied", "error")
        return redirect(url_for('equipment_detail', id=id))

    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('equipment_detail', id=id))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('equipment_detail', id=id))

    if file and allowed_file(file.filename, app.config['ALLOWED_EXTENSIONS']):
        # Unique filename to avoid overwrite
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"{timestamp}_{secure_filename(file.filename)}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        doc = Document(
            equipment_id=id,
            filename=filename,
            filepath=filepath,
            upload_date=datetime.today().strftime('%Y-%m-%d')
        )
        db.session.add(doc)
        db.session.commit()
        flash('File uploaded successfully', 'success')
    else:
        flash('File type not allowed', 'error')

    return redirect(url_for('equipment_detail', id=id))

# PERFORMANCE METRICS
@app.route('/equipment/<int:id>/metrics')
@login_required
def equipment_metrics(id):
    asset = Equipment.query.get_or_404(id)
    
    if asset.user_id != session['user']:
        flash("Access Denied", "error")
        return redirect('/equipment')
    
    metrics = Metric.query.filter_by(equipment_id=id).order_by(Metric.timestamp.desc()).all()
    return render_template('equipment_metrics.html', asset=asset, metrics=metrics)

@app.route('/equipment/<int:id>/metrics/add', methods=['GET', 'POST'])
@login_required
@admin_or_technician_required
def equipment_metrics_add(id):
    asset = Equipment.query.get_or_404(id)
    
    if asset.user_id != session['user']:
        flash("Access Denied", "error")
        return redirect('/equipment')
    
    if request.method == 'POST':
        try:
            metric = Metric(
                user_id=session['user'],
                equipment_id=id,
                name=request.form['name'],
                value=float(request.form['value']),
                unit=request.form.get('unit', ''),
                category=request.form.get('category', 'Performance')
            )
            db.session.add(metric)
            db.session.commit()
            
            # Check thresholds
            thresholds = Threshold.query.filter_by(
                equipment_id=id,
                metric_name=metric.name,
                enabled=True
            ).all()
            
            for threshold in thresholds:
                alert_triggered = False
                message = ""
                if threshold.min_value is not None and metric.value < threshold.min_value:
                    alert_triggered = True
                    message = f"{metric.name} below threshold: {metric.value} {metric.unit} (min: {threshold.min_value})"
                elif threshold.max_value is not None and metric.value > threshold.max_value:
                    alert_triggered = True
                    message = f"{metric.name} above threshold: {metric.value} {metric.unit} (max: {threshold.max_value})"
                
                if alert_triggered:
                    alert = Alert(
                        equipment_id=id,
                        title=f"Performance Threshold Alert",
                        message=message,
                        severity=threshold.severity,
                        status="Active"
                    )
                    db.session.add(alert)
            
            db.session.commit()
            flash("Metric added successfully!", "success")
            return redirect(f'/equipment/{id}/metrics')
        except Exception as e:
            print("Metric add error:", e)
            db.session.rollback()
            flash("Failed to add metric!", "error")
    
    return render_template('equipment_metrics_add.html', asset=asset)

# THRESHOLDS MANAGEMENT
@app.route('/thresholds')
@login_required
def thresholds_list():
    thresholds = Threshold.query.filter_by(user_id=session['user']).all()
    return render_template('thresholds.html', thresholds=thresholds)

@app.route('/thresholds/add', methods=['GET', 'POST'])
@login_required
@admin_or_technician_required
def threshold_add():
    if request.method == 'POST':
        try:
            threshold = Threshold(
                user_id=session['user'],
                equipment_id=request.form.get('equipment_id') or None,
                metric_name=request.form['metric_name'],
                min_value=float(request.form.get('min_value') or 0) if request.form.get('min_value') else None,
                max_value=float(request.form.get('max_value') or 0) if request.form.get('max_value') else None,
                severity=request.form['severity'],
                enabled=request.form.get('enabled') == 'on'
            )
            db.session.add(threshold)
            db.session.commit()
            flash("Threshold added successfully!", "success")
            return redirect('/thresholds')
        except Exception as e:
            print("Threshold add error:", e)
            db.session.rollback()
            flash("Failed to add threshold!", "error")
    
    assets = Equipment.query.filter_by(user_id=session['user']).all()
    return render_template('threshold_add.html', assets=assets)

@app.route('/thresholds/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_or_technician_required
def threshold_edit(id):
    threshold = Threshold.query.get_or_404(id)
    if threshold.user_id != session['user']:
        flash("Access Denied", "error")
        return redirect('/thresholds')
    
    if request.method == 'POST':
        try:
            threshold.metric_name = request.form['metric_name']
            threshold.min_value = float(request.form.get('min_value') or 0) if request.form.get('min_value') else None
            threshold.max_value = float(request.form.get('max_value') or 0) if request.form.get('max_value') else None
            threshold.severity = request.form['severity']
            threshold.enabled = request.form.get('enabled') == 'on'
            threshold.equipment_id = request.form.get('equipment_id') or None
            
            db.session.commit()
            flash("Threshold updated successfully!", "success")
            return redirect('/thresholds')
        except Exception as e:
            print("Threshold edit error:", e)
            db.session.rollback()
            flash("Failed to update threshold!", "error")
    
    assets = Equipment.query.filter_by(user_id=session['user']).all()
    return render_template('threshold_edit.html', threshold=threshold, assets=assets)

@app.route('/thresholds/<int:id>/delete')
@login_required
@admin_or_technician_required
def threshold_delete(id):
    threshold = Threshold.query.get_or_404(id)
    if threshold.user_id != session['user']:
        flash("Access Denied", "error")
        return redirect('/thresholds')
    
    db.session.delete(threshold)
    db.session.commit()
    flash("Threshold deleted successfully!", "success")
    return redirect('/thresholds')

# ---------------- APP ENTRY ----------------
def populate_fake_data():
    # Check if data already exists
    if User.query.count() > 0:
        return

    # Create fake users
    users = [
        User(name='Admin User', email='admin@example.com', password_hash=generate_password_hash('admin123'), role='Admin'),
        User(name='John Technician', email='john@example.com', password_hash=generate_password_hash('tech123'), role='Technician'),
        User(name='Jane User', email='jane@example.com', password_hash=generate_password_hash('user123'), role='User'),
        User(name='Bob Manager', email='bob@example.com', password_hash=generate_password_hash('manager123'), role='User'),
        User(name='Sarah Engineer', email='sarah@example.com', password_hash=generate_password_hash('eng123'), role='Technician'),
        User(name='Mike Operator', email='mike@example.com', password_hash=generate_password_hash('op123'), role='User'),
        User(name='Lisa Supervisor', email='lisa@example.com', password_hash=generate_password_hash('sup123'), role='Admin'),
    ]
    for user in users:
        db.session.add(user)
    db.session.commit()

    # Create extensive fake equipment
    equipments = [
        # IT Equipment
        Equipment(user_id=users[0].id, name='Server Rack 1', model='Dell PowerEdge R740', category='Server', purchase_date='2023-01-15', warranty='2026-01-15', location='Data Center A', status='Active', notes='Primary server rack with 8 blades'),
        Equipment(user_id=users[0].id, name='Network Switch Core', model='Cisco Catalyst 9500', category='Network', purchase_date='2023-03-20', warranty='2026-03-20', location='Data Center A', status='Active', notes='Core network switch 48-port'),
        Equipment(user_id=users[0].id, name='Storage Array', model='NetApp FAS2750', category='Storage', purchase_date='2022-11-10', warranty='2025-11-10', location='Data Center B', status='Active', notes='SAN storage with 50TB capacity'),
        Equipment(user_id=users[0].id, name='Firewall Appliance', model='Palo Alto PA-5220', category='Security', purchase_date='2023-05-15', warranty='2026-05-15', location='Network Room', status='Active', notes='Next-gen firewall'),

        # HVAC Equipment
        Equipment(user_id=users[1].id, name='HVAC Unit Main', model='Carrier 5000', category='HVAC', purchase_date='2022-06-10', warranty='2025-06-10', location='Building 1 Roof', status='Active', notes='Central air conditioning 50-ton unit'),
        Equipment(user_id=users[1].id, name='Chiller System', model='Trane CVHE 500', category='HVAC', purchase_date='2021-08-25', warranty='2024-08-25', location='Mechanical Room', status='Active', notes='Water-cooled chiller 500-ton'),
        Equipment(user_id=users[1].id, name='Air Handler Unit 1', model='York YTAH 200', category='HVAC', purchase_date='2022-02-14', warranty='2025-02-14', location='Floor 2', status='Under Maintenance', notes='Variable air volume handler'),

        # Vehicles & Mobile Equipment
        Equipment(user_id=users[2].id, name='Forklift A1', model='Toyota 8FGU25', category='Vehicle', purchase_date='2021-03-20', warranty='2024-03-20', location='Warehouse A', status='Under Maintenance', notes='Electric forklift 5000lb capacity'),
        Equipment(user_id=users[2].id, name='Forklift B2', model='Hyster H50XM', category='Vehicle', purchase_date='2020-09-15', warranty='2023-09-15', location='Warehouse B', status='Active', notes='Diesel forklift 10000lb capacity'),
        Equipment(user_id=users[2].id, name='Scissor Lift', model='Genie GS-2632', category='Vehicle', purchase_date='2022-07-08', warranty='2025-07-08', location='Maintenance Garage', status='Active', notes='26ft scissor lift'),
        Equipment(user_id=users[2].id, name='Company Van', model='Ford Transit 250', category='Vehicle', purchase_date='2023-01-10', warranty='2026-01-10', location='Fleet Parking', status='Active', notes='Service van with tool storage'),

        # Production Equipment
        Equipment(user_id=users[3].id, name='Conveyor Belt Main', model='BeltMaster 200', category='Conveyor', purchase_date='2020-11-05', warranty='2023-11-05', location='Production Line 1', status='Active', notes='Main production conveyor 200ft'),
        Equipment(user_id=users[3].id, name='Packaging Machine', model='Rovema BPA 250', category='Machinery', purchase_date='2021-12-01', warranty='2024-12-01', location='Packaging Area', status='Active', notes='Vertical form-fill-seal machine'),
        Equipment(user_id=users[3].id, name='Palletizer Robot', model='Fanuc M-410iC', category='Robot', purchase_date='2022-04-18', warranty='2025-04-18', location='Palletizing Station', status='Active', notes='6-axis robotic palletizer'),
        Equipment(user_id=users[3].id, name='Quality Scanner', model='Cognex In-Sight 7800', category='Inspection', purchase_date='2023-06-12', warranty='2026-06-12', location='Quality Control', status='Active', notes='Vision inspection system'),

        # Power & Backup Systems
        Equipment(user_id=users[4].id, name='Generator Backup Main', model='Cummins 100kW', category='Generator', purchase_date='2019-08-12', warranty='2022-08-12', location='Backup Power Room', status='Active', notes='Emergency power generator 100kW'),
        Equipment(user_id=users[4].id, name='UPS System A', model='APC Symmetra PX 40kW', category='UPS', purchase_date='2022-10-05', warranty='2025-10-05', location='Data Center A', status='Active', notes='Uninterruptible power supply'),
        Equipment(user_id=users[4].id, name='Transformer Main', model='Siemens 500kVA', category='Electrical', purchase_date='2018-03-20', warranty='2021-03-20', location='Electrical Room', status='Active', notes='Main power transformer'),

        # Workshop Equipment
        Equipment(user_id=users[5].id, name='CNC Machine', model='Haas VF-2', category='Machinery', purchase_date='2022-09-15', warranty='2025-09-15', location='Workshop', status='Active', notes='3-axis CNC milling machine'),
        Equipment(user_id=users[5].id, name='Welding Station', model='Miller Syncrowave 250', category='Welding', purchase_date='2021-07-22', warranty='2024-07-22', location='Fabrication Shop', status='Active', notes='TIG welding equipment'),
        Equipment(user_id=users[5].id, name='Lathe Machine', model='Hardinge HLV-H', category='Machinery', purchase_date='2020-05-10', warranty='2023-05-10', location='Machine Shop', status='Active', notes='Precision lathe'),
        Equipment(user_id=users[5].id, name='Drill Press', model='Jet JDP-20MF', category='Machinery', purchase_date='2021-11-30', warranty='2024-11-30', location='Workshop', status='Under Maintenance', notes='20" floor drill press'),

        # Material Handling
        Equipment(user_id=users[6].id, name='Pallet Jack A1', model='Raymond 8410', category='Vehicle', purchase_date='2020-12-01', warranty='2023-12-01', location='Loading Dock A', status='Inactive', notes='Manual pallet jack'),
        Equipment(user_id=users[6].id, name='Pallet Jack B2', model='Lift-Rite PLJ-2000', category='Vehicle', purchase_date='2022-01-15', warranty='2025-01-15', location='Loading Dock B', status='Active', notes='Electric pallet jack'),
        Equipment(user_id=users[6].id, name='Conveyor Belt Secondary', model='Dorner 2200', category='Conveyor', purchase_date='2021-06-08', warranty='2024-06-08', location='Production Line 2', status='Active', notes='Secondary conveyor system'),

        # Safety & Emergency Equipment
        Equipment(user_id=users[0].id, name='Fire Suppression System', model='Ansul R-102', category='Safety', purchase_date='2018-05-10', warranty='2021-05-10', location='Chemical Storage', status='Active', notes='Automatic fire suppression'),
        Equipment(user_id=users[0].id, name='Emergency Lighting', model='Lithonia ELM2', category='Safety', purchase_date='2020-02-28', warranty='2023-02-28', location='All Floors', status='Active', notes='Emergency exit lighting system'),
        Equipment(user_id=users[0].id, name='First Aid Station', model='Medique 600', category='Safety', purchase_date='2022-08-15', warranty='2025-08-15', location='Main Lobby', status='Active', notes='Automated external defibrillator included'),

        # Additional Equipment
        Equipment(user_id=users[1].id, name='Boiler System', model='Cleaver-Brooks CB-200', category='HVAC', purchase_date='2019-11-20', warranty='2022-11-20', location='Boiler Room', status='Active', notes='Steam boiler 200HP'),
        Equipment(user_id=users[1].id, name='Pump System Main', model='Goulds 10BF1C1D0', category='Pump', purchase_date='2021-04-05', warranty='2024-04-05', location='Pump Station', status='Active', notes='Centrifugal pump system'),
        Equipment(user_id=users[2].id, name='Reach Truck', model='Raymond 7500', category='Vehicle', purchase_date='2022-12-10', warranty='2025-12-10', location='Warehouse A', status='Active', notes='Narrow aisle reach truck'),
        Equipment(user_id=users[3].id, name='Filling Machine', model='Krones Contiform', category='Machinery', purchase_date='2023-02-20', warranty='2026-02-20', location='Filling Line', status='Active', notes='Bottle filling and capping machine'),
        Equipment(user_id=users[4].id, name='Solar Inverter', model='SMA Sunny Tripower', category='Electrical', purchase_date='2023-04-01', warranty='2026-04-01', location='Roof Solar Array', status='Active', notes='Solar power inverter 50kW'),
        Equipment(user_id=users[5].id, name='3D Printer', model='Stratasys Fortus 450mc', category='Machinery', purchase_date='2022-08-30', warranty='2025-08-30', location='Prototyping Lab', status='Active', notes='Production-grade 3D printer'),
    ]
    for eq in equipments:
        db.session.add(eq)
    db.session.commit()

    # Create extensive fake maintenance logs
    logs = [
        # Server maintenance
        MaintenanceLog(equipment_id=equipments[0].id, issue='Routine server check', type='Preventive', priority='Low', status='Completed', cost=150.0, date='2025-01-10', technician='John Technician', parts_replaced='Air filters', remarks='All systems normal', notes='Monthly server maintenance', recurrence='monthly', reminder_date='2025-02-10'),
        MaintenanceLog(equipment_id=equipments[0].id, issue='Firmware update', type='Preventive', priority='Medium', status='Completed', cost=0.0, date='2025-11-15', technician='Sarah Engineer', parts_replaced='', remarks='Updated to latest firmware', notes='Security patches applied', recurrence='quarterly', reminder_date='2025-02-15'),

        # Network equipment
        MaintenanceLog(equipment_id=equipments[1].id, issue='Port configuration', type='Corrective', priority='Medium', status='Completed', cost=75.0, date='2025-12-01', technician='John Technician', parts_replaced='Cable patch', remarks='Fixed port issues', notes='Network optimization', recurrence='', reminder_date=''),

        # HVAC maintenance
        MaintenanceLog(equipment_id=equipments[4].id, issue='Filter replacement', type='Corrective', priority='Medium', status='Pending', cost=0.0, date='2025-12-20', technician='Jane User', parts_replaced='', remarks='Needs urgent attention', notes='HVAC not cooling properly', recurrence='weekly', reminder_date='2025-12-27'),
        MaintenanceLog(equipment_id=equipments[5].id, issue='Refrigerant check', type='Preventive', priority='High', status='Completed', cost=200.0, date='2025-10-20', technician='Mike Operator', parts_replaced='Refrigerant', remarks='Recharged system', notes='Quarterly inspection', recurrence='quarterly', reminder_date='2026-01-20'),

        # Vehicle maintenance
        MaintenanceLog(equipment_id=equipments[7].id, issue='Battery replacement', type='Emergency', priority='High', status='In Progress', cost=300.0, date='2025-12-15', technician='Bob Manager', parts_replaced='Battery pack', remarks='Forklift out of service', notes='Safety issue', recurrence='', reminder_date='2025-12-25'),
        MaintenanceLog(equipment_id=equipments[8].id, issue='Tire replacement', type='Corrective', priority='Medium', status='Completed', cost=400.0, date='2025-11-08', technician='Jane User', parts_replaced='4 tires', remarks='Wear and tear', notes='Regular replacement', recurrence='yearly', reminder_date='2026-11-08'),

        # Production equipment
        MaintenanceLog(equipment_id=equipments[10].id, issue='Belt tension adjustment', type='Preventive', priority='Low', status='Completed', cost=50.0, date='2025-11-30', technician='John Technician', parts_replaced='Tensioner', remarks='Preventive maintenance', notes='Regular check', recurrence='monthly', reminder_date='2026-01-30'),
        MaintenanceLog(equipment_id=equipments[11].id, issue='Calibration', type='Preventive', priority='Medium', status='Completed', cost=120.0, date='2025-12-05', technician='Sarah Engineer', parts_replaced='Calibration weights', remarks='Precision maintained', notes='Monthly calibration', recurrence='monthly', reminder_date='2026-01-05'),

        # Power systems
        MaintenanceLog(equipment_id=equipments[14].id, issue='Oil change', type='Preventive', priority='Medium', status='Completed', cost=200.0, date='2025-10-05', technician='Mike Operator', parts_replaced='Engine oil', remarks='Generator maintenance', notes='Quarterly service', recurrence='quarterly', reminder_date='2026-01-05'),
        MaintenanceLog(equipment_id=equipments[15].id, issue='Battery test', type='Preventive', priority='Low', status='Completed', cost=25.0, date='2025-11-12', technician='Lisa Supervisor', parts_replaced='', remarks='All batteries good', notes='Monthly UPS check', recurrence='monthly', reminder_date='2026-01-12'),

        # Workshop equipment
        MaintenanceLog(equipment_id=equipments[17].id, issue='Calibration check', type='Preventive', priority='Low', status='Completed', cost=75.0, date='2025-09-20', technician='John Technician', parts_replaced='Calibration tools', remarks='Precision maintained', notes='Monthly calibration', recurrence='monthly', reminder_date='2025-12-20'),
        MaintenanceLog(equipment_id=equipments[18].id, issue='Torch replacement', type='Corrective', priority='Medium', status='Pending', cost=120.0, date='2025-11-15', technician='Bob Manager', parts_replaced='Tungsten electrode', remarks='Welding quality affected', notes='Replace consumables', recurrence='weekly', reminder_date='2025-12-22'),

        # Material handling
        MaintenanceLog(equipment_id=equipments[22].id, issue='Wheel bearing lubrication', type='Preventive', priority='Low', status='Completed', cost=25.0, date='2025-08-10', technician='Jane User', parts_replaced='Grease', remarks='Smooth operation restored', notes='Bi-weekly maintenance', recurrence='biweekly', reminder_date='2025-12-24'),

        # Safety systems
        MaintenanceLog(equipment_id=equipments[25].id, issue='Pressure test', type='Preventive', priority='High', status='In Progress', cost=180.0, date='2025-12-01', technician='John Technician', parts_replaced='Pressure gauge', remarks='Safety compliance check', notes='Annual inspection', recurrence='yearly', reminder_date='2026-12-01'),
        MaintenanceLog(equipment_id=equipments[26].id, issue='Battery replacement', type='Preventive', priority='Medium', status='Completed', cost=150.0, date='2025-09-15', technician='Sarah Engineer', parts_replaced='Emergency batteries', remarks='All lights functional', notes='Semi-annual maintenance', recurrence='biweekly', reminder_date='2026-03-15'),

        # Additional maintenance logs
        MaintenanceLog(equipment_id=equipments[28].id, issue='Pump seal replacement', type='Corrective', priority='High', status='Completed', cost=350.0, date='2025-10-25', technician='Mike Operator', parts_replaced='Mechanical seal', remarks='Prevented major failure', notes='Emergency repair', recurrence='', reminder_date=''),
        MaintenanceLog(equipment_id=equipments[29].id, issue='Motor bearing grease', type='Preventive', priority='Low', status='Completed', cost=45.0, date='2025-11-18', technician='Bob Manager', parts_replaced='Grease', remarks='Reduced vibration', notes='Monthly lubrication', recurrence='monthly', reminder_date='2026-01-18'),
        MaintenanceLog(equipment_id=equipments[30].id, issue='Hydraulic fluid change', type='Preventive', priority='Medium', status='Pending', cost=180.0, date='2025-12-10', technician='Jane User', parts_replaced='', remarks='Due for service', notes='Annual fluid change', recurrence='yearly', reminder_date='2026-12-10'),
        MaintenanceLog(equipment_id=equipments[31].id, issue='Sensor calibration', type='Preventive', priority='Medium', status='Completed', cost=90.0, date='2025-10-30', technician='Sarah Engineer', parts_replaced='Calibration kit', remarks='Accuracy verified', notes='Quarterly check', recurrence='quarterly', reminder_date='2026-01-30'),
        MaintenanceLog(equipment_id=equipments[32].id, issue='Inverter firmware update', type='Preventive', priority='Low', status='Completed', cost=0.0, date='2025-11-22', technician='Lisa Supervisor', parts_replaced='', remarks='Performance improved', notes='Software update', recurrence='quarterly', reminder_date='2026-02-22'),
        MaintenanceLog(equipment_id=equipments[33].id, issue='Nozzle cleaning', type='Preventive', priority='Low', status='Completed', cost=30.0, date='2025-12-08', technician='John Technician', parts_replaced='Cleaning solution', remarks='Print quality restored', notes='Weekly maintenance', recurrence='weekly', reminder_date='2025-12-15'),
    ]
    for log in logs:
        if log.recurrence:
            log.next_due = calculate_next_due(log.reminder_date, log.recurrence)
        db.session.add(log)
    db.session.commit()

    # Create some metrics
    metrics = [
        Metric(user_id=users[0].id, name='Total Equipment', value=len(equipments), unit='units', category='Equipment'),
        Metric(user_id=users[0].id, name='Active Equipment', value=len([e for e in equipments if e.status == 'Active']), unit='units', category='Equipment'),
        Metric(user_id=users[0].id, name='Maintenance Completed', value=len([l for l in logs if l.status == 'Completed']), unit='logs', category='Maintenance'),
        Metric(user_id=users[0].id, name='Total Maintenance Cost', value=sum(l.cost for l in logs if l.cost), unit='INR', category='Financial'),
        Metric(user_id=users[0].id, name='Pending Tasks', value=len([l for l in logs if l.status == 'Pending']), unit='tasks', category='Maintenance'),
    ]
    for metric in metrics:
        db.session.add(metric)
    db.session.commit()

    # Create some alerts
    alerts = [
        Alert(title='HVAC Filter Replacement Due', message='HVAC Unit Main filter needs replacement', severity='Medium', status='Active', equipment_id=equipments[4].id),
        Alert(title='Forklift Battery Low', message='Forklift A1 battery needs replacement', severity='High', status='Active', equipment_id=equipments[7].id),
        Alert(title='Generator Oil Change Due', message='Generator Backup Main due for oil change', severity='Medium', status='Active', equipment_id=equipments[14].id),
        Alert(title='Welding Torch Replacement', message='Welding Station torch needs replacement', severity='Medium', status='Active', equipment_id=equipments[18].id),
        Alert(title='Emergency Lighting Check', message='Emergency lighting batteries need testing', severity='Low', status='Active', equipment_id=equipments[26].id),
    ]
    for alert in alerts:
        db.session.add(alert)
    db.session.commit()

if __name__ == '__main__':
    # Create tables if not exist
    with app.app_context():
        db.create_all()
        populate_fake_data()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=os.getenv('DEBUG', 'true').lower() == 'true')
