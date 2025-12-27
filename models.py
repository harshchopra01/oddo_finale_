from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='User')  # Admin, Technician, User
    equipment = db.relationship('Equipment', backref='owner', lazy=True)

class Equipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100))
    category = db.Column(db.String(50), nullable=False)
    purchase_date = db.Column(db.String(20))
    warranty = db.Column(db.String(50))
    location = db.Column(db.String(100))
    status = db.Column(db.String(20), default="Active")
    notes = db.Column(db.Text)
    logs = db.relationship('MaintenanceLog', backref='asset', lazy=True)
    metrics = db.relationship('Metric', backref='equipment', lazy=True)
    documents = db.relationship('Document', backref='equipment', lazy=True)

class MaintenanceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    issue = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # Preventive, Corrective, Emergency
    priority = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Critical
    status = db.Column(db.String(20), nullable=False)  # Pending, In Progress, Completed
    cost = db.Column(db.Float)
    date = db.Column(db.String(20))
    technician = db.Column(db.String(100))
    parts_replaced = db.Column(db.Text)
    remarks = db.Column(db.Text)
    notes = db.Column(db.Text)
    recurrence = db.Column(db.String(50))  # daily, weekly, monthly, custom
    next_due = db.Column(db.String(20))
    reminder_date = db.Column(db.String(20))

class Metric(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=True)
    name = db.Column(db.String(100))
    value = db.Column(db.Float)
    unit = db.Column(db.String(20))
    category = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Threshold(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=True)
    metric_name = db.Column(db.String(100))
    min_value = db.Column(db.Float, nullable=True)
    max_value = db.Column(db.Float, nullable=True)
    severity = db.Column(db.String(20), default='Medium')  # Low, Medium, High
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    title = db.Column(db.String(100))
    message = db.Column(db.String(200))
    severity = db.Column(db.String(20))  # Low, Medium, High
    status = db.Column(db.String(20), default='Active')  # Active, Resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    filename = db.Column(db.String(200))
    filepath = db.Column(db.String(300))
    upload_date = db.Column(db.String(20))


# new