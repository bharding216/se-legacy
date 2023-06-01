from . import db
from sqlalchemy.dialects.mysql import BLOB
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import Flask
from sqlalchemy import DateTime, Date, Text

class bids(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bid_number = db.Column(db.String(45))
    title = db.Column(db.String(100))
    type = db.Column(db.String(45))
    organization = db.Column(db.String(100))
    issue_date = db.Column(Date)
    close_date = db.Column(DateTime)
    notes = db.Column(db.String(16000000))
    status = db.Column(db.String(45))

class bid_contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bid_id = db.Column(db.Integer)
    name = db.Column(db.String(100))
    address_1 = db.Column(db.String(100))
    address_2 = db.Column(db.String(100))
    city = db.Column(db.String(100))
    state = db.Column(db.String(25))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(320))

class supplier_login(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(500))
    email = db.Column(db.String(320))
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier_info.id'))
    supplier = db.relationship('supplier_info', backref='supplier_login')

class admin_login(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(500))
    email = db.Column(db.String(320))

class supplier_info(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(45))
    last_name = db.Column(db.String(45))
    company_name = db.Column(db.String(256))
    email = db.Column(db.String(320))
    phone = db.Column(db.String(20))
    duns = db.Column(db.String(12))
    legal_type = db.Column(db.String(45))
    ssn = db.Column(db.String(12))
    ein = db.Column(db.String(12))
    address_1 = db.Column(db.String(100))
    address_2 = db.Column(db.String(100))
    city = db.Column(db.String(100))
    state = db.Column(db.String(25))
    zip_code = db.Column(db.String(25))

class project_meta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500))
    uploaded_by_user_id = db.Column(db.Integer)
    date_time_stamp = db.Column(DateTime)
    filename_uuid = db.Column(db.String(500))
    bid_id = db.Column(db.Integer, db.ForeignKey('bids.id'))
    bid = db.relationship('bids', backref='project_meta')

class applicant_docs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(500))
    date_time_stamp = db.Column(DateTime)
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier_info.id'))
    supplier = db.relationship('supplier_info', backref='applicant_docs')
    bid_id = db.Column(db.Integer, db.ForeignKey('bids.id'))
    bid = db.relationship('bids', backref='applicant_docs')

class chat_history(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_type = db.Column(db.Integer)
    datetime_stamp = db.Column(DateTime)
    comment = db.Column(Text(length=2**24-1))
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier_info.id'))
    supplier = db.relationship('supplier_info', backref='chat_history')
    bid_id = db.Column(db.Integer, db.ForeignKey('bids.id'))
    bid = db.relationship('bids', backref='chat_history')