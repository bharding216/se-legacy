from flask import Blueprint, render_template, request, redirect, flash, url_for, \
    session, send_file, jsonify, make_response, Response, send_from_directory, current_app
from flask_login import login_required, current_user, login_user, logout_user
from sqlalchemy import and_, inspect
from project.models import bids, bid_contact, admin_login, supplier_info, \
    project_meta, supplier_login, applicant_docs, chat_history
from datetime import datetime
import pytz
from dateutil import parser
import datetime
from flask_mail import Message
from . import db, mail
from helpers import generate_sitemap, utc_to_central
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous.exc import BadSignature
from itsdangerous.url_safe import URLSafeSerializer
import os
import base64
import uuid
import string
import shutil
import boto3 
from botocore.exceptions import NoCredentialsError
import requests
from io import BytesIO, StringIO
from werkzeug.datastructures import Headers
import logging
from cryptography.fernet import Fernet
import csv


views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html',
                           user = current_user
                           )


@views.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'
        secret_key = os.getenv('reCAPTCHA_secret_key')
        recaptcha_site_key = os.getenv('reCAPTCHA_site_key')

        # Get the reCAPTCHA response from the form
        recaptcha_response = request.form.get('g-recaptcha-response')
        if recaptcha_response:
            # Verify the reCAPTCHA response using the Google reCAPTCHA API
            response = requests.post(url=f"{VERIFY_URL}?secret={secret_key or ''}&response={recaptcha_response or ''}").json()

            if response['success'] == True:
                first_name = request.form['first_name']
                last_name = request.form['last_name']
                email = request.form['email']
                phone = request.form['phone']
                message = request.form['message']

                if not first_name:
                    error = 'First name is required.'
                elif not email:
                    error = 'Email field is required.'
                elif not message:
                    error = 'Message is required.'
                else:
                    error = None
                
                if not error:
                    msg = Message('New Contact Form Submission',
                                    sender = ("SE Legacy", 'hello@selegacyconnect.org'),
                                    recipients = ['brandon@getsurmount.com',
                                                  'CCallanen@wbpconsult.com'
                                                ]
                                    )
                    

                    msg.html = render_template('contact_email.html',
                                            first_name = first_name,
                                            last_name = last_name,
                                            email = email,
                                            phone = phone,
                                            message = message
                                            )

                    mail.send(msg)

                    return render_template('contact_success.html', 
                                            first_name = first_name,
                                            email = email, 
                                            phone = phone, 
                                            message = message,
                                            user = current_user
                                            )
                else:
                    flash(error, category='error')
                    recaptcha_site_key = os.getenv('reCAPTCHA_site_key')
                    return render_template('contact.html', 
                                           user = current_user,
                                           recaptcha_site_key = recaptcha_site_key,
                                           first_name = first_name,
                                           last_name = last_name,
                                           email = email,
                                           phone = phone,
                                           message = message)


            else:
                flash('Invalid reCAPTCHA. Please try again.')
                return redirect(url_for('views.contact'))
        else:
            flash('Please complete the reCAPTCHA.')
            return redirect(url_for('views.contact'))



    recaptcha_site_key = os.getenv('reCAPTCHA_site_key')
    return render_template('contact.html', 
                           user = current_user,
                           recaptcha_site_key = recaptcha_site_key)




@views.route('/registration-personal', methods=['GET', 'POST'])
def registration_personal():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        company_name = request.form['company_name']
        email = request.form['email']
        phone = request.form['phone']
        password1 = request.form['password1']
        password2 = request.form['password2']

        email_already_exists = db.session.query(db.exists().where(supplier_info.email == email)).scalar()
        if email_already_exists:
            flash('That email is already in use. Please use another email.', category='error')
            return render_template('registration_personal.html',
                                   user = current_user,
                                   first_name = first_name,
                                   last_name = last_name,
                                   company_name = company_name,
                                   email = email,
                                   phone = phone
                                   )


        if password1 != password2:
            flash('Passwords do not match. Please try again.', category='error')
            return render_template('registration_personal.html',
                                   user = current_user,
                                   first_name = first_name,
                                   last_name = last_name,
                                   company_name = company_name,
                                   email = email,
                                   phone = phone
                                   )
        session['first_name'] = first_name
        session['last_name'] = last_name
        session['company_name'] = company_name
        session['email'] = email
        session['phone'] = phone
        session['password'] = generate_password_hash(password1)

        return redirect(url_for('views.registration_location'))

    return render_template('registration_personal.html',
                           user = current_user
                           )


@views.route('/registration-location', methods=['GET', 'POST'])
def registration_location():
    if request.method == "POST":
        address_1 = request.form['address_1']
        address_2 = request.form['address_2']
        city = request.form['city']
        state = request.form['state']
        zip_code = request.form['zip_code']

        session['address_1'] = address_1
        session['address_2'] = address_2
        session['city'] = city
        session['state'] = state
        session['zip_code'] = zip_code

        return redirect(url_for('views.registration_business'))

    return render_template('registration_location.html',
                           user = current_user
                           )


@views.route('/registration-business', methods=['GET', 'POST'])
def registration_business():
    if request.method == "POST":
        legal_structure = request.form['legal_structure']
        session['legal_structure'] = legal_structure

        current_time = datetime.datetime.now().time()
        current_time_str = current_time.strftime('%H:%M:%S')
        s = URLSafeSerializer(os.getenv('secret_key') or 'default-secret-key')

        radio_type = request.form['radio_type']
        if radio_type == 'individual':
            ssn = request.form['ssn']
            ssn_serialized = s.dumps([ssn, current_time_str])

            session['ssn'] = ssn_serialized
            logging.info('ssn_serialized: %s', ssn_serialized)

            with db.session() as db_session:
                new_supplier_info_record = supplier_info()
                new_supplier_info_record.first_name = session['first_name']
                new_supplier_info_record.last_name = session['last_name']
                new_supplier_info_record.company_name = session['company_name']
                new_supplier_info_record.email = session['email']
                new_supplier_info_record.phone = session['phone']
                new_supplier_info_record.address_1 = session['address_1']
                new_supplier_info_record.address_2 = session['address_2']
                new_supplier_info_record.city = session['city']
                new_supplier_info_record.state = session['state']
                new_supplier_info_record.zip_code = session['zip_code']
                new_supplier_info_record.ssn = session['ssn']
                new_supplier_info_record.legal_type = session['legal_structure']
                
                logging.info('new_supplier_info_record: %s', new_supplier_info_record)
                db_session.add(new_supplier_info_record)
                db_session.commit()
                
                new_supplier_info_record_id = new_supplier_info_record.id

                new_supplier_login_record = supplier_login()
                new_supplier_login_record.supplier_id = new_supplier_info_record_id
                new_supplier_login_record.email = session['email']
                new_supplier_login_record.password = session['password']
                db_session.add(new_supplier_login_record)
                db_session.commit()
                logging.info('new supplier login record created!')

        if radio_type == 'company':
            ein = request.form['ein']
            if ein:
                ein_serialized = s.dumps([ein, current_time_str])
                session['ein'] = ein_serialized
                session['duns'] = ""
                logging.info('serialized_ein: %s', ein_serialized)
                logging.info('duns record is not applicable for this user')

            duns = request.form['duns']
            if duns:
                duns_serialized = s.dumps([duns, current_time_str])
                session['duns'] = duns_serialized
                session['ein'] = ""
                logging.info('serialized_duns: %s', duns_serialized)
                logging.info('ein record is not applicable for this user')

            with db.session() as db_session:
                new_supplier_info_record = supplier_info()
                new_supplier_info_record.first_name = session['first_name']
                new_supplier_info_record.last_name = session['last_name']
                new_supplier_info_record.company_name = session['company_name']
                new_supplier_info_record.email = session['email']
                new_supplier_info_record.phone = session['phone']
                new_supplier_info_record.address_1 = session['address_1']
                new_supplier_info_record.address_2 = session['address_2']
                new_supplier_info_record.city = session['city']
                new_supplier_info_record.state = session['state']
                new_supplier_info_record.zip_code = session['zip_code']
                new_supplier_info_record.ein = session['ein']
                new_supplier_info_record.duns = session['duns']
                new_supplier_info_record.legal_type = session['legal_structure']
            
                logging.info('new_supplier_info_record: %s', new_supplier_info_record)
                db_session.add(new_supplier_info_record)
                db_session.commit()

                new_supplier_info_record_id = new_supplier_info_record.id

                new_supplier_login_record = supplier_login()
                new_supplier_login_record.supplier_id = new_supplier_info_record_id
                new_supplier_login_record.email = session['email']
                new_supplier_login_record.password = session['password']
                db_session.add(new_supplier_login_record)
                db_session.commit()
                logging.info('new supplier login record created!')

        flash('New supplier profile created! Please login using your email and password to \
              apply for open bids.', category='success')
        return redirect(url_for('views.index'))

    # Add default return for GET request
    return render_template('registration_business.html', user=current_user)


@views.route('/admin-data-view')
def admin_data_view():
    return render_template('admin_data_view.html', user = current_user)




@views.route('/download-vendor-list')
def download_vendor_list():
    supplier_data = supplier_info.query.all()
    
    csv_output = StringIO()
    csv_writer = csv.writer(csv_output)
    
    inspector = inspect(db.engine)
    columns = [column['name'] for column in inspector.get_columns('supplier_info')]
    csv_writer.writerow(columns)
    
    s = URLSafeSerializer(os.getenv('secret_key') or 'default-secret-key')

    for data in supplier_data:
        if data.ein: # If there is an EIN value present
            ein, current_time_str_ein = s.loads(data.ein)
        else:
            ein = ''

        if data.ssn: # If there is an SSN value present
            ssn, current_time_str_ssn = s.loads(data.ssn)
        else:
            ssn = ''
        if data.duns: # If there is an DUNS value present
            duns, current_time_str_duns = s.loads(data.duns)
        else:
            duns = ''

        row_data = []
        for column in columns:
            if column != 'ein' and column != 'ssn' and column != 'duns':
                value = getattr(data, column)
            elif column == 'ein':
                value = ein
            elif column == 'ssn':
                value = ssn
            elif column == 'duns':
                value = duns

            row_data.append(value)

        csv_writer.writerow(row_data)

    filename = 'supplier_info.csv'
    
    headers = {
        'Content-Disposition': 'attachment; filename=' + filename,
        'Content-Type': 'text/csv'
    }
    
    return Response(
        csv_output.getvalue(),
        mimetype='text/csv',
        headers=headers
    )









@views.route('/manage-project', methods=['GET', 'POST'])
@login_required
def manage_project():
    logging.info("STARTING 'manage_project' VIEW FUNCTION.")
    if request.method == 'POST':
        try:
            files = request.files.getlist('file[]')
            now = datetime.datetime.now()
            date_time_stamp = now.strftime("%Y-%m-%d %H:%M:%S")
            secure_date_time_stamp = secure_filename(date_time_stamp)
            user_id = current_user.id
            project_title = request.form['project_title']
            bid_type = request.form['bid_type']
            organization = request.form['organization']
            issue_date = request.form['issue_date']
            notes = request.form['notes']
            
            close_date = request.form['close_date']
            close_time_central = request.form['close_time']
            datetime_str = close_date + ' ' + close_time_central
            datetime_obj_central = datetime.datetime.strptime(datetime_str, '%Y-%m-%d %H:%M')

            central_timezone = pytz.timezone('US/Central')
            datetime_obj_central_localized = central_timezone.localize(datetime_obj_central)

            utc_timezone = pytz.timezone('UTC')
            datetime_obj_utc = datetime_obj_central_localized.astimezone(utc_timezone)

            # First, create a new project record. Get the project record ID, then
            # use that ID to create a 'project_meta' record for each file that was uploaded.
            new_project_record = {
                'title': project_title,
                'type': bid_type,
                'organization': organization,
                'issue_date': issue_date,
                'close_date': datetime_obj_utc,
                'notes': notes,
                'status': 'open'
            }

            logging.debug("PROJECT RECORD: %s", new_project_record)

            with db.session() as db_session:
                new_project = bids(**new_project_record)
                db_session.add(new_project)
                db_session.commit()
                new_project_id = new_project.id
            logging.info("Added project record with ID: %s", new_project_id)


            # Configure S3 credentials
            s3 = boto3.client('s3', region_name='us-east-1',
                            aws_access_key_id=os.getenv('s3_access_key_id'),
                            aws_secret_access_key=os.getenv('s3_secret_access_key'))
            
            # Set the name of your S3 bucket
            S3_BUCKET = 'se-legacy-bucket'

            for file in files:
                s3_filename = f"{secure_date_time_stamp}_{secure_filename(file.filename or '')}"
                logging.info("Attempting to upload '%s' to S3 as '%s'", file.filename, s3_filename)
                s3.upload_fileobj(file, S3_BUCKET, s3_filename)
                logging.info("Uploaded file '%s' to S3 as '%s'", file.filename, s3_filename)

                new_metadata_record = {
                    'title': file.filename,
                    'uploaded_by_user_id': user_id,
                    'date_time_stamp': date_time_stamp,
                    'bid_id': new_project_id
                }

                with db.session() as db_session:
                    new_project = project_meta(**new_metadata_record)
                    db_session.add(new_project)
                    db_session.commit()
                logging.info("Added new project meta data record to db: %s", new_metadata_record)


            flash('Project created successfully! All files have been uploaded.', 'success')
            logging.info("EXITING 'manage_project' VIEW FUNCTION.")
            return redirect(url_for('views.manage_project'))

        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            logging.info("ERROR MESSAGE", error_message)
            flash(error_message, 'error')
            logging.info("EXITING 'manage_project' VIEW FUNCTION.")
            return redirect(url_for('views.manage_project'))


    # Handle GET request:
    with db.session() as db_session:
        bid_list = db_session.query(bids).all()

        for bid in bid_list:
            close_date_utc = bid.close_date
            close_date_central = utc_to_central(close_date_utc)
            bid.close_date = close_date_central

        return render_template('manage_project.html',
                            user = current_user,
                            bid_list = bid_list
                            )





@views.route('/view-bid-details/<int:bid_id>', methods=['GET', 'POST'])
def view_bid_details(bid_id):
    bid_object = db.session.query(bids) \
                        .filter_by(id = bid_id) \
                        .first()
    if not bid_object:
        flash('Bid not found', category='error')
        return redirect(url_for('views.index'))
        
    if bid_object:
        bid_object = convert_to_central_time(bid_object)
    logging.info('bid_object: %s', bid_object)

    # Collect the docs related to this bid (uploaded by the admin and the vendors)
    project_meta_records = db.session.query(project_meta).filter_by(bid_id = bid_object.id).all()
    applications_for_bid = db.session.query(applicant_docs).filter_by(bid_id = bid_object.id).all()
    logging.info('applications_for_bid: %s', applications_for_bid)

    for application in applications_for_bid:
        application_submitted_datetime_utc = application.date_time_stamp
        application_submitted_datetime_central = utc_to_central(application_submitted_datetime_utc)
        application.date_time_stamp = application_submitted_datetime_central

    vendor_chat_list = []

    if not 'user_type' in session: # user_type key not in session
        logging.info('user_type key not in session.')
        applied_status = 'not applied'
        applications_for_bid_and_supplier = []
        chat_history_records = []

    else:
        logging.info('session_user_type: %s', session['user_type'])

        if session['user_type'] is None: # user is not logged in
            logging.info('user_type key not in session. User is not logged in.')
            applied_status = 'not applied'
            applications_for_bid_and_supplier = []
            chat_history_records = []
        
        else: # user is logged in
            if session['user_type'] == 'supplier':
                try:
                    logging.info('supplier_id: %s', current_user.supplier_id)
                except:
                    logging.info('supplier_id: UNKNOWN')

                logging.info('collecting chat history records for supplier_id: %s', current_user.supplier_id)
                chat_history_records = chat_history.query \
                    .filter_by(supplier_id=current_user.supplier_id, bid_id=bid_id) \
                    .all()

                if chat_history_records:
                    logging.info('found chat_history_records: %s', chat_history_records)

                    # Convert UTC timestamps to Central Time
                    for message in chat_history_records:
                        chat_timestamp_utc = message.datetime_stamp
                        chat_timestamp_central = utc_to_central(chat_timestamp_utc)
                        message.datetime_stamp = chat_timestamp_central

                else: # no chat history
                    chat_history_records = []

                has_applied = db.session.query(applicant_docs) \
                    .filter(and_(applicant_docs.bid_id == bid_id, applicant_docs.supplier_id == current_user.supplier_id)) \
                    .first() is not None # returns true or false

                if has_applied:
                    applied_status = 'applied'

                    applications_for_bid_and_supplier = db.session.query(applicant_docs) \
                                        .filter_by(bid_id = bid_object.id) \
                                        .filter_by(supplier_id = current_user.supplier_id) \
                                        .all()
                                
                else: # supplier has not applied
                    applied_status = 'not applied'
                    applications_for_bid_and_supplier = []

            else: # user is admin
                applied_status = 'not applied'
                applications_for_bid_and_supplier = []
                chat_history_records = []

                # Collect chat records and company name for each supplier
                distinct_supplier_ids = db.session.query(chat_history.supplier_id) \
                    .filter_by(bid_id=bid_id) \
                    .distinct().all()


                supplier_ids = [supplier_id for supplier_id, in distinct_supplier_ids]
                supplier_info_data = db.session.query(supplier_info.id, supplier_info.company_name).\
                    filter(supplier_info.id.in_(supplier_ids)).all()
                vendor_chat_list = {supplier_id: company_name for supplier_id, company_name in supplier_info_data}
                logging.info('vendor_chat_list: %s', vendor_chat_list) # returns: {supplier_id: company_name}

    request_data = request.stream.read()

    logging.info('applied_status: %s', applied_status)
    logging.info('applications_for_bid_and_supplier: %s', applications_for_bid_and_supplier)
    logging.info('chat_history_records: %s', chat_history_records)

    return render_template('view_bid_details.html', 
                            user = current_user,
                            bid_object = bid_object,
                            project_meta_records = project_meta_records,
                            applications_for_bid = applications_for_bid,
                            applied_status = applied_status,
                            chat_history_records = chat_history_records,
                            applications_for_bid_and_supplier = applications_for_bid_and_supplier,
                            vendor_chat_list = vendor_chat_list
                            )


def convert_to_central_time(bid_object):
    close_date_utc = bid_object.close_date
    close_date_central = utc_to_central(close_date_utc)
    bid_object.close_date = close_date_central
    return bid_object



@views.route('/post-chat-message', methods=['GET', 'POST'])
@login_required
def post_chat_message():
    logging.info('ENTERING POST CHAT MESSAGE VIEW FUNCTION')

    message = request.form['message']
    bid_id = request.form['bid_id']
    now = datetime.datetime.utcnow()
    datetime_stamp = now.strftime("%Y-%m-%d %H:%M:%S")

    logging.info('message: %s', message)
    logging.info('bid_id: %s', bid_id)
    logging.info('datetime_stamp: %s', datetime_stamp)

    bid_object = db.session.query(bids).filter_by(id=bid_id).first()

    with db.session() as db_session:

        if session['user_type'] == 'supplier':
            logging.info('User is a supplier.')
            author_type = 'vendor'
            supplier_id = current_user.supplier_id
            supplier_object = db_session.query(supplier_info).filter_by(id=supplier_id).first()
            logging.info('supplier_id: %s', supplier_id)

            new_comment = chat_history()
            new_comment.author_type = author_type
            new_comment.datetime_stamp = datetime_stamp
            new_comment.comment = message
            new_comment.bid_id = bid_id
            new_comment.supplier_id = supplier_id
            
            db.session.add(new_comment)
            db.session.commit()
            logging.info('new_comment: %s', new_comment)

            logging.info('Sending email to admin...')
            admin_msg = Message('New Comment on Bid',
                            sender = ("SE Legacy", 'hello@selegacyconnect.org'),
                            recipients = ['brandon@getsurmount.com',
                                        #   'CCallanen@wbpconsult.com'
                                        ]
                            )
            
            admin_msg.html = render_template('new_comment_email_to_admin.html',
                                    bid_object=bid_object,
                                    supplier_object=supplier_object
                                    )
            
            mail.send(admin_msg)

            flash('New comment successfully added! We\'ll get back to you soon.', category='success')
            return redirect(url_for('views.view_bid_details', bid_id=bid_id))

        elif session['user_type'] == 'admin':
            logging.info('User is an admin.')
            author_type = 'admin'
            supplier_id = request.form['supplier_id']
            supplier_object = db_session.query(supplier_info).filter_by(id=supplier_id).first()
            logging.info('supplier_id: %s', supplier_id)

            new_comment = chat_history()
            new_comment.author_type = author_type
            new_comment.datetime_stamp = datetime_stamp
            new_comment.comment = message
            new_comment.bid_id = bid_id
            new_comment.supplier_id = supplier_id
            logging.info('new_comment: %s', new_comment)

            db.session.add(new_comment)
            db.session.commit()
            logging.info('New comment successfully added to db.')

            logging.info('Sending email to vendor...')

            try:
                vendor_msg = Message('SE Legacy replied to your comment',
                                sender = ("SE Legacy", 'hello@selegacyconnect.org'),
                                recipients = [supplier_object.email if supplier_object else 'brandon@getsurmount.com'
                                            ]
                                )
                
                vendor_msg.html = render_template('new_comment_email_to_vendor.html',
                                        bid_object=bid_object
                                        )
                
                mail.send(vendor_msg)
                logging.info('Email sent to vendor: %s', supplier_object.email if supplier_object else 'unknown')
            
            except Exception as e:
                logging.error('Error sending email to vendor: %s', str(e))
                # Send Brandon an email
                msg = Message('Error sending email to vendor',
                                sender = ("SE Legacy" 'hello@selegacyconnect.org'),
                                recipients = ['brandon@getsurmount.com']
                                )
                msg.html = f"Error sending email to vendor: {str(e)}"
                mail.send(msg)

                # If the email fails to send, log the error and send an email to Brandon
                # Everything should look normal to the user (admin)
                flash('New comment successfully added!', category='success')
                return redirect(url_for('views.view_application', 
                                bid_id=bid_id,
                                supplier_id=supplier_id
                                ))

            flash('New comment successfully added!', category='success')
            return redirect(url_for('views.view_bid_details', bid_id=bid_id))

        else:
            return 'Error: Session user_type not set'





@views.route('/applications-summary-page', methods=['GET', 'POST'])
@login_required
def applications_summary_page():
    with db.session() as db_session:
        supplier_id = current_user.supplier_id

        bid_ids = [row.bid_id for row in applicant_docs.query.filter_by(supplier_id=supplier_id).all()]
    
        bid_list = bids.query.filter(bids.id.in_(bid_ids)).all() # list of bid objects

        for bid in bid_list:
            close_date_utc = bid.close_date
            close_date_central = utc_to_central(close_date_utc)
            bid.close_date = close_date_central

        logging.info('supplier_id: %s', supplier_id)
        logging.info('bid_ids: %s', bid_ids)
        logging.info('bid_list: %s', bid_list)

        return render_template('applications_summary_page.html',
                            bid_list = bid_list,
                            user = current_user
                            )




@views.route('/view-vendor-chats/<int:bid_id>/<int:supplier_id>', methods=['GET', 'POST'])
@login_required
def view_vendor_chats(bid_id, supplier_id):
    chat_history_records = chat_history.query \
        .filter_by(supplier_id=supplier_id, bid_id=bid_id) \
        .all()

    central_tz = pytz.timezone('America/Chicago')  # Set the timezone to Central Time
    for message in chat_history_records:
        utc_datetime = message.datetime_stamp
        central_datetime = utc_datetime.replace(tzinfo=pytz.utc).astimezone(central_tz)
        message.datetime_stamp = central_datetime

    return render_template('view_vendor_chats.html', 
                            user = current_user,
                            chat_history_records = chat_history_records,
                            supplier_id = supplier_id,
                            bid_id = bid_id)





@views.route('/view-application/<int:bid_id>/<int:supplier_id>', methods=['GET', 'POST'])
@login_required
def view_application(bid_id, supplier_id):
    with db.session() as db_session:
        bid_object = db_session.query(bids) \
                            .filter_by(id = bid_id) \
                            .first()

        applications_for_bid_and_supplier = db_session.query(applicant_docs) \
                                        .filter_by(bid_id = bid_object.id if bid_object else None) \
                                        .filter_by(supplier_id = supplier_id) \
                                        .all()

        chat_history_records = chat_history.query \
            .filter_by(supplier_id=supplier_id, bid_id=bid_id) \
            .all()

        central_tz = pytz.timezone('America/Chicago')  # Set the timezone to Central Time
        for message in chat_history_records:
            utc_datetime = message.datetime_stamp
            central_datetime = utc_datetime.replace(tzinfo=pytz.utc).astimezone(central_tz)
            message.datetime_stamp = central_datetime

        return render_template('view_application.html', 
                                user = current_user,
                                bid_object = bid_object,
                                applications_for_bid_and_supplier = applications_for_bid_and_supplier,
                                chat_history_records = chat_history_records,
                                supplier_id = supplier_id)




@views.route('/apply-for-bid', methods=['GET', 'POST'])
@login_required
def apply_for_bid():
    if request.method == 'POST':
        files = request.files.getlist('file[]')
        bid_id = request.form['bid_id']
        bid = bids.query.get(bid_id)
        if not bid:
            flash('Bid not found', category='error')
            return redirect(url_for('views.index'))
        
        close_date_utc = bid.close_date

        if current_user.supplier_id:
            supplier_id = current_user.supplier_id
        else: # user is logged in as admin
            flash('Please log in as a vendor to apply to this bid.', category='error')
            return redirect(url_for('views.view_bid_details', bid_id=bid_id))
        
        now = datetime.datetime.utcnow()

        logging.info('close_date_utc: %s', close_date_utc)
        logging.info('current_datetime_utc: %s', now)
        logging.info('supplier_id: %s', supplier_id)
        logging.info('bid object: %s', bid)

        if close_date_utc < now: # all times in UTC
            flash('The close date for this bid has passed. Please contact us if you have any questions.', category='error')
            return redirect(url_for('views.view_bid_details', bid_id=bid_id))

        date_time_stamp = now.strftime("%Y-%m-%d %H:%M:%S")      
        secure_date_time_stamp = secure_filename(date_time_stamp)

        s3 = boto3.client('s3', region_name='us-east-1',
                        aws_access_key_id=os.getenv('s3_access_key_id'),
                        aws_secret_access_key=os.getenv('s3_secret_access_key'))
        
        S3_BUCKET = 'se-legacy-bucket'

        for file in files:
            s3_filename = f"{secure_date_time_stamp}_{secure_filename(file.filename or '')}"
            s3.upload_fileobj(file, S3_BUCKET, s3_filename)

            new_applicant_record = {
                'filename': file.filename,
                'date_time_stamp': date_time_stamp,
                'supplier_id': supplier_id,
                'bid_id': bid_id
            }

            with db.session() as db_session:
                new_application = applicant_docs(**new_applicant_record)
                db_session.add(new_application)
                db_session.commit()

        flash('Your application was successfully submitted! Feel free to log out. We will \
              contact you via email or phone with next steps. Scroll down to view your application documents.', \
                category='success')

        bid_object = db_session.query(bids) \
                            .filter_by(id = bid_id) \
                            .first()

        supplier_object = db_session.query(supplier_info) \
                                        .filter_by(id = supplier_id) \
                                        .first()

        admin_msg = Message('New Application Submitted',
                        sender = ("SE Legacy", 'hello@selegacyconnect.org'),
                        recipients = ['brandon@getsurmount.com',
                                      'CCallanen@wbpconsult.com'
                                    ]
                        )
        
        admin_msg.html = render_template('new_application_email.html',
                                bid_object=bid_object,
                                supplier_object=supplier_object
                                )
        
        mail.send(admin_msg)

        msg_to_vendor = Message('Thank You For Applying',
                        sender = ("SE Legacy", 'hello@selegacyconnect.org'),
                        recipients = [supplier_object.email if supplier_object else 'brandon@getsurmount.com'
                                    ]
                        )

        msg_to_vendor.html = render_template('new_app_email_to_vendor.html',
                                bid_object = bid_object,
                                supplier_object = supplier_object
                                )

        mail.send(msg_to_vendor)


        return redirect(url_for('views.view_bid_details', bid_id=bid_id))
    
        # return render_template('view_bid_details.html', 
        #                         user = current_user,
        #                         bid_object = bid_object,
        #                         project_meta_records = project_meta_records,
        #                         applied_status = applied_status,
        #                         applications_for_bid_and_supplier = applications_for_bid_and_supplier,
        #                         applications_for_bid = applications_for_bid,
        #                         supplier_object = supplier_object
        #                         )


    else: # user is trying to send a GET request
        logging.info('User trying to send a GET request to "apply-for-bid" view function.')
        return 'This URL only accepts POST requests. Please return to the SE Legacy homepage.'





@views.route('/download-application-doc', methods = ['GET', 'POST'])
def download_application_doc():
    if request.method == 'POST':
        filename = request.form['filename']
        date_time_stamp = request.form['date_time_stamp']
        secure_date_time_stamp = secure_filename(date_time_stamp)

        dt = parser.parse(date_time_stamp)
        ct_timezone = pytz.timezone('America/Chicago')
        ct_datetime = dt.astimezone(ct_timezone)
        utc_datetime = ct_datetime.astimezone(pytz.utc)
        utc_timestamp = utc_datetime.strftime('%Y-%m-%d %H:%M:%S')

        secure_date_time_stamp = secure_filename(utc_timestamp)

        s3_filename = f"{secure_date_time_stamp}_{secure_filename(filename or '')}"

        s3 = boto3.client('s3', region_name='us-east-1',
                        aws_access_key_id=os.getenv('s3_access_key_id'),
                        aws_secret_access_key=os.getenv('s3_secret_access_key'))

        logging.info('central_date_time_stamp: %s', date_time_stamp)
        logging.info('utc_date_time_stamp: %s', utc_timestamp)
        logging.info('s3_filename: %s', s3_filename)

        S3_BUCKET = 'se-legacy-bucket'

        url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={
                'Bucket': S3_BUCKET,
                'Key': s3_filename
            },
            ExpiresIn=3600
        )

        response = requests.get(url)

        download_filename = secure_filename(filename)

        headers = Headers()
        headers.add('Content-Disposition', 'attachment', filename=download_filename)
        response.headers['Content-Disposition'] = 'attachment; filename=' + download_filename

        return Response(BytesIO(response.content), headers=headers)
    
    # Add default return for GET requests
    return redirect(url_for('views.index'))


@views.route('/delete-application-doc', methods = ['GET', 'POST'])
@login_required
def delete_application_doc():
    bid_id = request.form['bid_id']
    doc_id = request.form['doc_id']
    filename = request.form['filename']
    date_time_stamp = request.form['date_time_stamp']
    secure_date_time_stamp = secure_filename(date_time_stamp)
    supplier_id = current_user.supplier.id

    s3_filename = f"{secure_date_time_stamp}_{secure_filename(filename or '')}"

    s3 = boto3.client('s3', region_name='us-east-1',
                    aws_access_key_id=os.getenv('s3_access_key_id'),
                    aws_secret_access_key=os.getenv('s3_secret_access_key'))

    S3_BUCKET = 'se-legacy-bucket'

    s3.delete_object(Bucket=S3_BUCKET, Key=s3_filename)

    with db.session() as db_session:
        record_to_delete = db_session.query(applicant_docs).get(doc_id)
        db_session.delete(record_to_delete)
        db_session.commit()

        applications_for_bid_and_supplier = db_session.query(applicant_docs) \
                                                    .filter_by(bid_id = bid_id) \
                                                    .filter(applicant_docs.supplier_id == supplier_id) \
                                                    .all()

        if applications_for_bid_and_supplier is not None:
            applied_status = 'applied'
        else:
            applied_status = 'not applied'

        flash('Document deleted successfully.', 'success')
        bid_object = db_session.query(bids) \
                                .filter_by(id = bid_id) \
                                .first()

        project_meta_records = db_session.query(project_meta) \
                                            .filter_by(bid_id = bid_object.id if bid_object else None) \
                                            .all()

        return redirect(url_for('views.view_bid_details',
                                bid_id = bid_object.id if bid_object else None))



@views.route('/upload-doc', methods=['GET', 'POST'])
def upload_doc():
    if request.method == 'POST':
        bid_id = request.form['bid_id']
        files = request.files.getlist('file[]')
        now = datetime.datetime.utcnow()
        date_time_stamp = now.strftime("%Y-%m-%d %H:%M:%S")
        secure_date_time_stamp = secure_filename(date_time_stamp)
        user_id = current_user.id

        # Configure S3 credentials
        s3 = boto3.client('s3', region_name='us-east-1',
                        aws_access_key_id=os.getenv('s3_access_key_id'),
                        aws_secret_access_key=os.getenv('s3_secret_access_key'))
        
        # Set the name of your S3 bucket
        S3_BUCKET = 'se-legacy-bucket'

        for file in files:
            s3_filename = f"{secure_date_time_stamp}_{secure_filename(file.filename or '')}"
            s3.upload_fileobj(file, S3_BUCKET, s3_filename)

            new_metadata_record = {
                'title': file.filename,
                'uploaded_by_user_id': user_id,
                'date_time_stamp': date_time_stamp,
                'bid_id': bid_id
            }

            with db.session() as db_session:
                new_project = project_meta(**new_metadata_record)
                db_session.add(new_project)
                db_session.commit()

        flash('File(s) uploaded successfully!', 'success')

        return redirect(url_for('views.view_bid_details',
                                bid_id = bid_id))
    
    # Add default return for GET requests
    return redirect(url_for('views.index'))






@views.route('/download-project', methods = ['GET', 'POST'])
def download_project():
    if request.method == 'POST':
        filename = request.form['filename']
        date_time_stamp = request.form['date_time_stamp']
        secure_date_time_stamp = secure_filename(date_time_stamp)

        s3_filename = f"{secure_date_time_stamp}_{secure_filename(filename or '')}"

        s3 = boto3.client('s3', region_name='us-east-1',
                        aws_access_key_id=os.getenv('s3_access_key_id'),
                        aws_secret_access_key=os.getenv('s3_secret_access_key'))

        S3_BUCKET = 'se-legacy-bucket'

        url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={
                'Bucket': S3_BUCKET,
                'Key': s3_filename
            },
            ExpiresIn=3600
        )

        response = requests.get(url)
        download_filename = secure_filename(filename)

        headers = {
            'Content-Disposition': f'attachment; filename="{download_filename}"',
            'Content-Type': 'application/pdf'  # Specify the content type as PDF
        }

        msg = Message('Document Downloaded', 
                      sender = ("SE Legacy", 'hello@selegacyconnect.org'),
                      recipients=['CCallanen@wbpconsult.com']
                      )

        if current_user.is_authenticated:
            msg.body = f"The document '{filename}' was downloaded by {current_user.email}."
        else:
            msg.body = f"The document '{filename}' was downloaded by a guest user."

        try:
            mail.send(msg)
        except Exception as e:
            print(f"Error sending email notification: {str(e)}")
            logging.error('experienced an error: %s', str(e))


        return Response(BytesIO(response.content), headers=headers)
    
    # Add default return for GET requests
    return redirect(url_for('views.index'))










@views.route('/delete-doc', methods = ['GET', 'POST'])
@login_required
def delete_doc():
    bid_id = request.form['bid_id']
    doc_id = request.form['doc_id']
    filename = request.form['filename']
    date_time_stamp = request.form['date_time_stamp']
    secure_date_time_stamp = secure_filename(date_time_stamp)

    s3_filename = f"{secure_date_time_stamp}_{secure_filename(filename or '')}"

    # Configure S3 credentials
    s3 = boto3.client('s3', region_name='us-east-1',
                    aws_access_key_id=os.getenv('s3_access_key_id'),
                    aws_secret_access_key=os.getenv('s3_secret_access_key'))

    # Set the name of your S3 bucket
    S3_BUCKET = 'se-legacy-bucket'

    s3.delete_object(Bucket=S3_BUCKET, Key=s3_filename)

    # Then delete the meta data from the project_meta table.
    with db.session() as db_session:
        record_to_delete = db_session.query(project_meta).get(doc_id)
        db_session.delete(record_to_delete)
        db_session.commit()

    flash('Document deleted successfully.', 'success')
    bid_object = db_session.query(bids) \
                            .filter_by(id = bid_id) \
                            .first()

    project_meta_records = db_session.query(project_meta) \
                                        .filter_by(bid_id = bid_object.id if bid_object else None) \
                                        .all()

    return render_template('view_bid_details.html', 
                            user = current_user,
                            bid_object = bid_object,
                            project_meta_records = project_meta_records)




@views.route('/delete-project', methods = ['GET', 'POST'])
@login_required
def delete_project():
    if request.method == 'POST':
        bid_id = request.form['bid_id']

        with db.session() as db_session:
            project_meta_records_to_delete = db_session.query(project_meta) \
                                                       .filter_by(bid_id = bid_id) \
                                                       .all()

            # Configure S3 credentials
            s3 = boto3.client('s3', region_name='us-east-1',
                            aws_access_key_id=os.getenv('s3_access_key_id'),
                            aws_secret_access_key=os.getenv('s3_secret_access_key'))

            # Set the name of your S3 bucket
            S3_BUCKET = 'se-legacy-bucket'

            for record in project_meta_records_to_delete:
                filename = record.title
                date_time_stamp = record.date_time_stamp
                secure_date_time_stamp = secure_filename(date_time_stamp.strftime('%Y-%m-%d %H:%M:%S'))

                s3_filename = f"{secure_date_time_stamp}_{secure_filename(filename or '')}"

                s3.delete_object(Bucket=S3_BUCKET, Key=s3_filename)
                db_session.delete(record)

            bid_to_delete = db_session.query(bids).filter_by(id = bid_id).first()
            db_session.delete(bid_to_delete)
            db_session.commit()
                
            flash('Project successfully deleted!', category='error')
            return redirect(url_for('views.manage_project', user = current_user))
    
    # Add default return for GET requests
    return redirect(url_for('views.manage_project'))




@views.route("/vendor-settings", methods=['GET', 'POST'])
@login_required
def supplier_settings():
    if request.method == 'POST':
        # The name of the category you are updating.
        field_name = request.form['field_name']

        return render_template('update_supplier_settings.html', 
                               user = current_user, 
                               field_name = field_name)

    return render_template('supplier_settings.html', user = current_user)


@views.route("/update-vendor-settings/<string:field_name>", methods=['GET', 'POST'])
@login_required
def update_supplier_settings(field_name):
    if request.method == 'POST':
        new_value = request.form[field_name]

        if field_name == 'password':
            password2 = request.form['password2']
            if new_value == password2:
                new_value = generate_password_hash(new_value)
                current_user.password = new_value

                with db.session() as db_session:
                    db_session.add(current_user)
                    db_session.commit()

                    flash('Password successfully updated!', 'success')
                    return redirect(url_for('views.supplier_settings'))

            else:
                flash('Those password do not match, please try again.', 'error')
                return render_template('update_supplier_settings.html',
                                    user = current_user,
                                    field_name = field_name)

        supplier_info_obj = current_user.supplier
        setattr(supplier_info_obj, field_name, new_value)

        with db.session() as db_session:
            db_session.commit()
            flash('Your settings have been successfully updated!', 'success')
            return redirect(url_for('views.supplier_settings'))
    else:
        return render_template('update_supplier_settings.html')




@views.route('/current-bids', methods=['GET', 'POST'])
def current_bids():
    open_bids_to_check = bids.query.filter(bids.status == 'open').all()
    logging.info('open_bids_to_check: %s', open_bids_to_check)

    current_datetime_utc = datetime.datetime.now()
    logging.info('current_datetime_utc: %s', current_datetime_utc)

    bids_to_update = []
    for bid in open_bids_to_check:
        if bid.close_date < current_datetime_utc: # close_date has passed
            bid.status = 'closed'
            bids_to_update.append(bid)

    db.session.bulk_save_objects(bids_to_update)
    db.session.commit()

    open_bids = bids.query.filter(bids.status == 'open').all()

    for bid in open_bids:
        close_date_utc = bid.close_date
        close_date_central = utc_to_central(close_date_utc)
        bid.close_date = close_date_central

    return render_template('current_bids.html',
                        open_bids = open_bids,
                        user = current_user
                        )





@views.route('/closed-bids', methods=['GET', 'POST'])
def closed_bids():
    closed_bids = bids.query.filter(bids.status == 'closed').all()

    for bid in closed_bids:
        close_date_utc = bid.close_date
        close_date_central = utc_to_central(close_date_utc)
        bid.close_date = close_date_central

    return render_template('closed_bids.html',
                           closed_bids = closed_bids,
                           user = current_user
                           )



@views.route('/awarded-bids', methods=['GET', 'POST'])
def awarded_bids():

    awarded_bids = bids.query.filter(bids.status == 'awarded').all()

    for bid in awarded_bids:
        close_date_utc = bid.close_date
        close_date_central = utc_to_central(close_date_utc)
        bid.close_date = close_date_central

    return render_template('awarded_bids.html',
                           awarded_bids = awarded_bids,
                           user = current_user
                           )









@views.route('/bid-details', methods=['GET', 'POST'])
def bid_details():
    return render_template('bid_details.html',
                           user = current_user
                           )






@views.route('/login-vendor', methods=['GET', 'POST'])
def login_vendor():
    if request.method == 'POST':
        email = request.form["email"]
        password = request.form["password"]

        user = supplier_login.query.filter_by(email = email).first()

        if user:
            logging.info('user trying to log in with email: %s', email)
            if check_password_hash(user.password, password):
                login_user(user, remember = True)
                session['user_type'] = 'supplier'
                logging.info('suppler_id: %s', user.supplier_id)
                session.permanent = True
                flash('Login successful!', category = 'success')
                return redirect(url_for('views.index'))
            else:
                flash('Incorrect password. Please try again.', category = 'error')
                return render_template('login_vendor.html',
                                       email = email,
                                       user = current_user)
        else:
            flash('That email is not associated with an account.', category = 'error')

    return render_template('login_vendor.html',
                           user = current_user
                           )


@views.route("/reset_password_request/<string:user_type>", methods=['GET', 'POST'])
def reset_password_request(user_type):
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()  # Normalize email case
        
        if not email:
            flash('Please enter your email address.', category='error')
            return render_template("reset_password_form.html", 
                               user_type = user_type,
                               user = current_user)

        if '@' not in email or '.' not in email:
            flash('Please enter a valid email address.', category='error')
            return render_template("reset_password_form.html", 
                               user_type = user_type,
                               user = current_user)

        if user_type == 'supplier':
            user = supplier_login.query.filter_by(email=email).first()
        else:
            user = admin_login.query.filter_by(email=email).first()

        if user:
            current_time = datetime.datetime.now().time()
            current_time_str = current_time.strftime('%H:%M:%S')

            s = URLSafeSerializer(os.getenv('secret_key') or 'default-secret-key')
            token = s.dumps([email, current_time_str])

            reset_password_url = url_for('views.reset_password', 
                                          token = token, 
                                          _external=True
                                          )

            try:
                msg = Message('Password Reset Request', 
                    sender = ("SE Legacy", 'hello@selegacyconnect.org'),
                    recipients = [email],
                    body=f'Reset your password by visiting the following link: {reset_password_url}')

                mail.send(msg)
                logging.info('Password reset email sent to: %s', email)
                flash('Success! We sent you an email containing a link where you can reset your password.', category = 'success')
                return redirect(url_for('views.index'))
            except Exception as e:
                logging.error('Failed to send password reset email to %s: %s', email, str(e))
                flash('There was an error sending the password reset email. Please try again later.', category='error')
                return render_template("reset_password_form.html", 
                                   user_type = user_type,
                                   user = current_user)
        else:
            logging.warning('Password reset requested for non-existent email: %s', email)
            flash('That email does not exist in our system. Please check the email address and try again.', category = 'error')
            return render_template("reset_password_form.html", 
                               user_type = user_type,
                               user = current_user)
    
    else:
        return render_template("reset_password_form.html", 
                               user_type = user_type,
                               user = current_user)




@views.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "POST":
        s = URLSafeSerializer(os.getenv('secret_key') or 'default-secret-key')
        try: 
            user_email_from_token = (s.loads(token))[0].strip().lower()  # Normalize email case
            logging.info('Attempting password reset for email: %s', user_email_from_token)
        except BadSignature:
            logging.error('Invalid password reset token received')
            flash('The password reset link is invalid or has expired. Please request a new password reset link.', category = 'error')
            return redirect(url_for('views.reset_password_request', user_type='supplier'))

        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password or not confirm_password:
            flash('Please enter both new password and confirmation password.', category='error')
            return render_template("reset_password.html", 
                               user = current_user, 
                               token = token)

        if new_password != confirm_password:
            flash('Those passwords do not match. Please try again.', category='error')
            return render_template("reset_password.html", 
                               user = current_user, 
                               token = token)

        hashed_password = generate_password_hash(new_password)
        
        # Try supplier login first
        user = supplier_login.query.filter_by(email = user_email_from_token).first()
        if user is None:
            # Try admin login if not found in supplier login
            user = admin_login.query.filter_by(email = user_email_from_token).first()
            if user is None:
                logging.error('Password reset attempted for non-existent email: %s', user_email_from_token)
                flash('We could not find an account with that email address. Please check the email address and try again.', category='error')
                return render_template("reset_password.html", 
                                   user = current_user, 
                                   token = token)
            
        user.password = hashed_password
        db.session.commit()
        logging.info('Password successfully reset for email: %s', user_email_from_token)

        flash('Your password has been successfully updated! Please login with your new password.', category = 'success')
        return redirect(url_for('views.index'))

    else:
        return render_template("reset_password.html", 
                               user = current_user, 
                               token = token)




@views.route('/login-admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        email = request.form.get("email", "").strip().lower()  # Get with default, strip whitespace, and lowercase
        password = request.form.get("password", "")  # Get with default

        # Input validation
        if not email or not password:
            flash('Please provide both email and password.', category='error')
            return render_template('login_admin.html', user=current_user)

        # Basic email format validation
        if '@' not in email or '.' not in email:
            flash('Please enter a valid email address.', category='error')
            return render_template('login_admin.html', user=current_user)

        try:
            user = admin_login.query.filter_by(email=email).first()
            
            if user:
                if check_password_hash(user.password, password):
                    # Successful login
                    login_user(user, remember=True)
                    session['user_type'] = 'admin'
                    session.permanent = True
                    
                    # Set secure session flags
                    session['_fresh'] = True
                    session['_id'] = str(uuid.uuid4())
                    
                    # Log successful login
                    logging.info('Admin login successful for email: %s', email)
                    
                    flash('Login successful!', category='success')
                    return redirect(url_for('views.index'))
                else:
                    # Log failed password attempt
                    logging.warning('Failed admin login attempt - incorrect password for email: %s', email)
                    flash('Incorrect password. Please try again.', category='error')
                    return render_template('login_admin.html', email=email, user=current_user)
            else:
                # Log failed login attempt
                logging.warning('Failed admin login attempt - email not found: %s', email)
                flash('That email is not associated with an account.', category='error')
                return render_template('login_admin.html', user=current_user)
                
        except Exception as e:
            # Log any unexpected errors
            logging.error('Error during admin login: %s', str(e))
            flash('An error occurred during login. Please try again.', category='error')
            return render_template('login_admin.html', user=current_user)

    return render_template('login_admin.html', user=current_user)



@views.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == "POST":
        email = request.form['email']
        password1 = request.form['password1']
        password2 = request.form['password2']
        secret_code = request.form['secret_code']

        if secret_code != os.getenv('secret_admin_code'):
            flash('That secret code is incorrect. Please contact us if you need assistance.', category='error')
            return render_template('admin_signup.html',
                                   email = email,
                                   user = current_user)            

        if password1 != password2:
            flash('Passwords do not match. Please try again.', category='error')
            return render_template('admin_signup.html',
                                   user = current_user)

        else:
            hashed_password = generate_password_hash(password1)
            new_admin = admin_login()
            new_admin.password = hashed_password
            new_admin.email = email
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin account successfully created!', category='success')
            return redirect(url_for('views.index'))

    else:
        return render_template('admin_signup.html',
                               user = current_user
                               )


@views.route("/logout")
@login_required
def logout():
    session['user_type'] = None
    flash('User successfully logged out', category='success')
    logout_user()

    return redirect(url_for('views.index'))


@views.route('/terms', methods=['GET', 'POST'])
def terms():
    return render_template('terms.html',
                           user = current_user
                           )


@views.route('/privacy-policy', methods=['GET', 'POST'])
def privacy():
    return render_template('privacy.html',
                           user = current_user
                           )