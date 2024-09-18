from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

from rsa_encryption import get_keys, rsa_encryption, rsa_decryption
import os
import ftplib
import nltk
import mysql.connector
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from collections import Counter

application = Flask(__name__)
application.secret_key = 'new'

application.config['MYSQL_HOST'] = 'localhost'
application.config['MYSQL_USER'] = 'root'
application.config['MYSQL_PASSWORD'] = 'Rocknroll@7043'
application.config['MYSQL_DB'] = 'ehr_tf_final'

mysql = MySQL(application)

application.config['MAIL_SERVER'] = 'smtp.gmail.com'
application.config['MAIL_PORT'] = 465
application.config['MAIL_USERNAME'] = 'richard.james.data.v1@gmail.com'
application.config['MAIL_PASSWORD'] = 'qtutenlumismuaht'
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USE_SSL'] = True
mail = Mail(application)

HOSTNAME = "ftp.drivehq.com"
USERNAME = "richard.james.data"
PASSWORD = "Rocknroll@7043"
FTP_PORT = '21'

UPLOAD_FOLDER = ('uploads/'
                 '')


# -----------------------------------    Admin routes --------------------------------------------


@application.route('/')
@application.route('/admin_login', methods=['POST', 'GET'])
def admin_login():
    if "admin" not in session:
        if request.method == 'POST':
            admin_id = request.form["admin_id"]
            admin_pwd = request.form["admin_pwd"]
            cur = mysql.connection.cursor()
            cur.execute("select * from m_admin where admin_id=%s and admin_pwd=%s", (admin_id, admin_pwd))
            user = cur.fetchone()
            if user:
                session['admin'] = user[1]
                flash("Hello Admin", 'success')
                return redirect(url_for('admin_home'))
            else:
                msg9 ='Invalid Login Details Try Again'
                return render_template('admin/login.html', msg9=msg9)
        return render_template('admin/login.html')
    return redirect(url_for('admin_home'))


@application.route('/admin_home', methods=['POST', 'GET'])
def admin_home():
    if "admin" in session:
        return render_template('admin/home.html')
    return redirect(url_for('admin_login'))


@application.route('/data_owner_list', methods=['POST', 'GET'])
def data_owner_list():
    if "admin" in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM m_dataowner")
        data = cur.fetchall()
        return render_template('admin/data_owner_list.html', data=data)
    return redirect(url_for('admin_login'))
##
@application.route('/sensitive_word_list', methods=['POST', 'GET'])
def sensitive_word_list():
    if "admin" in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM sensitive_data")
        data = cur.fetchall()
        return render_template('admin/sensitive_word_list.html', data=data)
    return redirect(url_for('admin_login'))
##
@application.route('/all_files_list', methods=['POST', 'GET'])
def all_files_list():
    if "admin" in session:
        cur = mysql.connection.cursor()
        # cur.execute("SELECT * FROM m_file_upload")
        cur.execute("SELECT f_no,date,do_name,f_name,f_remarks,f_size FROM m_file_upload, m_dataowner "
                    "WHERE m_file_upload.do_code=m_dataowner.do_code")
        data = cur.fetchall()
        return render_template('admin/all_files_list.html', data=data)
    return redirect(url_for('admin_login'))


@application.route('/all_users_list', methods=['POST', 'GET'])
def all_users_list():
    if "admin" in session:
        cur = mysql.connection.cursor()
        # cur.execute("SELECT * FROM m_data_user")
        cur.execute("SELECT du_id,du_name,du_email,a_name,do_name FROM m_data_user, m_attribute, m_dataowner "
                    "WHERE m_data_user.du_attribute=m_attribute.a_code and m_dataowner.do_code=m_data_user.do_code")
        data = cur.fetchall()
        return render_template('admin/all_users_list.html', data=data)
    return redirect(url_for('admin_login'))


@application.route('/create_dataOwner', methods=['POST', 'GET'])
def create_dataOwner():
    if "admin" in session:
        if request.method == 'POST':
            do_code = request.form['do_code']
            do_name = request.form['name']
            do_email = request.form['email']
            # do_phone = request.form['mobile']
            do_password = request.form['password']
            algorithm_name = request.form['algorithm']

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT do_code FROM m_dataowner WHERE do_code=%s", (do_code,))
            d_code = cursor.fetchone()
            if not d_code:
                cursor.execute("SELECT do_email FROM m_dataowner WHERE do_email=%s", (do_email,))
                d_owner = cursor.fetchone()
                if not d_owner:
                    if algorithm_name == 'rsa':
                        enc_keys = get_keys()
                        encryption_key = enc_keys[0]
                        decryption_key = enc_keys[1]
                    else:
                        enc_keys = generate_keys()
                        encryption_key = str(enc_keys[0])
                        decryption_key = str(enc_keys[0])

                    cursor.execute(
                        'INSERT INTO m_dataowner(do_code,do_password,do_name,do_email,do_algorithm,do_encryption_key,do_decryption_key)'
                        'VALUES(%s,%s,%s,%s,%s,%s,%s)',
                        (do_code, do_password, do_name, do_email, algorithm_name, encryption_key, decryption_key))

                    mysql.connection.commit()
                    cursor.close()

                    with open('static/credentials.txt', 'w') as file:
                        file.write(
                            'Hello {}...\n You can use below Credentials to login into your account.\n\nYour id : {}\n'
                            'User mail id: {}\nPassword : {}\n\n*Note : Do not forget to change your password after '
                            'login. '.format(do_name, do_code, do_email, do_password))

                    try:
                        subject = 'Login Credentials'
                        msg = Message(subject, sender='smtp.gmail.com', recipients=[do_email])
                        msg.body = "Hello  " + do_name + "  You have been created as data owner.. Below file contains your credentials"
                        with application.open_resource("static/credentials.txt") as fp:
                            msg.attach("credentials.txt", "application/txt", fp.read())
                        mail.send(msg)
                    except Exception as e:
                        print(e)
                        print("Something went wrong")
                    flash("New Data Owner Created Successfully ...", 'success')
                    return redirect(url_for('data_owner_list'))
                msg2 = "This Email Id is already Registered"
                return render_template('admin/create_data_owner.html', msg1=msg2)
            msg2 = "This Code is not available to use.. try another.."
            return render_template('admin/create_data_owner.html', msg1=msg2)
        return render_template('admin/create_data_owner.html')
    return redirect(url_for('admin_login'))


@application.route('/edit_dataOwner', methods=['POST', 'GET'])
def edit_dataOwner():
    if "admin" in session:
        if request.method == 'POST':
            do_code = request.form['do_code']
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM m_dataowner WHERE do_code=%s", (do_code,))
            data = cursor.fetchone()
            cursor.close()
            return render_template('admin/update_data_owner.html', data=data)
        return render_template('admin/update_data_owner.html')
    return redirect(url_for('admin_login'))


@application.route('/update_dataOwner', methods=['POST', 'GET'])
def update_dataOwner():
    if "admin" in session:
        if request.method == 'POST':
            do_id = request.form['do_id']
            do_code = request.form['do_id']
            do_name = request.form['do_name']
            do_email = request.form['do_email']

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT do_name, do_email FROM m_dataowner WHERE do_id=%s", (do_id,))
            data1 = cursor.fetchone()

            if do_name == data1[0] and do_email == data1[1]:
                flash("No changes detected ...", 'success')
                return redirect(url_for('data_owner_list'))
            elif do_name != data1[0] and do_email == data1[1]:
                cursor.execute("UPDATE m_dataowner SET do_name=%s WHERE do_id = %s", (do_name, do_id))
                mysql.connection.commit()
                cursor.close()
                flash("Name successfully updated  ...", 'success')
                return redirect(url_for('data_owner_list'))
            elif do_name != data1[0] and do_email != data1[1]:
                cursor.execute("SELECT do_email FROM m_dataowner WHERE do_email=%s", (do_email,))
                d_owner = cursor.fetchone()
                if not d_owner:
                    cursor.execute("UPDATE m_dataowner SET do_name=%s, do_email=%s WHERE do_id = %s",
                                   (do_name, do_email, do_id))
                    mysql.connection.commit()
                    cursor.close()
                    flash("Name and Email successfully updated  ...", 'success')
                    return redirect(url_for('data_owner_list'))
                msg = 'This Email Id is already Existed'
                data = [do_id, do_code, '', do_name, do_email]
                return render_template('admin/update_data_owner.html', msg1=msg, data=data)

            elif do_name == data1[0] and do_email != data1[1]:
                cursor.execute("SELECT do_email FROM m_dataowner WHERE do_email=%s", (do_email,))
                d_owner = cursor.fetchone()
                if not d_owner:
                    cursor.execute("UPDATE m_dataowner SET do_email=%s WHERE do_id = %s", (do_email, do_id))
                    mysql.connection.commit()
                    cursor.close()
                    flash("Email successfully updated  ...", 'success')
                    return redirect(url_for('data_owner_list'))
                msg = 'This Email Id is already Existed'
                data = [do_id, do_code, '', do_name, do_email]
                return render_template('admin/update_data_owner.html', msg1=msg, data=data)
            return redirect(url_for('data_owner_list'))
        return render_template('admin/update_data_owner.html')
    return redirect(url_for('admin_login'))

##########################

@application.route('/create_sensitive_word', methods=['POST', 'GET'])
def create_sensitiveword():
    if "admin" in session:
        if request.method == 'POST':
            words = request.form('word')

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT word FROM sensitive_data WHERE word=%s", (words))
            d_words = cursor.fetchone()
            if not d_words:
                
                cursor = mysql.connection.cursor()
                cursor.execute("SELECT word FROM sensitive_data WHERE word=%s", (words))
                d_code = cursor.fetchone()
                if not d_code:
                
                    cursor.execute("SELECT word FROM sensitive_data WHERE words=%s", (words))
                d_words = cursor.fetchone()
  
                cursor.execute(
                        'INSERT INTO sensitive_data(word)'
                        'VALUES(%s)',
                        (words))

                mysql.connection.commit()
                cursor.close()

                with open('static/SWD.txt', 'w') as file:
                        file.write(
                            'Hello Admin'
                            .format(words))

                try:
                        subject = 'Sensitive Word Dictionary Modified'
                        msg = Message(subject, sender='smtp.gmail.com', recipients=["richard.james.data@gmail.com"])
                        msg.body = "Hello  " + "Admin" + "Sensitive Word Dictionary Has Been Modified"
                        with application.open_resource("static/SWD.txt") as fp:
                            msg.attach("SWD.txt", "application/txt", fp.read())
                        mail.send(msg)
                except Exception as e:
                        print(e)
                        print("Something went wrong")
                flash("New Sensitive Word has been updated successfully ...", 'success')
                return redirect(url_for('sensitive_word_list'))
                msg2 = "This Word Already Exist"
                return render_template('admin/data_owner_list.html', msg1=msg2)
            msg2 = "This Already Exist."
            return render_template('admin/create_sensitive_word.html', msg1=msg2)
        return render_template('admin/create_sensitive_word.html')
    return redirect(url_for('admin_login'))


@application.route('/edit_sensitive_data', methods=['POST', 'GET'])
def edit_sensitive_data():
    if "admin" in session:
        if request.method == 'POST':
            words = request.form['word']
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM sensitive_data WHERE word=%s", (words,))
            data = cursor.fetchone()
            cursor.close()
            return render_template('admin/update_sensitive_word.html', data=data)
        return render_template('admin/update_sensitive_word.html')
    return redirect(url_for('admin_login'))

            

###############################################

@application.route('/admin_password_change', methods=['POST', 'GET'])
def admin_password_change():
    if "admin" in session:
        if request.method == 'POST':
            current_pass = request.form['old']
            new_pass = request.form['new']
            verify_pass = request.form['verify']
            cur = mysql.connection.cursor()
            cur.execute("select admin_pwd from m_admin")
            user = cur.fetchone()
            if user:
                if user[0] == current_pass:
                    if new_pass == verify_pass:
                        msg = 'Password changed successfully'
                        cur.execute("UPDATE m_admin SET admin_pwd = %s ", (new_pass,))
                        mysql.connection.commit()
                        return render_template('admin/admin_password_change.html', msg1=msg)
                    else:
                        msg = 'Re-entered password is not matched'
                        return render_template('admin/admin_password_change.html', msg2=msg)
                else:
                    msg = 'Incorrect password'
                    return render_template('admin/admin_password_change.html', msg3=msg)
            else:
                msg = 'Incorrect password'
                return render_template('admin/admin_password_change.html', msg3=msg)
        return render_template('admin/admin_password_change.html')
    return redirect(url_for('admin_login'))


@application.route('/admin_logout')
def admin_logout():
    if "admin" in session:
        session.pop('admin')
        msg = 'Admin logged out', 'success'
        return redirect(url_for('admin_login', msg=msg))
    return redirect(url_for('admin_login'))

# -----------------------------------    Data Owner routes --------------------------------------------


@application.route('/dataOwner_login', methods=['POST', 'GET'])
def dataOwner_login():
    if 'dataOwner_name' not in session:
        if request.method == 'POST':
            do_email = request.form["admin_id"]
            do_pwd = request.form["admin_pwd"]
            cur = mysql.connection.cursor()
            cur.execute("select * from m_dataowner where do_email=%s and do_password=%s", (do_email, do_pwd))
            user = cur.fetchone()
            if user:
                session['dataOwner_name'] = user[3]
                session['dataOwner_code'] = user[1]
                wish_msg = "Hello " + user[3]
                flash(wish_msg, 'success')
                return redirect(url_for('dataOwner_home'))
            else:
                msg9 = 'Invalid Login Details Try Again'
                return render_template('dataOwner/login.html', msg9=msg9)
        return render_template('dataOwner/login.html')
    return redirect(url_for('dataOwner_home'))


@application.route('/dataOwner_home', methods=['POST', 'GET'])
def dataOwner_home():
    if 'dataOwner_name' in session:
        return render_template('dataOwner/home.html', dataOwner_name=session['dataOwner_name'])
    return render_template('dataOwner/login.html')


@application.route('/users_list', methods=['POST', 'GET'])
def users_list():
    if 'dataOwner_name' in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT du_id,du_name,du_email,a_name,do_name FROM m_data_user, m_attribute, m_dataowner "
                    "WHERE m_data_user.du_attribute=m_attribute.a_code and m_dataowner.do_code=m_data_user.do_code and"
                    " m_data_user.do_code=%s", (session['dataOwner_code'],))
        data = cur.fetchall()
        return render_template('dataOwner/users_list.html', data=data, dataOwner_name=session['dataOwner_name'])
    return redirect(url_for('dataOwner_login'))


@application.route('/create_user_page', methods=['POST', 'GET'])
def create_user_page():
    if 'dataOwner_name' in session:
        domain_list1 = domain_list()
        if request.method == 'POST':
            username = request.form['username']
            attribute = request.form['branch']
            email = request.form['email']
            Password = request.form['password']
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT du_email FROM m_data_user WHERE du_email=%s", (email,))
            user = cursor.fetchone()
            if not user:
                cursor.execute("SELECT do_decryption_key FROM m_dataowner WHERE do_code=%s",
                               (session['dataOwner_code'],))
                pri_key = cursor.fetchone()
                key = pri_key[0]
                key_length = len(key)
                new_attribute = attribute.zfill(key_length)
                result = [chr(ord(a) ^ ord(b)) for a, b in zip(key, new_attribute)]
                access_key = '-'.join(result)
                cursor = mysql.connection.cursor()
                cursor.execute(
                    "INSERT INTO m_data_user (du_name,du_email,du_password,du_attribute,do_code,du_key) VALUES(%s,%s,%s,%s,%s,%s)",
                    (username, email, Password, attribute, str(session['dataOwner_code']), access_key))
                mysql.connection.commit()
                cursor.close()

                with open('static/credentials.txt', 'w') as file:
                    file.write('Hello {}...\n You can use below Credentials to login into your account.\n\n'
                               'User mail id: {}\nPassword : {}\n\n*Note : Do not forget to change your password after '
                               'login. '.format(username, email, Password))

                try:
                    subject = 'User Login Credentials'
                    msg = Message(subject, sender='smtp.gmail.com', recipients=[email])
                    msg.body = "Hello  " + username + "  You have been created as user below file contains your credentials."
                    with application.open_resource("static/credentials.txt") as fp:
                        msg.attach("credentials.txt", "application/txt", fp.read())
                    mail.send(msg)
                except Exception as e:
                    print("Something went wrong", e)
                flash("New User Successfully Created...", "success")
                return redirect(url_for('users_list'))
            msg2 = "This Email Id is already Registered"
            return render_template('dataOwner/create_user_page.html', msg1=msg2, domain_codes=domain_list1[0],
                                   domain_names=domain_list1[1], dataOwner_name=session['dataOwner_name'])
        return render_template('dataOwner/create_user_page.html', domain_codes=domain_list1[0],
                               domain_names=domain_list1[1], dataOwner_name=session['dataOwner_name'])
    return redirect(url_for('dataOwner_login'))


@application.route('/dataOwner_files_list', methods=['POST', 'GET'])
def dataOwner_files_list():
    if 'dataOwner_name' in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM m_file_upload WHERE do_code=%s", (session['dataOwner_code'],))
        data = cur.fetchall()
        return render_template('dataOwner/user_files_list.html', data=data, dataOwner_name=session['dataOwner_name'])
    return redirect(url_for('dataOwner_login'))


# Term frequency part#
def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except Exception as e:
        print("Error reading file:", e)
        return None


def insert_word_counts(cur, word_counts, term_frequency):
    try:
        cur.execute("TRUNCATE TABLE word_counts")
        cur.execute("CREATE TABLE IF NOT EXISTS word_counts (word VARCHAR(255), count INT, termfrequency FLOAT)")

        for word, count in word_counts.items():
            freq_str = "{:.4f}".format(term_frequency[word])
            cur.execute("INSERT INTO word_counts (word, count, termfrequency) VALUES (%s, %s, %s)",
                        (word, count, freq_str))

        return True
    except Exception as e:
        print("Error inserting word counts into database:", e)
        return False


def get_term_frequency_sum(cur):
    try:
        cur.execute("SELECT DISTINCT words, count, termfrequency FROM sensitive_data JOIN word_counts ON "
                    "sensitive_data.words = word_counts.word;")
        result = cur.fetchall()
        return sum(row[2] for row in result)
    except Exception as e:
        print("Error fetching term frequency sum:", e)
        return None


@application.route('/process_upload', methods=['POST', 'GET'])
def process_upload():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            
            # file = request.files['file']
            file = request.files['file']
            print("file_22", file)
            sub = request.form["subject"]
            time = datetime.today().date()
            original_filename = secure_filename(file.filename)
            file_path = os.path.join(original_filename)
            file.save(file_path)
            
            
            
            # Store necessary file information in session
            session['original_filename'] = original_filename
            session['sub'] = sub
            session['file_path'] = file_path
            file_name_without_extension = os.path.splitext(original_filename)[0]
            print("File name without extension:", original_filename)
            print("file_11", file)
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            # file_path = 'uploads/' + file.filename
            # file.save(file_path)
            # print("file_path", file_path)
            # session['file_path'] = file_path
            # Process the uploaded file
            text = read_file(file_path)
            if not text:
                flash('Error reading file')
                return redirect(request.url)

            words = word_tokenize(text)
            stop_words = set(stopwords.words('english'))
            words = [word.lower() for word in words if word.isalpha() and word.lower() not in stop_words]

            word_counts = Counter(words)
            word_count = len(words)
            term_frequency = {word: (count / word_count) * 100 for word, count in word_counts.items()}
            print("Tf", term_frequency)
            cur = mysql.connection.cursor()
            if not cur:
                flash('Database connection failed')
                return redirect(request.url)

            if insert_word_counts(cur, word_counts, term_frequency):
                mysql.connection.commit()
                term_frequency_sum = get_term_frequency_sum(cur)
                if term_frequency_sum is not None:
                    print("Result:", term_frequency_sum)
                    threshold = 0.1
                    if term_frequency_sum >= threshold:
                        return render_template('dataOwner/alert.html', is_sensitive=True)
                    else:
                        flash('Term frequency value does not exceed the threshold.')
                        return data_owner_file_upload(), session
                        # return render_template('dataOwner/alert.html', is_sensitive=False)
            else:
                flash('Failed to insert word counts into the database.')
                return redirect(url_for('data_owner_file_upload'))

            cur.close()
            flash('Word counts inserted into the database successfully.')
            return redirect(url_for('data_owner_file_upload', filename=original_filename, subject=sub, time=time,
                                    original_filename=original_filename))
        return render_template('dataOwner/file_upload.html', dataOwner_name=session['dataOwner_name'])
    return redirect(url_for('dataOwner_login'))


# TF End#

@application.route('/data_owner_file_upload', methods=['POST', 'GET'])
def data_owner_file_upload():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            file_path = session.get('file_path')
            print("file_path", file_path)
            original_filename = session.get('original_filename')
            sub = session.get('sub')
            time = datetime.today().date()
            cursor = mysql.connection.cursor()
            f_no = None
            try:

                cursor.execute('INSERT INTO m_file_upload(date,do_code,f_name,f_remarks) '
                               'VALUES(%s,%s,%s,%s)', (str(time), session['dataOwner_code'], original_filename, sub))
                mysql.connection.commit()

                cursor.execute("SELECT f_no FROM m_file_upload WHERE f_name=%s", (original_filename,))
                f_no = cursor.fetchone()[0]
                print("f_no....", f_no)
                f_size = os.stat(file_path).st_size
                f_size = str(f_size / 1024)[0:4] + 'KB'
                new_filename = str(f_no) + '_' + original_filename + '.enc'
                infile = file_path
                outfile = "static/upload/" + new_filename
                cur = mysql.connection.cursor()
                cur.execute("SELECT do_encryption_key, do_algorithm FROM m_dataowner WHERE do_code=%s",
                            (session['dataOwner_code'],))
                d_data = cur.fetchone()
                public_key = d_data[0]
                algorithm = d_data[1]
                if algorithm == "rsa":
                    with open(infile, 'rb') as in_file1, open(outfile, 'wb') as out_file1:
                        enc_key = rsa_encryption(in_file1, out_file1, public_key)
                else:
                    with open(infile, 'rb') as in_file1, open(outfile, 'wb') as out_file1:
                        enc_key = ecc_encryption(in_file1, out_file1, public_key, new_filename)

                file_path1 = 'static/download/' + new_filename
                with open(outfile, "rb") as file:
                    # Command for Uploading the file "STOR filename"
                    ftp_server = ftplib.FTP(HOSTNAME, USERNAME, PASSWORD)
                    ftp_server.storbinary(f"STOR {file_path1}", file)
                    ftp_server.encoding = "utf-8"

                cursor.execute("UPDATE m_file_upload SET cloud_f_name=%s,f_key=%s,f_size=%s  WHERE f_no = %s",
                               (new_filename, enc_key, f_size, f_no))
                mysql.connection.commit()

                os.remove(infile)
                os.remove(outfile)

                cursor.execute("SELECT a_mail FROM m_admin")
                a_email = cursor.fetchone()[0]
                print("a_email", a_email)

                cursor.execute("SELECT do_name FROM m_dataowner WHERE do_code=%s", (session['dataOwner_code'],))
                d_name = cursor.fetchone()[0]
                session['d_name'] = d_name
                print("d_name", d_name)

                try:
                    subject = 'File Acknowledgement'
                    msg = Message(subject, sender='smtp.gmail.com', recipients=[a_email])

                    msg.body = "File Ack: Mr." + str(
                        d_name) + " the data owner, has uploaded a sensitive file titled " + str(
                        original_filename) + " to cloud sharing."
                    mail.send(msg)
                except Exception as e:
                    print("Something went wrong", e)

                flash("New File Uploaded Successfully...", "success")
                return redirect(url_for('dataOwner_files_list'))

            except Exception as e:
                print("Try block not exits")
                msg = "File Not Uploaded :" + str(e)
                cursor.execute("DELETE FROM m_file_upload WHERE f_no=%s", [f_no])
                mysql.connection.commit()
                flash(msg, "error")
                return redirect(url_for('data_owner_file_upload'))

            finally:
                cursor.close()

        return render_template('dataOwner/file_upload.html', dataOwner_name=session['dataOwner_name'])
    return redirect(url_for('dataOwner_login'))


@application.route('/cancel_upload', methods=['POST', 'GET'])
def cancel_upload():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT do_name FROM m_dataowner WHERE do_code=%s", (session['dataOwner_code'],))
            d_name = cursor.fetchone()[0]

            print("d_name", d_name)
            # Retrieve necessary data from session

            original_filename = session['original_filename']
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT a_mail FROM m_admin")
            a_email = cursor.fetchone()[0]
            print("a_email", a_email)
            cursor.close()
            # Send the email notification
            subject = 'File Upload Cancellation'
            msg = Message(subject, sender='smtp.gmail.com', recipients=[a_email])
            msg.body = "Alert: Mr. " + str(
                d_name) + " the data owner, has canceled the upload of a sensitive file titled " + str(
                original_filename) + " to cloud sharing."
            mail.send(msg)

            return 'Cancellation notification sent.', 200
        else:
            return 'Unauthorized', 401
    return "session not found"


@application.route('/dataOwner_file_access', methods=['POST', 'GET'])
def dataOwner_file_access():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            f_no = request.form['file_num']
            f_name = request.form['file_name']
            cur = mysql.connection.cursor()
            cur.execute(
                "SELECT a_name FROM m_attribute, m_file_access WHERE m_attribute.a_code=m_file_access.a_code and m_file_access.f_no=%s",
                (f_no,))
            file_access_data = cur.fetchall()
            list1 = []
            for i in file_access_data:
                list1.append(i[0])
            access_data = ','.join(list1)
            d_list = domain_list()
            return render_template('dataOwner/file_access_control.html', f_name=f_name, f_no=f_no, d_codes=d_list[0],
                                   d_names=d_list[1], dataOwner_name=session['dataOwner_name'], old_access=access_data)
        return redirect(url_for('dataOwner_files_list'))
    return redirect(url_for('dataOwner_login'))


@application.route('/dataOwner_file_access_update', methods=['POST', 'GET'])
def dataOwner_file_access_update():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            f_no = request.form['file_num']
            f_name = request.form['file_name']
            access_codes = request.form.getlist('access')
            cursor = mysql.connection.cursor()
            cursor.execute('DELETE FROM m_file_access WHERE f_no=%s', (f_no,))
            mysql.connection.commit()
            for i in access_codes:
                cursor.execute('INSERT INTO m_file_access(f_no,a_code) VALUES(%s,%s)', (f_no, i))
            mysql.connection.commit()
            flash("File Access Updated Successfully", "success")
            return redirect(url_for('dataOwner_files_list'))
        return redirect(url_for('dataOwner_files_list'))
    return redirect(url_for('dataOwner_login'))


def delete_file(file_name):
    # Connect to DriveHQ
    try:
        ftp_server = ftplib.FTP(HOSTNAME, USERNAME, PASSWORD)
        # Delete the file from DriveHQ
        ftp_server.delete(file_name)
        print("File deleted successfully from DriveHQ.")
        ftp_server.quit()
    except Exception as e:
        print("Error deleting file from DriveHQ:", e)


@application.route('/dataOwner_file_delete', methods=['POST', 'GET'])
def dataOwner_file_delete():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            f_no = request.form['file_num']
            file_name = request.form['cloud_file_name']

            #pickle_file_name = file_name.split('.')[0] + '.pkl'
            #pickle_file_name = 'static/pickle_files/' + pickle_file_name

            cursor = mysql.connection.cursor()
            cursor.execute("DELETE FROM m_file_upload WHERE f_no = %s ", [f_no])
            mysql.connection.commit()
            cursor.close()

            cloud_file_name = 'static/download/' + file_name
            delete_file(cloud_file_name)
            #os.remove(pickle_file_name)
            flash("File Deleted Successfully", "success")
            return redirect(url_for('dataOwner_files_list'))
        return redirect(url_for('dataOwner_files_list'))
    return redirect(url_for('dataOwner_login'))


def domain_list():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT a_code, a_name FROM m_attribute")
    domain_list1 = cursor.fetchall()
    domain_code_list = []
    domain_name_list = []
    for i in domain_list1:
        domain_code_list.append(i[0])
        domain_name_list.append(i[1])
    return domain_code_list, domain_name_list


@application.route('/add_domain', methods=['POST', 'GET'])
def add_domain():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            domainCode = request.form['domain_code']
            domainName = request.form['domain_name']
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM m_attribute WHERE a_code=%s", (domainCode,))
            domain_code_check = cursor.fetchone()
            if not domain_code_check:
                cursor.execute("SELECT * FROM m_attribute WHERE a_name=%s", (domainName,))
                domain_name_check = cursor.fetchone()
                if not domain_name_check:
                    cursor.execute('INSERT INTO m_attribute (a_code,a_name) VALUES(%s,%s)', (domainCode, domainName))
                    mysql.connection.commit()
                    flash("New Domain Added Successfully..", "success")
                    return redirect(url_for('dataOwner_domain_change'))
                flash("Domain Not Added, That Domain Name is Already Existed..", "error")
                return redirect(url_for('dataOwner_domain_change'))
            flash("Domain Not Added, That Domain Code is Already Existed..", "error")
            return redirect(url_for('dataOwner_domain_change'))
    return redirect(url_for('dataOwner_login'))


@application.route('/dataOwner_domain_change', methods=['POST', 'GET'])
def dataOwner_domain_change():
    if 'dataOwner_name' in session:
        d = domain_list()
        return render_template('dataOwner/update_domains.html', domain_codes=d[0], domain_names=d[1],
                               dataOwner_name=session['dataOwner_name'])
    return redirect(url_for('dataOwner_login'))


@application.route('/single_domain_delete', methods=['POST', 'GET'])
def single_domain_delete():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            domain_code = request.form['domain_code']
            cursor = mysql.connection.cursor()
            cursor.execute("DELETE FROM m_attribute WHERE a_code= %s", [domain_code])
            mysql.connection.commit()
            flash("Domain Was Deleted...", "success")
            return redirect(url_for('dataOwner_domain_change'))
        return redirect(url_for('dataOwner_domain_change'))
    return redirect(url_for('dataOwner_login'))


@application.route('/all_domain_delete', methods=['POST', 'GET'])
def all_domain_delete():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            cursor = mysql.connection.cursor()
            cursor.execute("DELETE FROM m_attribute")
            mysql.connection.commit()
            flash("All Domains Are Deleted...", "success")
            return redirect(url_for('dataOwner_domain_change'))
        return redirect(url_for('dataOwner_domain_change'))
    return redirect(url_for('dataOwner_login'))


@application.route('/dataOwner_password_change', methods=['POST', 'GET'])
def dataOwner_password_change():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            current_pass = request.form['old']
            new_pass = request.form['new']
            verify_pass = request.form['verify']
            cur = mysql.connection.cursor()
            cur.execute("select do_password from m_dataowner WHERE do_code=%s", (session['dataOwner_code'],))
            user = cur.fetchone()
            if user:
                if user[0] == current_pass:
                    if new_pass == verify_pass:
                        msg = 'Password changed successfully'
                        cur.execute("UPDATE m_dataowner SET do_password=%s WHERE do_code=%s",
                                    (new_pass, session['dataOwner_code']))
                        mysql.connection.commit()
                        return render_template('dataOwner/dataOwner_password_change.html', msg1=msg,
                                               dataOwner_name=session['dataOwner_name'])
                    else:
                        msg = 'Re-entered password is not matched'
                        return render_template('dataOwner/dataOwner_password_change.html', msg2=msg,
                                               dataOwner_name=session['dataOwner_name'])
                else:
                    msg = 'Incorrect password'
                    return render_template('dataOwner/dataOwner_password_change.html', msg3=msg,
                                           dataOwner_name=session['dataOwner_name'])
            else:
                msg = 'Incorrect password'
                return render_template('dataOwner/dataOwner_password_change.html', msg3=msg,
                                       dataOwner_name=session['dataOwner_name'])
        return render_template('dataOwner/dataOwner_password_change.html',
                               dataOwner_name=session['dataOwner_name'])
    return redirect(url_for('dataOwner_login'))


@application.route('/dataOwner_user_edit', methods=['POST', 'GET'])
def dataOwner_user_edit():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            u_id = request.form['user_id']
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM m_data_user WHERE du_id=%s", (u_id,))
            data = cursor.fetchone()
            cursor.close()
            return render_template('dataOwner/update_user_page.html', data=data)
        return render_template('dataOwner/update_user_page.html')
    return redirect(url_for('dataOwner_login'))


@application.route('/dataOwner_user_update', methods=['POST', 'GET'])
def dataOwner_user_update():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            du_id = request.form['du_id']
            du_name = request.form['du_name']
            du_email = request.form['du_email']

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT du_name, du_email FROM m_data_user WHERE du_id=%s", (du_id,))
            data1 = cursor.fetchone()

            if du_name == data1[0] and du_email == data1[1]:
                flash("No changes detected ...", 'success')
                return redirect(url_for('users_list'))
            elif du_name != data1[0] and du_email == data1[1]:
                cursor.execute("UPDATE m_data_user SET du_name=%s WHERE du_id = %s", (du_name, du_id))
                mysql.connection.commit()
                cursor.close()
                flash("User Name successfully updated  ...", 'success')
                return redirect(url_for('users_list'))
            elif du_name != data1[0] and du_email != data1[1]:
                cursor.execute("SELECT du_email FROM m_data_user WHERE du_email=%s", (du_email,))
                d_user = cursor.fetchone()
                if not d_user:
                    cursor.execute("UPDATE m_data_user SET du_name=%s, du_email=%s WHERE du_id = %s",
                                   (du_name, du_email, du_id))
                    mysql.connection.commit()
                    cursor.close()
                    flash("User Name and Email successfully updated  ...", 'success')
                    return redirect(url_for('users_list'))
                msg = 'This Email Id is already Existed'
                data = [du_id, du_name, du_email]
                return render_template('dataOwner/update_user_page.html', msg1=msg, data=data)

            elif du_name == data1[0] and du_email != data1[1]:
                cursor.execute("SELECT du_email FROM m_data_user WHERE du_email=%s", (du_email,))
                d_user = cursor.fetchone()
                if not d_user:
                    cursor.execute("UPDATE m_data_user SET du_email=%s WHERE du_id = %s", (du_email, du_id))
                    mysql.connection.commit()
                    cursor.close()
                    flash("Email successfully updated  ...", 'success')
                    return redirect(url_for('users_list'))
                msg = 'This Email Id is already Existed'
                data = [du_id, du_name, du_email]
                return render_template('dataOwner/update_user_page.html', msg1=msg, data=data)
            return redirect(url_for('users_list'))
        return render_template('dataOwner/update_user_page.html')
    return redirect(url_for('dataOwner_login'))


@application.route('/dataOwner_user_delete', methods=['POST', 'GET'])
def admin_user_delete():
    if 'dataOwner_name' in session:
        if request.method == 'POST':
            user_id = request.form['user_id']

            cursor = mysql.connection.cursor()
            cursor.execute("DELETE FROM m_data_user WHERE du_id = %s ", [user_id])
            mysql.connection.commit()
            cursor.close()
            flash("User Deleted Successfully", 'success')
            return redirect(url_for('users_list'))
        return render_template('admin/users_list.html')
    return redirect(url_for('dataOwner_login'))


@application.route('/dataOwner_profile', methods=['POST', 'GET'])
def dataOwner_profile():
    if 'dataOwner_name' in session:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM m_dataowner WHERE do_code=%s ", (session['dataOwner_code'],))
        data = cursor.fetchone()
        cursor.close()
        return render_template('dataOwner/profile.html', data=data, dataOwner_name=session['dataOwner_name'])
    return redirect(url_for('dataOwner_login'))


# @application.route('/test', methods=['POST', 'GET'])
# def test():
#     cursor = mysql.connection.cursor()
#     # cursor.execute("SELECT TOP 1 * FROM m_file_upload")
#     data = cursor.fetchall()
#     for i in data:
#         print(i)
#     return redirect(url_for('dataOwner_home'))


@application.route('/dataOwner_new_key_generation', methods=['POST', 'GET'])
def dataOwner_new_key_generation():
    if 'dataOwner_name' in session:
        if request.method == "POST":
            # 1) Generate new Rsa keys
            algorithm_name = ''
            a_name = request.get_json().get('message')

            if a_name == "rsa":
                enc_keys = get_keys()
                encryption_key = enc_keys[0]
                decryption_key = enc_keys[1]
            else:
                enc_keys = generate_keys()
                encryption_key = enc_keys[0]
                decryption_key = enc_keys[0]

            # 2) Update new rsa or ecc keys in m_dataowner table
            cursor = mysql.connection.cursor()
            cursor.execute(
                'UPDATE m_dataowner SET do_algorithm=%s,do_encryption_key=%s,do_decryption_key=%s WHERE do_code=%s ',
                (a_name, encryption_key, decryption_key, session['dataOwner_code']))
            mysql.connection.commit()

            # 3) Update data user key in m_data_user table

            cursor.execute("SELECT du_attribute FROM m_data_user WHERE do_code=%s ", (session['dataOwner_code'],))
            data = cursor.fetchall()
            attribute_list = [i[0] for i in data]

            cursor.execute("SELECT do_decryption_key FROM m_dataowner WHERE do_code=%s", (session['dataOwner_code'],))
            pri_key = cursor.fetchone()
            key = pri_key[0]
            key_length = len(key)

            for attribute in attribute_list:
                new_attribute = attribute.zfill(key_length)
                result = [chr(ord(a) ^ ord(b)) for a, b in zip(key, new_attribute)]
                access_key = '-'.join(result)

                cursor.execute("UPDATE m_data_user SET du_key=%s WHERE du_attribute=%s and do_code=%s",
                               (access_key, attribute, session['dataOwner_code'],))
            mysql.connection.commit()

            # 4) Delete data owner uploaded files from file upload table
            cursor.execute("SELECT cloud_f_name FROM m_file_upload WHERE do_code=%s ", (session['dataOwner_code'],))
            data = cursor.fetchall()
            file_list = [i[0] for i in data]

            cursor.execute("DELETE FROM m_file_upload WHERE do_code=%s ", [session['dataOwner_code']])
            mysql.connection.commit()
            cursor.close()

            # 4) Delete files from drivehq
            # Connect to DriveHQ
            # ftp_server = ftplib.FTP(HOSTNAME, USERNAME, PASSWORD)
            try:
                ftp_server = ftplib.FTP(HOSTNAME, USERNAME, PASSWORD)
                # Delete the file from DriveHQ
                for file in file_list:
                    cloud_file_name = 'static/download/' + file
                    ftp_server.delete(cloud_file_name)
                ftp_server.quit()
                print("Files deleted successfully from DriveHQ.")
            except Exception as e:
                print("Error deleting file from DriveHQ:", e)

            cursor.close()
            flash("keys updated and files has been deleted...", 'success')
            return redirect('users_list')
        return redirect(url_for('dataOwner_login'))
    return redirect(url_for('dataOwner_login'))


@application.route('/dataOwner_logout')
def dataOwner_logout():
    if 'dataOwner_name' in session:
        do_name = session['dataOwner_name']
        session.pop('dataOwner_name')
        session.pop('dataOwner_code')
        msg = 'See you soon {}'.format(do_name)
        return render_template('dataOwner/login.html', msg=msg)
        # return redirect(url_for('dataOwner_login'))
    return redirect(url_for('dataOwner_login'))


# -------------------------------------    User routes  -------------------------------------


@application.route('/user_login', methods=['POST', 'GET'])
def user_login():
    if "user_name" not in session:
        if request.method == 'POST':
            user_email = request.form["email"]
            user_pwd = request.form["password"]
            cur = mysql.connection.cursor()
            cur.execute("select * from m_data_user where du_email=%s and du_password=%s", (user_email, user_pwd))
            user = cur.fetchone()
            if user:
                session['user_name'] = user[1]
                session['user_mail'] = user[2]
                wish_msg = "Hii " + user[1]
                flash(wish_msg, 'success')
                return redirect(url_for('user_home'))
            else:
                msg9 = 'Invalid Login Details Try Again'
                return render_template('user/login.html', msg9=msg9)
        return render_template('user/login.html')
    wish_msg = "Welcome back " + session['user_name']
    flash(wish_msg, 'success')
    return redirect(url_for('user_home'))


@application.route('/user_home', methods=['POST', 'GET'])
def user_home():
    if "user_name" in session:
        return render_template('user/home.html', user_name=session['user_name'])
    return redirect(url_for("user_login"))


@application.route('/user_files_list', methods=['POST', 'GET'])
def user_files_list():
    if "user_name" in session:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT f_no FROM m_file_access, m_data_user WHERE a_code=du_attribute and du_email=%s",
                       (session["user_mail"],))
        file_num_list = cursor.fetchall()
        new_list = []
        for i in file_num_list:
            new_list.append(i[0])
        data = []
        for i in new_list:
            cursor.execute(
                "SELECT f_no,date,do_name,f_name,f_remarks,f_size,cloud_f_name FROM m_file_upload,m_dataowner "
                "WHERE m_dataowner.do_code=m_file_upload.do_code and f_no=%s", (i,))
            file_data = cursor.fetchall()
            data.append(file_data)
        return render_template('user/home.html', user_name=session['user_name'], data=data)
    return redirect(url_for("user_login"))


@application.route('/user_file_download', methods=['POST', 'GET'])
def user_file_download():
    if "user_name" in session:
        if request.method == 'POST':
            file_num = request.form["file_num"]
            file_name = request.form["file_name"]
            new_file_name = request.form["new_file_name"]
            # do_name = request.form["do_name"]

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT f_key FROM m_file_upload WHERE f_no=%s", (file_num,))
            file_key = cursor.fetchone()
            file_key = file_key[0]

            cursor.execute("select do_code from m_data_user where du_email=%s", (session["user_mail"],))
            do_code = cursor.fetchone()
            do_code = do_code[0]

            cursor.execute("SELECT do_algorithm FROM m_dataowner WHERE do_code=%s", (do_code,))
            algorithm = cursor.fetchone()
            algorithm = algorithm[0]

            cursor.execute("SELECT du_attribute, du_key FROM m_data_user WHERE du_email=%s", (session["user_mail"],))
            data = cursor.fetchone()
            attribute = data[0]
            key = data[1]
            key_list = key.split('-')
            key_length = len(key_list)
            new_attribute = attribute.zfill(key_length)

            result2 = [chr(ord(a) ^ ord(b)) for a, b in zip(key_list, new_attribute)]
            pri_key = ''.join(result2)

            in_file1 = "static/download/" + new_file_name
            out_file1 = "static/download/" + file_name

            with open(in_file1, "wb") as file:
                try:
                    ftp_server = ftplib.FTP(HOSTNAME, USERNAME, PASSWORD)
                    ftp_server.encoding = "utf-8"
                    ftp_server.retrbinary(f"RETR {in_file1}", file.write)
                    file.close()
                    if algorithm == 'rsa':
                        with open(in_file1, 'rb') as infile, open(out_file1, 'wb') as outfile:
                            rsa_decryption(infile, outfile, file_key, pri_key)
                    else:
                        with open(in_file1, 'rb') as infile, open(out_file1, 'wb') as outfile:
                            ecc_decryption(infile, outfile, new_file_name, pri_key)

                    os.remove(in_file1)
                    return render_template("user/home.html", file=out_file1, f_name=file_name,
                                           user_name=session['user_name'])
                except Exception as e:
                    msg = "File Not Downloaded: " + str(e)
                    flash(msg, 'error')
                    return redirect(url_for('user_files_list'))
            # return redirect(url_for('user_files_list'))
        return redirect(url_for('user_files_list'))
    return redirect(url_for("user_login"))


@application.route('/user_profile', methods=['POST', 'GET'])
def user_profile():
    if "user_name" in session:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT du_id,du_name,du_email,a_name,do_name FROM m_data_user,m_attribute,m_dataowner "
                       "WHERE m_attribute.a_code=m_data_user.du_attribute and m_dataowner.do_code=m_data_user.do_code"
                       " and du_email=%s ", (session['user_mail'],))

        data = cursor.fetchone()
        cursor.close()
        return render_template('user/profile.html', data=data, user_name=session['user_name'])
    return redirect(url_for("user_login"))


@application.route('/user_change_password', methods=['POST', 'GET'])
def user_change_password():
    if "user_name" in session:
        if request.method == 'POST':
            current_pass = request.form['old']
            new_pass = request.form['new']
            verify_pass = request.form['verify']
            cur = mysql.connection.cursor()
            cur.execute("select du_password from m_data_user where du_email=%s", (session['user_mail'],))
            user = cur.fetchone()
            if user:
                if user[0] == current_pass:
                    if new_pass == verify_pass:
                        msg1 = 'Password changed successfully'
                        cur.execute("UPDATE m_data_user SET du_password=%s WHERE du_email=%s",
                                    (new_pass, session['user_mail']))
                        mysql.connection.commit()
                        return render_template('user/user_change_password.html', msg1=msg1,
                                               user_name=session['user_name'])
                    else:
                        msg2 = 'Re-entered password is not matched'
                        return render_template('user/user_change_password.html', msg2=msg2,
                                               user_name=session['user_name'])
                else:
                    msg3 = 'Incorrect password'
                    return render_template('user/user_change_password.html', msg3=msg3, user_name=session['user_name'])
            else:
                msg3 = 'Incorrect password'
                return render_template('user/user_change_password.html', msg3=msg3, user_name=session['user_name'])
        return render_template('user/user_change_password.html', user_name=session['user_name'])
    return redirect(url_for("user_login"))


@application.route('/user_logout')
def user_logout():
    if "user_name" in session:
        msg = 'Siging Off {} .., Thank You'.format(session['user_name'])
        session.pop('user_name')
        session.pop('user_mail')
        return render_template('user/login.html', msg=msg)
    return redirect(url_for("user_login"))


if __name__ == '__main__':
    nltk.download('punkt')
    nltk.download('stopwords')
    application.run(port=5002, debug=True)
