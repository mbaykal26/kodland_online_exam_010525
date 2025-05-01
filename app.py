import os
import sqlite3
from flask import Flask, g, request, render_template, flash, redirect, url_for, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import random
from flask import send_from_directory
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask import make_response, send_file
import requests
import json
import os
import requests
# Define the path to the database file
DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'exam.db')

########################################
# FLASK APPLICATION SETUP
########################################
app = Flask(__name__)
app.secret_key = "a1d76c1f45b9d653bcfe0c0782c928b6aa54e24cc1685e3b839de0f57282b88f"
app.config['DATABASE'] = DATABASE


# Mail configuration (use your SMTP provider here)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'muratbaykal@gmail.com'
app.config['MAIL_PASSWORD'] = 'fgeh mjan punh zelv'  # Use app password, not real password
app.config['MAIL_DEFAULT_SENDER'] = 'muratbaykal@gmail.com'

mail = Mail(app)

s = URLSafeTimedSerializer(app.secret_key)

# Configure upload folder (inside static for easy serving)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

########################################
# DATABASE CONNECTION & INITIALIZATION
########################################
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if they don't exist."""
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS kullanicilar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ad TEXT,
        email TEXT UNIQUE,
        sifre TEXT,
        en_yuksek_skor INTEGER DEFAULT 0,
        deneme_sayisi INTEGER DEFAULT 0,
        email_confirmed INTEGER DEFAULT 0,
        rolId INTEGER DEFAULT 2
    )
    """)

    # Questions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sorular (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        soru_metni TEXT NOT NULL,
        dogru_cevap TEXT NOT NULL,
        secenek1 TEXT NOT NULL,
        secenek2 TEXT NOT NULL,
        secenek3 TEXT NOT NULL,
        secenek4 TEXT NOT NULL,
        konu TEXT NOT NULL
    )
    """)

    # Answers table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cevaplar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kullanici_id INTEGER,
        soru_id INTEGER,
        verilen_cevap TEXT,
        dogru_mu INTEGER,
        FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id),
        FOREIGN KEY (soru_id) REFERENCES sorular(id)
    )
    """)

    # Blog Comments table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blog_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blog_post_id INTEGER,
        user_id INTEGER,
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (blog_post_id) REFERENCES blog_posts(id),
        FOREIGN KEY (user_id) REFERENCES kullanicilar(id)
    )
    """)

    # Exam results table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sinavsonuclari (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kullanici_id INTEGER,
        skor INTEGER,
        tarih TEXT,
        FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id)
    )
    """)
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS temperature_readings (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            value     REAL    NOT NULL,
            timestamp TEXT    NOT NULL DEFAULT (datetime('now'))
    """)

    # Blog posts table, now with an "approved" column (default 0 means not approved yet)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blog_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT,
        filename TEXT,
        filetype TEXT,
        posted_by INTEGER,
        approved INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)    # Build a multi-row INSERT statement from the data list


    #2. Create a cursor and execute a query to fetch all columns from 'sorular'
    query = "SELECT * FROM sorular"
    cursor.execute(query)

    # 3. Fetch all results
    data = cursor.fetchall()  # This will return a list of tuples

    values = []
    new_data = []
    for q, correct, false_opts, topic in data:
        # Split the false options into a list and trim extra whitespace
        options = [opt.strip() for opt in false_opts.split(";")]
        # Add the correct answer to the list
        options.append(correct)
        # Shuffle so the correct answer appears in a random position
        random.shuffle(options)
        # Create a tuple: (question, dogru_cevap, option1, option2, option3, option4, topic)
        new_tuple = (q, correct, options[0], options[1], options[2], options[3], topic)
        new_data.append(new_tuple)

    print("new_data::::::::::::::::::::::::::::::", new_data)

    for row in new_data:
        # Unpack all seven fields and escape single quotes by replacing them with two single quotes
        q, correct, opt1, opt2, opt3, opt4, topic = (s.replace("'", "''") for s in row)
        values.append(f"('{q}', '{correct}', '{opt1}', '{opt2}', '{opt3}', '{opt4}', '{topic}')")

    # Construct the multi-row INSERT statement for 6 columns
    insert_stmt = ("INSERT INTO sorular (soru_metni, dogru_cevap, secenek1, secenek2, secenek3, secenek4, konu) VALUES " +
                ", ".join(values) + ";")
    print(insert_stmt)
    cursor.execute(insert_stmt)

    connection.commit()
    connection.close()


#######roles requirement ###############################################################
from functools import wraps

def roles_required(*allowed_roles):
    """
    Decorator to ensure the user has one of the specified rolIds.
    For example, @roles_required(1) restricts access to users with rolId=1.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Check if user is logged in
            if 'user_id' not in session:
                #flash("Bu işlemi yapmak için giriş yapmalısınız.", "danger")
                return redirect(url_for('login'))

            # Get the user's role from the database
            conn = get_db_connection()
            user = conn.execute("SELECT rolId FROM kullanicilar WHERE id = ?", (session['user_id'],)).fetchone()
            conn.close()

            # If no user or the user's role is not in allowed_roles, deny access
            if not user or user['rolId'] not in allowed_roles:
                #flash("Bu işlemi yapmak için yetkiniz yok.", "danger")
                return redirect(url_for('blog'))

            return f(*args, **kwargs)
        return wrapper
    return decorator
#ROLES REQUIREMENT ENDS ###############################################################

# IPSTACK VISITOR API KEY #########################
import requests

IPSTACK_KEY  = os.environ.get('IPSTACK_KEY', 'cebb4d3ad2781db0d85bb13bb3b969af')
EXCLUDED_IP = '94.54.232.86'

# ── right after your Flask() setup ────────────────────────────────────────────
# your real ipstack key:
def get_client_ip():
    # if running behind a proxy that sets X-Forwarded-For:
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        # may contain a comma-separated list; the first is the real client
        return forwarded.split(',')[0].strip()
    return request.remote_addr

def get_ip_info(ip_address):
    """Fetch geo info for `ip_address` from ipstack.com."""
    url = f"http://api.ipstack.com/{ip_address}?access_key={IPSTACK_KEY}"
    try:
        resp = requests.get(url, timeout=2)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}

# ── ensure you have a `visits` table ───────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    # … your existing table creations …
    cur.execute("""
      CREATE TABLE IF NOT EXISTS visits (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        ip       TEXT,
        country  TEXT,
        date     TEXT    -- store as TEXT date('now')
      )
    """)
    conn.commit()
    conn.close()
# call init_db() when you first run or on startup

# ── record every incoming request ─────────────────────────────────────────────
EXCLUDED_IP = "94.54.232.86"  # your own IP

@app.before_request
def record_visit():
    client_ip = request.remote_addr
    if client_ip == EXCLUDED_IP:
        return

    info    = get_ip_info(client_ip)
    country = info.get("country_name") or "(unknown)"

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO visits (ip, country, visited_at) VALUES (?, ?, datetime('now','localtime'))",
        (client_ip, country)
    )
    conn.commit()
    conn.close()



# ── expose a simple analytics page ────────────────────────────────────────────
@app.route('/visit_count')
@roles_required(1)
def visit_count():
    excluded_ip = EXCLUDED_IP
    conn = get_db_connection()

    total = conn.execute(
        "SELECT COUNT(*) AS total FROM visits WHERE ip != ?",
        (excluded_ip,)
    ).fetchone()["total"]

    daily = conn.execute("""
        SELECT
          DATE(visited_at) AS tarih,
          COUNT(*)         AS sayi
        FROM visits
        WHERE ip != ?
        GROUP BY DATE(visited_at)
        ORDER BY DATE(visited_at) DESC
    """, (excluded_ip,)).fetchall()

    country = conn.execute("""
        SELECT
          COALESCE(country,'(unknown)') AS ulke,
          COUNT(*)                     AS sayi
        FROM visits
        WHERE ip != ?
        GROUP BY country
        ORDER BY sayi DESC
    """, (excluded_ip,)).fetchall()

    conn.close()
    return render_template('visit_count.html',
                           total=total,
                           daily=daily,
                           country=country)




## IPSTACK VISITOR API KEY #########################

########################################
# EMAIL CONFIRMATION HELPER FUNCTIONS
########################################
def generate_confirmation_token(email):
    return s.dumps(email, salt='email-confirm')

def confirm_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='email-confirm', max_age=expiration)
    except Exception:
        return False
    return email

def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template)
    mail.send(msg)

@app.route('/confirm_email/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash("Doğrulama bağlantısı geçersiz veya süresi dolmuş.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM kullanicilar WHERE email = ?", (email,)).fetchone()
    if not user:
        flash("Kullanıcı bulunamadı.", "danger")
        conn.close()
        return redirect(url_for('register'))

    # Use dictionary indexing since sqlite3.Row does not support .get()
    if user['email_confirmed']:
        flash("E-posta adresiniz zaten onaylanmış.", "info")
    else:
        conn.execute("UPDATE kullanicilar SET email_confirmed = 1 WHERE email = ?", (email,))
        conn.commit()
        flash("E-posta adresiniz başarıyla onaylandı!", "success")
    conn.close()
    return redirect(url_for('login'))


#password forgot ######################################
# at top of app.py, after you define `s = URLSafeTimedSerializer(...)`

def generate_password_reset_token(email):
    # use a separate salt so reset tokens aren’t interchangeable
    return s.dumps(email, salt='password-reset')

def confirm_password_reset_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='password-reset', max_age=expiration)
    except Exception:
        return False
    return email
#password forgot#########################################


from werkzeug.security import generate_password_hash, check_password_hash
h = generate_password_hash("123")
print("Generated hash:", h)
print("Check password:", check_password_hash(h, "123"))
print("repr(h)::::::::::::::::::::", repr(h))

########################################
# ROUTES
########################################

def get_comments(post_id):
    conn = get_db_connection()
    comments = conn.execute(
        """
        SELECT bc.id, bc.comment, bc.user_id, bc.created_at,
               COALESCE(u.ad, 'Anonymous') AS author_name
        FROM blog_comments bc
        LEFT JOIN kullanicilar u ON bc.user_id = u.id
        WHERE bc.blog_post_id = ?
        ORDER BY bc.created_at ASC
        """,
        (post_id,)
    ).fetchall()
    conn.close()
    return comments

@app.context_processor
def utility_processor():
    """
    Expose get_comments in Jinja templates
    so you can call get_comments(post.id) directly.
    """
    return dict(get_comments=get_comments)



#LOGIN###############################################################
@app.route('/')
def index():
    """Redirect to login if not logged in, otherwise to exam selection."""
    if 'user_id' in session:
        for i in session:
            print(f"session[i]: {session[i]}")
        return redirect(url_for('select_exam'))
    return render_template('index.html')


@app.route('/view_file/<path:filename>')
def view_file(filename):
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    # Specify the appropriate mimetype for DOCX files
    # For docx, the mimetype is typically 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    mimetype = None
    ext = filename.rsplit('.', 1)[1].lower()
    if ext == 'pdf':
        mimetype = 'application/pdf'
    elif ext in ['doc', 'docx']:
        mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    elif ext in ['png', 'jpg', 'jpeg', 'gif']:
        # Let send_file auto-detect for images or you can   specify image/jpeg etc.
        mimetype = None
    elif ext == 'txt':
        mimetype = 'text/plain'
    else:
        mimetype = None

    response = make_response(send_file(full_path, as_attachment=False, mimetype=mimetype))
    # Force inline content disposition; note many browsers will still prompt download if no viewer exists
    response.headers['Content-Disposition'] = f'inline; filename="{filename}"'
    return response

#LOGIN###############################################################

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        sifre = request.form['sifre'].strip()
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM kullanicilar WHERE email = ?", (email,)).fetchone()
        conn.close()
        print("DEBUG: Retrieved user:", user)
        if user:
            print("DEBUG: Stored password hash:", repr(user['sifre']))
            if check_password_hash(user['sifre'], sifre):
                # Check if the email is confirmed
                if not user['email_confirmed']:
                    flash("Lütfen önce e-posta adresinizi onaylayın.", "warning")
                    return render_template('login.html', error="E-posta henüz onaylanmamış.")
                # Set session variables since the user is now confirmed.
                session['user_id'] = user['id']
                session['user_name'] = user['ad']
                session['rolId'] = user['rolId']
                flash("<strong>Giriş başarılı!</strong> Hoşgeldin, <strong>" + user['ad'] + "</strong>! Başarı dolu bir deneyim seni bekliyor.", "success")
                return redirect(url_for('select_exam'))
            else:
                error = "E-posta veya şifre hatalı"
                return render_template('login.html', error=error)
        else:
            error = "E-posta veya şifre hatalı"
            return render_template('login.html', error=error)
    return render_template('login.html')


#LOGOUT #################################
@app.route('/logout')
def logout():
    """Logs out the user and renders a confirmation page."""
    session.pop('user_id', None)
    session.pop('user_name', None)
    #flash("Çıkış yaptınız.", "info")
    return render_template('logout.html')
##LOGOUT##################################

#USER REGISTRATION###############################################################
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user and send a confirmation email."""
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        sifre = request.form['sifre'].strip()

        if not name or not email or not sifre:
            flash("<strong>Lütfen tüm alanları doldurun.</strong>", "danger")
            return render_template('register.html')

        conn = get_db_connection()
        # Check case-insensitively for existing email
        existing = conn.execute("SELECT * FROM kullanicilar WHERE LOWER(email) = ?", (email,)).fetchone()
        if existing:
            flash("<strong>Bu e-posta adresi zaten kayıtlı.</strong>", "warning")
            conn.close()
            return render_template('register.html')

        hashed_password = generate_password_hash(sifre)
        # Ensure the user is inserted with email_confirmed = 0 (not confirmed)
        cursor = conn.execute(
            "INSERT INTO kullanicilar (ad, email, sifre, rolId, email_confirmed) VALUES (?, ?, ?, ?, ?)",
            (name, email, hashed_password, 2, 0)
        )
        conn.commit()
        new_user_id = cursor.lastrowid
        conn.close()

        # Generate the confirmation token and URL.
        token = generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        # Render the email template (activate.html) with the confirm URL.
        html = render_template('activate.html', confirm_url=confirm_url, name=name)
        send_email(email, "Lütfen E-posta Adresinizi Doğrulayın", html)

        # Flash a striking message; do not log the user in automatically.
        flash(f"<strong>Kayıt başarılı!</strong> Hoşgeldin, <strong>{name}</strong>! Lütfen e-posta adresinize gönderilen doğrulama bağlantısını kontrol edin.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

#USER REGISTRATION###############################################################


####### DELETE ACCOUNT ############################################
@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    """
    Allows a logged-in user to delete (unsubscribe) their account from the database.
    """
    # Check if the user is logged in
    if 'user_id' not in session:
        flash("Bu işlemi yapmak için giriş yapmalısınız.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        # Confirm the user truly wants to delete their account.
        conn = get_db_connection()

        # Optionally: If you have child references, remove them or rely on CASCADE.
        # For example, if blog_posts or cevaplar references user:
        # conn.execute("DELETE FROM blog_posts WHERE posted_by = ?", (user_id,))
        # conn.execute("DELETE FROM cevaplar WHERE kullanici_id = ?", (user_id,))
        # etc.

        # Now, remove the user from the 'kullanicilar' table.
        conn.execute("DELETE FROM kullanicilar WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        # Log out the user to clear session
        session.pop('user_id', None)
        session.pop('user_name', None)
        session.pop('rolId', None)

        flash("Hesabınız kalıcı olarak silinmiştir. Üzgünüz sizi kaybettiğimize!", "info")
        return redirect(url_for('login'))

    # If GET request, render a confirmation form
    return render_template('delete_account.html')
#LOGIN REGISTRATION###############################################################



# DISPLAY MEMBERS OF THE WEBSITE ##################################################
from flask import flash

# (somewhere after your other imports and @roles_required decorator)

@app.route('/members')
@roles_required(1)  # only admins can see the full list — remove decorator if you want everyone to see it
def members():
    """List all registered users."""
    conn = get_db_connection()
    users = conn.execute("""
        SELECT
          u.id,
          u.ad    AS name,
          u.email,
          r.rolAdi AS role
        FROM kullanicilar u
        LEFT JOIN roller r ON u.rolId = r.rolId
        ORDER BY u.ad COLLATE NOCASE
    """).fetchall()
    conn.close()

    return render_template('members.html', users=users)


#SELECT EXAM###############################################################
@app.route('/select_exam', methods=['GET'])
def select_exam():
    """Exam subject selection page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('select_exam.html')
#SELECT EXAM###############################################################


# EXAM ###############################################################
@app.route('/exam/<subject>', methods=['GET', 'POST'])
def exam(subject):
    # 1) Normalize hyphens to plain ASCII minus:
    subject = subject.replace("\u2011", "-").replace("\u2010", "-")

    # 2) Map each URL slug to the exact `konu` in your DB:
    TOPIC_MAPPING = {
        # IT interview:
        'Python':       'Python',
        'Java':         'Java',
        'JavaScript':   'JavaScript',
        'C':            'C',
        'C++':          'C++',
        'Golang':       'Golang',
        'C#':           'C#',
        'SQL':          'SQL',
        'HTML':         'HTML',
        'CSS':          'CSS',

        # 5th grade math:
        '5sinif-kesirler':            'Kesirler',
        '5sinif-orant':               'Oran-Orantı',
        '5sinif-cebirselifadeler':    'Cebirsel İfadeler',
        '5sinif-geometri':            'Geometri',
        '5sinif-problemler':          'Problemler',
        '5sinif-geneldeneme':         'Genel Deneme',

        # 6th grade math:
        '6sinif-kesirler':            'Kesirler',
        '6sinif-orant':               'Oran-Orantı',
        '6sinif-cebirselifadeler':    'Cebirsel İfadeler',
        '6sinif-geometri':            'Geometri',
        '6sinif-problemler':          'Problemler',
        '6sinif-geneldeneme':         'Genel Deneme',

        # 7th grade math:
        '7sinif-kesirler':            'Kesirler',
        '7sinif-orant':               'Oran-Orantı',
        '7sinif-cebirselifadeler':    'Cebirsel İfadeler',
        '7sinif-geometri':            'Geometri',
        '7sinif-problemler':          'Problemler',
        '7sinif-geneldeneme':         'Genel Deneme',

        # 8th grade math:
        '8sinif-kesirler':            'Kesirler',
        '8sinif-orant':               'Oran-Orantı',
        '8sinif-cebirselifadeler':    'Cebirsel İfadeler',
        '8sinif-geometri':            'Geometri',
        '8sinif-problemler':          'Problemler',
        '8sinif-geneldeneme':         'Genel Deneme',
    }

    # 3) Disallow anything not in our map:
    if subject not in TOPIC_MAPPING:
        return redirect(url_for('select_exam'))

    actual_topic = TOPIC_MAPPING[subject]

    # 4) Protect the page:
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    if request.method == 'GET':
        sorular = conn.execute(
            "SELECT * FROM sorular WHERE konu = ?",
            (actual_topic,)
        ).fetchall()
        conn.close()
        print(f"GET /exam/{subject}: found {len(sorular)} rows for konu={actual_topic!r}")
        return render_template('exam.html', sorular=sorular, subject=subject)

    # POST: grade answers
    conn = get_db_connection()
    sorular = conn.execute(
        "SELECT * FROM sorular WHERE konu = ?", (actual_topic,)
    ).fetchall()

    if request.method == 'POST':
        action = request.form.get('action', 'finish')
        results = {}
        dogru_sayisi = 0

        # grade in‑memory
        for soru in sorular:
            given = request.form.get(f"cevap_{soru['id']}", "").strip()
            correct = soru['dogru_cevap'].strip()
            is_correct = (given == correct)
            if is_correct:
                dogru_sayisi += 1
            results[soru['id']] = {
                'given': given,
                'correct': correct,
                'is_correct': is_correct
            }

        if action == 'review':
            # re‑render exam.html with review/highlight data
            return render_template('exam.html',
                                   sorular=sorular,
                                   subject=subject,
                                   review=True,
                                   results=results)

        # otherwise action == 'finish': record to DB and redirect
        for soru in sorular:
            r = results[soru['id']]
            conn.execute(
                "INSERT INTO cevaplar (kullanici_id, soru_id, verilen_cevap, dogru_mu) "
                "VALUES (?, ?, ?, ?)",
                (session['user_id'], soru['id'], r['given'], int(r['is_correct']))
            )

        # record overall exam result
        conn.execute(
            "INSERT INTO sinavsonuclari (kullanici_id, konu, skor, tarih) VALUES (?, ?, ?, datetime('now'))",
            (session['user_id'], actual_topic, dogru_sayisi)
        )

        # … your code to update the user's en_yuksek_skor etc …
        conn.commit()
        conn.close()

        return redirect(url_for('result',
                                skor=dogru_sayisi,
                                subject=subject))
    else:
        conn.close()
        return render_template('exam.html', sorular=sorular, subject=subject)
# EXAM ENDS ###############################################################


#RESULTS###############################################################
@app.route('/result')
def result():
    """Exam result page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    skor = request.args.get('skor', 0, type=int)
    subject = request.args.get('subject', '')
    return render_template('result.html', skor=skor, subject=subject)
#RESULTS ENDS ###############################################################

@app.context_processor
def inject_scores():
    conn = get_db_connection()
    row = conn.execute("SELECT MAX(skor) AS max_skor FROM sinavsonuclari").fetchone()
    top_score = row["max_skor"] if row and row["max_skor"] is not None else 0
    user_best = 0
    user_role_id = None

    if 'user_id' in session:
        user_row = conn.execute(
            "SELECT en_yuksek_skor, rolId FROM kullanicilar WHERE id = ?",
            (session['user_id'],)
        ).fetchone()
        if user_row:
            user_best = user_row['en_yuksek_skor'] or 0
            user_role_id = user_row['rolId']

    conn.close()
    return {
        'top_score': top_score,
        'user_best': user_best,
        'user_role_id': user_role_id  # <-- role ID for use in templates
    }


########################################
# BLOG ROUTES
########################################

@app.route('/blog')
def blog():
    """Display all blog posts with optional filtering."""
    q = request.args.get('q', '').strip()
    conn = get_db_connection()
    if q:
        posts = conn.execute(
            """
            SELECT
                bp.id,
                bp.title,
                bp.content,
                bp.filename,
                bp.filetype,
                bp.created_at,
                bp.posted_by AS author_id,
                COALESCE(u.ad, 'Anonymous') AS author_name
            FROM blog_posts bp
            LEFT JOIN kullanicilar u ON bp.posted_by = u.id
            WHERE (bp.title LIKE ? OR bp.content LIKE ?) AND bp.approved = 1
            ORDER BY bp.created_at DESC
            """,
            ('%' + q + '%', '%' + q + '%')
        ).fetchall()
    else:
        posts = conn.execute(
            """
            SELECT
                bp.id,
                bp.title,
                bp.content,
                bp.filename,
                bp.filetype,
                bp.created_at,
                bp.posted_by AS author_id,
                COALESCE(u.ad, 'Anonymous') AS author_name
            FROM blog_posts bp
            LEFT JOIN kullanicilar u ON bp.posted_by = u.id
            WHERE bp.approved = 1
            ORDER BY bp.created_at DESC
            """
        ).fetchall()
    conn.close()
    return render_template(
        'blog.html',
        posts=posts,
        q=q,
        user_role_id=session.get('rolId')
    )



#BLOG ENDS ###############################################################

#NEW BLOG POST###############################################################
@app.route('/blog/new', methods=['GET', 'POST'])
@roles_required(1, 2)  # Allow both role 1 and role 2 to add posts
def new_blog_post():
    """Create a new blog post with an optional file upload."""
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        uploaded_file = request.files.get('file')
        filename = None
        filetype = None

        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            uploaded_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            ext = filename.rsplit('.', 1)[1].lower()
            if ext == 'pdf':
                filetype = 'pdf'
            elif ext == 'docx':
                filetype = 'document'
            elif ext == 'txt':
                filetype = 'txt'
            else:
                filetype = 'image'

        # Get the posting user's id from the session
        posted_by = session.get('user_id')

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO blog_posts (title, content, filename, filetype, posted_by, approved) VALUES (?, ?, ?, ?, ?, ?)",
            (title, content, filename, filetype, posted_by, 0)  # approved is 0 (pending)
        )
        conn.commit()
        conn.close()
        flash("Blog post created successfully! It is pending moderator approval.", "success")
        return redirect(url_for('blog'))
    return render_template('new_blog_post.html')



##NEW BLOG POST ENDS ###############################################################

####### UPDATE THE ARTICLE #######
####### UPDATE THE ARTICLE #######
@app.route('/blog/edit/<int:post_id>', methods=['GET', 'POST'])
@roles_required(1,2)  # Allow both admin (rolId == 1) and regular users (rolId == 2) to access if they are the author.
def update_blog_yazisi(post_id):
    """Update an existing blog post. After updating, set approved to 0 so the post must be re-moderated."""
    conn = get_db_connection()
    post = conn.execute("SELECT * FROM blog_posts WHERE id = ?", (post_id,)).fetchone()
    if post is None:
        flash("Blog yazısı bulunamadı.", "danger")
        conn.close()
        return redirect(url_for('blog'))

    # Get the current user's ID and role
    current_user_id = session.get('user_id')
    current_role = session.get('rolId')

    # Allow update only if the current user is admin or is the author of this post.
    if not (current_role == 1 or current_user_id == post['posted_by']):
        flash("Bu yazıyı düzenleme yetkiniz yok.", "danger")
        conn.close()
        return redirect(url_for('blog'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        file = request.files.get('file')
        # Preserve existing file details by default
        filename = post['filename']
        filetype = post['filetype']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            ext = filename.rsplit('.', 1)[1].lower()
            print("DEBUG (edit): Uploaded file extension is:", ext)  # Debug print
            if ext == 'pdf':
                filetype = 'pdf'
            elif ext in ['doc', 'docx']:
                filetype = 'document'
            elif ext == 'txt':
                filetype = 'txt'
            else:
                filetype = 'image'

        # Update the post and also reset 'approved' to 0 so that the post is sent for moderation again.
        conn.execute(
            "UPDATE blog_posts SET title = ?, content = ?, filename = ?, filetype = ?, approved = 0 WHERE id = ?",
            (title, content, filename, filetype, post_id)
        )
        conn.commit()
        conn.close()
        flash("Blog yazısı güncellendi. Lütfen moderatör onayı bekleyiniz.", "success")
        return redirect(url_for('blog'))

    conn.close()
    return render_template('update_blog_yazisi.html', post=post)


######################################### update blog post route ##########################################


######## DELETE THE ARTICLE #######
@app.route('/blog/delete/<int:post_id>', methods=['GET', 'POST'])
@roles_required(1,2)  # Only rolId=1 can access
def delete_blog_post(post_id):
    """Belirli bir blog yazısını silmek için route."""
    conn = get_db_connection()
    post = conn.execute("SELECT * FROM blog_posts WHERE id = ?", (post_id,)).fetchone()
    if post is None:
        flash("Blog yazısı bulunamadı.", "danger")
        conn.close()
        return redirect(url_for('blog'))

    # Get the current user's ID and role.
    current_user_id = session.get('user_id')
    current_role = session.get('rolId')

    # Allow deletion if the user is an admin (role 1) OR if the user is the author.
    if not (current_role == 1 or current_user_id == post['posted_by']):
        flash("Bu işlemi yapmak için yetkiniz yok.", "danger")
        conn.close()
        return redirect(url_for('blog'))

    if request.method == 'POST':
        # Eğer dosya yüklenmişse, dosyayı sistemden de silebiliriz.
        if post['filename']:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], post['filename'])
            if os.path.exists(filepath):
                os.remove(filepath)
        conn.execute("DELETE FROM blog_posts WHERE id = ?", (post_id,))
        conn.commit()
        conn.close()
        flash("Blog yazısı silindi.", "success")
        return redirect(url_for('blog'))

    conn.close()
    return render_template('delete_blog_yazisi.html', post=post)
######################################### delete blog post route ##########################################

#BLOG POST DETAIL###############################################################
@app.route('/blog/<int:post_id>')
def blog_post_detail(post_id):
    """Display the full details of a specific blog post."""
    conn = get_db_connection()
    post = conn.execute("SELECT * FROM blog_posts WHERE id = ?", (post_id,)).fetchone()
    conn.close()
    if post is None:
        flash("Blog yazısı bulunamadı.", "danger")
        return redirect(url_for('blog'))
    return render_template('blog_post_detail.html', post=post)
#BLOG POST DETAIL ENDS ###############################################################

#MODERATOR ROUTE ######################################################
@app.route('/blog/moderate')
@roles_required(1)  # Only administrators can moderate posts.
def moderate_blog_posts():
    """Display all blog posts that are pending approval."""
    conn = get_db_connection()
    pending_posts = conn.execute(
        """
        SELECT
            bp.id,
            bp.title,
            bp.content,
            bp.filename,
            bp.filetype,
            bp.created_at,
            bp.posted_by AS author_id,
            u.ad AS posted_by
        FROM blog_posts bp
        LEFT JOIN kullanicilar u ON bp.posted_by = u.id
        WHERE bp.approved = 0
        ORDER BY bp.created_at DESC
        """
    ).fetchall()
    conn.close()
    return render_template('moderate.html', posts=pending_posts)


# APPROVE ROOTE ###################################
@app.route('/blog/approve/<int:post_id>', methods=['POST'])
@roles_required(1)
def approve_post(post_id):
    """Approve a blog post so that it goes live."""
    conn = get_db_connection()
    conn.execute("UPDATE blog_posts SET approved = 1 WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    flash("Blog yazısı onaylandı.", "success")
    return redirect(url_for('moderate_blog_posts'))


##################  COMMENT SECTIONS  #################################################
@app.route('/blog/<int:post_id>/comments', methods=['POST'])
def add_comment(post_id):
    """
    Add a new comment to the specified blog post.
    Requires the user be logged in.
    """
    if 'user_id' not in session:
        flash("Yorum yapmak için giriş yapmalısınız.", "danger")
        return redirect(url_for('login'))

    new_comment = request.form.get('comment', '').strip()
    if not new_comment:
        flash("Yorum boş olamaz.", "warning")
        return redirect(url_for('blog_post_detail', post_id=post_id))

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO blog_comments (blog_post_id, user_id, comment) VALUES (?, ?, ?)",
        (post_id, session['user_id'], new_comment)
    )
    conn.commit()
    conn.close()

    flash("Yorumunuz başarıyla eklendi.", "success")
    return redirect(url_for('blog_post_detail', post_id=post_id))



#  EDIT A COMMENT ######################################################
@app.route('/blog/comment/<int:comment_id>/edit', methods=['GET', 'POST'])
def edit_comment(comment_id):
    """Edit an existing comment."""
    conn = get_db_connection()
    comment = conn.execute("SELECT * FROM blog_comments WHERE id = ?", (comment_id,)).fetchone()
    if not comment:
        flash("Yorum bulunamadı.", "danger")
        conn.close()
        return redirect(url_for('blog'))

    # Only allow editing if the current user is the author of the comment.
    if session.get('user_id') != comment['user_id']:
        flash("Bu yorumu düzenleme yetkiniz yok.", "danger")
        conn.close()
        return redirect(url_for('blog_post_detail', post_id=comment['blog_post_id']))

    if request.method == 'POST':
        new_comment_text = request.form.get('comment')
        if not new_comment_text or new_comment_text.strip() == "":
            flash("Yorum boş bırakılamaz.", "warnin g")
            conn.close()
            return redirect(url_for('edit_comment', comment_id=comment_id))
        conn.execute(
            "UPDATE blog_comments SET comment = ? WHERE id = ?",
            (new_comment_text.strip(), comment_id)
        )
        conn.commit()
        conn.close()
        flash("Yorum güncellendi.", "success")
        return redirect(url_for('blog_post_detail', post_id=comment['blog_post_id']))

    conn.close()
    return render_template('edit_comment.html', comment=comment)


########### DELETE A COMMENT  #########################
@app.route('/blog/comment/delete/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    """
    Delete a specific comment if the user is the comment's author
    or an admin.
    """
    if 'user_id' not in session:
        flash("Bu işlemi yapmak için giriş yapmalısınız.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    comment = conn.execute(
        "SELECT * FROM blog_comments WHERE id = ?",
        (comment_id,)
    ).fetchone()

    if not comment:
        conn.close()
        flash("Yorum bulunamadı.", "danger")
        return redirect(url_for('blog'))

    # Ensure the user is the comment author or an admin
    if comment['user_id'] != session['user_id'] and session.get('rolId') != 1:
        conn.close()
        flash("Bu yorumu silmeye yetkiniz yok.", "danger")
        return redirect(url_for('blog'))

    # Otherwise, delete
    conn.execute("DELETE FROM blog_comments WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()
    flash("Yorum silindi.", "success")

    # After deletion, redirect back to the post’s detail page
    return redirect(url_for('blog_post_detail', post_id=comment['blog_post_id']))

# … after your existing confirm_email route …

@app.route('/forgot_password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM kullanicilar WHERE email = ?", (email,)).fetchone()
        conn.close()

        if not user:
            flash("Böyle bir e‑posta kayıtlı değil.", "warning")
            return redirect(url_for('forgot_password'))

        # generate token & URL
        token = generate_password_reset_token(user['email'])
        reset_url = url_for('reset_password', token=token, _external=True)

        # **Here** `user` is defined, so this will work:
        html = render_template('reset_email.html',
                               name=user['ad'],
                               reset_url=reset_url)
        send_email(user['email'], "Şifre Sıfırlama Talebi", html)

        flash("Şifre sıfırlama bağlantısı e‑postanıza gönderildi.", "info")
        return redirect(url_for('login'))

    # GET: render the “forgot password” form
    return render_template('forgot_password.html')



@app.route('/reset_password/<token>', methods=['GET','POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except Exception:
        flash("Sıfırlama bağlantısı geçersiz veya süresi dolmuş.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_pass = request.form['password'].strip()
        confirm  = request.form['confirm'].strip()
        if not new_pass or new_pass != confirm:
            flash("Şifreler eşleşmeli ve boş olmamalı.", "warning")
            return render_template('reset_password.html')

        hashed = generate_password_hash(new_pass)
        conn = get_db_connection()
        conn.execute("UPDATE kullanicilar SET sifre = ? WHERE email = ?", (hashed, email))
        conn.commit()
        conn.close()

        flash("Şifreniz başarıyla güncellendi. Giriş yapabilirsiniz.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

############ RESET PASSWORD ENDING #######################################

# MEMBERS DELETION ############################################
@app.route('/members/delete/<int:user_id>', methods=['POST'])
@roles_required(1)  # only admins
def delete_member(user_id):
    """Admin can delete a user account."""
    conn = get_db_connection()
    conn.execute("DELETE FROM kullanicilar WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash("Kullanıcı başarıyla silindi.", "success")
    return redirect(url_for('members'))
########## MEMBERS DELETION ENDING #######################

# USERS SCORE ORDER #################################################
# near the bottom of your file, after your existing routes

@app.route('/scoreboard')
def scoreboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    rows = conn.execute("""
        SELECT
          ss.id     AS attempt_id,
          ss.konu   AS konu,
          ss.skor   AS dogru_sayisi,
          ss.tarih  AS tarih
        FROM sinavsonuclari ss
        WHERE ss.kullanici_id = ?
        ORDER BY ss.tarih DESC
    """, (session['user_id'],)).fetchall()
    conn.close()

    return render_template('scoreboard.html', rows=rows)

######### USERS SCORE ORDER ##################################

##############GAME ENDPOINT ###################
@app.route('/game')
def game():
    return render_template('game.html')


#hakkımda###############################################################
@app.route('/about')
def about():
    """Display the About page."""
    return render_template('about.html')
#hakkımda ENDS ###############################################################

###### TEMPERATURE READING ##############################################################
current_temperature = None

@app.route('/update_temp', methods=['GET', 'POST'])
def update_temp():
    conn = get_db_connection()

    if request.method == 'POST':
        data = request.get_json()
        if not data or 'temperature' not in data:
            return jsonify(error='Temperature data not provided'), 400

        temp = data['temperature']
        # insert a new reading
        conn.execute(
            'INSERT INTO temperature_readings (value) VALUES (?)',
            (temp,)
        )
        conn.commit()
        print(f"[{datetime.now()}] Saved temperature: {temp}")
        return jsonify(status='success', temperature=temp), 200

    # GET → fetch the very latest reading
    row = conn.execute(
        'SELECT value, timestamp '
        'FROM temperature_readings '
        'ORDER BY timestamp DESC '
        'LIMIT 1'
    ).fetchone()

    if row:
        temperature = row['value']
        timestamp   = row['timestamp']
    else:
        temperature = None
        timestamp   = None

    return render_template(
        'temperature.html',
        temperature=temperature,
        timestamp=timestamp
    )
# TEMPERATURE READING #######################################################################

########################################
# RUN THE APPLICATION
########################################
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)

#########################################################################################################################################
##########################################################################################################
########################################################################
###############################################
#############################
##############


# import random
# import sqlite3
# import os

# # Adjust the DATABASE path if necessary
# DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'exam.db')

# def get_db_connection():
#     conn = sqlite3.connect(DATABASE)
#     conn.row_factory = sqlite3.Row
#     return conn

# # Get a connection
# conn = get_db_connection()

# # Create a cursor object
# cursor = conn.cursor()

# # Query the database
# query = "SELECT * FROM sorular"
# cursor.execute(query)

# # Fetch all results
# data = cursor.fetchall()  # This will return a list of tuples

# # Now data will contain the rows from the 'sorular' table

# values = []

# kesirler_8 = [
#     ("2^3 * 2^4 = 2^? işleminin sonucu kaçtır?", "2^7", "2^12;2^1;2^4", "Kesirler"),
#     ("(3^2)^3 = ?", "3^6", "3^5;3^8;6^2", "Kesirler"),
#     ("√49 = ?", "7", "49;√7;±7", "Kesirler"),
#     ("√(16) = ?", "4", "-4;8;±4", "Kesirler"),
#     ("2^5 kaçtır?", "32", "25;16;64", "Kesirler"),
#     ("5^2 kaçtır?", "25", "52;10;7", "Kesirler"),
#     ("2^3 + 3^2 = ?", "17", "36;13;12", "Kesirler"),
#     ("1,2 × 10^3 sayısı hangi sayıya eşittir?", "1200", "120;12000;1.200.000", "Kesirler"),
#     ("4,5 × 10^2 sayısı kaçtır?", "450", "45;4.500;0,045", "Kesirler"),
#     ("Aşağıdaki sayılardan hangisi irrasyonel sayıdır?", "√2", "0,5;3/4;9,81", "Kesirler"),
#     ("0,121212... ondalık sayısı kesir olarak nedir?", "12/99", "12/100;11/90;1212/9999", "Kesirler"),
#     ("4^-2 = ?", "1/16", "-16;16; -1/16", "Kesirler"),
#     ("(-2)^3 = ?", "-8", "8;4;-4", "Kesirler"),
#     ("10^0 = ?", "1", "0;10; -1", "Kesirler"),
#     ("27^(1/3) = ?", "3", "9;1/3;√3", "Kesirler"),
#     ("25^(1/2) = ?", "5", "25;±5;625", "Kesirler"),
#     ("5√(2) ifadesinde 5 hangi rolde?", "Katsayı", "Taban;Kareköklü sayı;Üs", "Kesirler"),
#     ("Aşağıdaki sayılardan hangisi 10'un tam kuvvetidir?", "1000", "50;200;100", "Kesirler"),
#     ("2^4 * 3^4 = ?", "6^4", "12^4;5^4;6^8", "Kesirler"),
#     ("1/5 sayısının negatif kuvvetlerinden biri aşağıdakilerden hangisidir?", "(1/5)^-1 = 5", "(1/5)^2;5^-1;1/5^-1", "Kesirler")
# ]

# oran_oranti_8 = [
#     ("Nüfusu 1200 olan bir kasabanın nüfusu bir yılda %10 artmıştır. Yeni nüfus kaç olmuştur?", "1320", "1300;120;1210", "Oran-Orantı"),
#     ("Bir mal %20 karla 144 TL'ye satılıyor. Malın maliyeti kaç TL'dir?", "120", "100;140;180", "Oran-Orantı"),
#     ("Bir para %50 zararla 75 TL'ye satıldıysa, ilk fiyatı kaç TL idi?", "150", "50;125;100", "Oran-Orantı"),
#     ("80 sayısının %25 fazlası kaçtır?", "100", "85;120;75", "Oran-Orantı"),
#     ("Bir miktar para yıllık %20 basit faizle bir yılda 240 TL faiz getirmiştir. Ana para kaç TL'dir?", "1200", "1000;2000;480", "Oran-Orantı"),
#     ("a : b : c = 2 : 3 : 5 ve a + b + c = 100 ise c kaçtır?", "50", "20;30;60", "Oran-Orantı"),
#     ("x, y'ye ters orantılı. x=4 iken y=15 ise, x=6 iken y kaçtır?", "10", "12;8;22.5", "Oran-Orantı"),
#     ("120'nin 2/3'ü 80'in kaç katıdır?", "2", "1/2;4/3;4", "Oran-Orantı"),
#     ("Bir işin %30'u 6 günde bitti ise tamamı kaç günde biter?", "20", "9;18;12", "Oran-Orantı"),
#     ("Bir sayı 4 ile doğru orantılı, 6 ile ters orantılıdır. Bu sayı 12 olduğuna göre orantı sabiti kaçtır?", "18", "8;2;72", "Oran-Orantı"),
#     ("%20'si 40 olan sayı ile %40'ı 20 olan sayının farkı kaçtır?", "180", "20;80;100", "Oran-Orantı"),
#     ("%60'ı 90 olan sayının %20'si kaçtır?", "30", "20;15;45", "Oran-Orantı"),
#     ("Birinci sayının ikinci sayıya oranı 3/5'tir. İkinci sayı 40 ise birinci sayı kaçtır?", "24", "15;30;60", "Oran-Orantı"),
#     ("%10 artış sonrası 99 olan değer, başlangıçta kaçtı?", "90", "100;110;89", "Oran-Orantı"),
#     ("3x + 2y = 4 denklemi y=mx+n formunda yazıldığında m kaçtır?", "-3/2", "3/2;2/3;-2", "Oran-Orantı"),
#     ("Bir doğru orantıda orantı sabiti nasıl bulunur?", "y/x (sabit)", "x*y (sabit);x^2 (sabit);y^2 (sabit)", "Oran-Orantı"),
#     ("Bir öğrenci sınavda soruların %75'ini doğru yaptı. 60 soruluk sınavda kaç soruyu yanlış yaptı?", "15", "45;15;20", "Oran-Orantı"),
#     ("48 sayısının 16'ya oranı kaçtır?", "3", "1/3;4;2", "Oran-Orantı"),
#     ("Bir haritada 5 cm 20 km'yi gösteriyorsa, 2 cm kaç km'yi gösterir?", "8 km", "4 km;10 km;50 km", "Oran-Orantı"),
#     ("a/5 = b/8 = c/10 ise a:b:c oranı nedir?", "5:8:10", "8:5:10;10:8:5;5:10:8", "Oran-Orantı")
# ]

# cebirsel_ifadeler_8 = [
#     ("2*(x - 3) = 14 denkleminde x kaçtır?", "10", "7;8;5", "Cebirsel İfadeler"),
#     ("(x + 3)^2 açılımı aşağıdakilerden hangisidir?", "x^2 + 6x + 9", "x^2 + 9; x^2 + 3; x^2 + 3x + 3", "Cebirsel İfadeler"),
#     ("(a - b)^2 özdeşliği aşağıdakilerden hangisine eşittir?", "a^2 - 2ab + b^2", "a^2 + 2ab + b^2; a^2 - b^2; 2a^2 - 2b^2", "Cebirsel İfadeler"),
#     ("5x + 2 = 3x + 10 denkleminde x kaçtır?", "4", "8; -4; 2", "Cebirsel İfadeler"),
#     ("| -7 | = ?", "7", "-7;0; -(-7)", "Cebirsel İfadeler"),
#     ("x^2 = 49 denkleminde x için kaç çözüm vardır?", "2", "1;0;sonsuz", "Cebirsel İfadeler"),
#     ("x^2 = -1 denkleminin çözüm kümesi nedir?", "Gerçel sayılarda çözüm yoktur", "{-1,1};{i,-i};{-1}", "Cebirsel İfadeler"),
#     ("2x - 4 > 0 eşitsizliğinde x nasıl bir sayı olmalıdır?", "x > 2", "x < 2; x = 2; x >= 0", "Cebirsel İfadeler"),
#     ("3x + 5 < 2x + 8 eşitsizliğinde x için hangi aralık doğrudur?", "x < 3", "x > 3; x = 3; x < -3", "Cebirsel İfadeler"),
#     ("x^3 ifadesi aşağıdakilerden hangisine eşittir?", "x * x * x", "3x; x^2 + x; x + x + x", "Cebirsel İfadeler"),
#     ("2x(3x - 5) = ? (dağıtın)", "6x^2 - 10x", "6x^2 - 5;6x - 10;6x^2 - 5x", "Cebirsel İfadeler"),
#     ("9x^2 - 4 ifadesi çarpanlarına ayrılırsa hangisi elde edilir?", "(3x - 2)(3x + 2)", "(9x - 4)(x + 1);(3x - 4)(3x + 1);(9x - 2)(x + 2)", "Cebirsel İfadeler"),
#     ("x + 1 = 0 denkleminin çözümü nedir?", "x = -1", "x = 1; x = 0; çözüm yok", "Cebirsel İfadeler"),
#     ("a^3 + b^3 özdeşliği aşağıdakilerden hangisidir?", "(a+b)(a^2 - ab + b^2)", "a^3 + b^3; (a+b)^3; (a-b)(a^2 + ab + b^2)", "Cebirsel İfadeler"),
#     ("x^2 - 1 = 0 denkleminin kökleri toplamı kaçtır?", "0", "1; -1; -2", "Cebirsel İfadeler"),
#     ("2x + y = 10 doğrusunun y-eksenini kestiği nokta (kesim noktası) hangisidir?", "(0,10)", "(5,0); (10,0); (0,5)", "Cebirsel İfadeler"),
#     ("3x + 4 = 4x - 5 denkleminde x kaçtır?", "9", "1; -9; -1", "Cebirsel İfadeler"),
#     ("m = 2n - 5 bağıntısında n = 6 ise m kaçtır?", "7", "17; -7; -17", "Cebirsel İfadeler"),
#     ("(x + 2)(x - 2) = ? (çarpımı)", "x^2 - 4", "x^2 + 4; x^2 - 2x; x^2 - 4x + 4", "Cebirsel İfadeler"),
#     ("7a + 7b ifadesi 7 çarpanı dışına alınırsa hangi ifade elde edilir?", "7(a + b)", "7a + b; 7(a - b); 7ab", "Cebirsel İfadeler")
# ]

# geometri_8 = [
#     ("Bir üçgende kenarlar 5, 12 ve x olsun. Üçgenin dik üçgen olabilmesi için x kaç olmalıdır?", "13", "11;13;14", "Geometri"),
#     ("3-4-5 üçgeni nedir?", "Dik üçgen (özeldir)", "Eşkenar üçgen;İkizkenar üçgen;Benzer üçgen", "Geometri"),
#     ("Bir üçgende kenar uzunlukları 7, 24, 25 ise üçgenin açılarından biri nedir?", "90°", "60°;30°;75°", "Geometri"),
#     ("Bir dik üçgende dik kenarlar 8 ve 15 ise hipotenüs uzunluğu kaçtır?", "17", "23;9;11", "Geometri"),
#     ("Bir dik üçgende hipotenüs 10, bir dik kenar 6 ise diğer dik kenar uzunluğu kaçtır?", "8", "4;6;12", "Geometri"),
#     ("Bir düzgün beşgenin bir dış açısının ölçüsü nedir?", "72°", "108°;60°;36°", "Geometri"),
#     ("Bir paralelkenarın alanı nasıl hesaplanır?", "Taban * yükseklik", "1/2 * (taban * yükseklik);tüm kenarlar çarpımı;taban^2", "Geometri"),
#     ("Bir dairenin alanı nasıl hesaplanır?", "πr^2", "2πr;πd;2r", "Geometri"),
#     ("Bir silindirin hacmi nasıl hesaplanır?", "Taban alanı * yükseklik (πr^2 * h)", "2πrh;2πr^2 + 2πrh; (4/3)πr^3", "Geometri"),
#     ("Kenar uzunlukları orantılı olan iki üçgen için aşağıdakilerden hangisi doğrudur?", "Benzer üçgendirler", "Eş üçgendirler;Dik üçgendirler;İkizkenar üçgendirler", "Geometri"),
#     ("Eş üçgenler için aşağıdakilerden hangisi doğrudur?", "Tüm açıları ve kenarları eşittir", "Sadece açıları eşittir;Sadece kenarları eşittir;Alanları farklı olabilir", "Geometri"),
#     ("Yamukta yalnız bir çift kenar için ne söylenebilir?", "Paralel", "Dik;Eş;Çakışık", "Geometri"),
#     ("Koordinat düzleminde (5, -2) noktası hangi bölgededir?", "IV. bölge", "I. bölge;II. bölge;III. bölge", "Geometri"),
#     ("(x, y) -> (x+3, y-2) dönüşümü ne tür bir geometrik dönüşümdür?", "Öteleme (translasyon)", "Döndürme (rotasyon);Yansıma (simetri);Işınlanma", "Geometri"),
#     ("Yansıma (ayna) simetrisinde orijin etrafında (x, y) noktası nereye gider?", "(-x, -y)", "(y, x);(-y, -x);(x, -y)", "Geometri"),
#     ("Bir şeklin kendi üzerine örtüşmesi durumu hangi simetri türüdür?", "Döndürme simetrisi", "Öteleme simetrisi;Yansıma simetrisi;Eksen simetrisi", "Geometri"),
#     ("Bir cismin bir noktadan aynı uzaklıkta noktalar kümesine ne ad verilir?", "Küre", "Daire;Silindir;Konik", "Geometri"),
#     ("İki düzlem uzayda en fazla kaç noktada kesişir?", "Bir doğru boyunca (sonsuz)", "1 nokta;2 nokta;kesişmez", "Geometri"),
#     ("Bir dikdörtgenler prizmasının ayrıt uzunlukları 2, 3, 4 ise hacmi kaç birim küptür?", "24", "9;12;20", "Geometri")
# ]

# problemler_8 = [
#     ("Ali ile Veli'nin yaşları toplamı 40'tır. Ali, Veli'den 8 yaş büyüktür. Ali ve Veli'nin yaşları nedir?", "24 ve 16", "20 ve 20;26 ve 14;22 ve 18", "Problemler"),
#     ("Bir tren saatte 80 km hızla 3 saatte kaç km yol alır?", "240 km", "160 km;80 km;400 km", "Problemler"),
#     ("Bir baba, oğlundan 30 yaş büyüktür. 5 yıl sonra babanın yaşı, oğlunun yaşının 2 katı olacağına göre, oğul şimdi kaç yaşındadır?", "10", "5;15;20", "Problemler"),
#     ("100 sayfası olan bir kitabın %30'u okundu. Kaç sayfa okunmuştur?", "30", "70;3;100", "Problemler"),
#     ("Bir sınıfta futbol oynayan 15 öğrenci, basketbol oynayan 10 öğrenci var. Hiçbir spor yapmayan 5 öğrenci var ve toplam öğrenci sayısı 25. Kaç öğrenci her iki sporu da yapıyor? (Kesişim problem)", "5", "0;10;15", "Problemler"),
#     ("Bir havuz iki muslukla 8 saatte doluyor. Musluklardan biri tek başına 12 saatte doldurursa, diğer musluk tek başına kaç saatte doldurur?", "24", "6;18;12", "Problemler"),
#     ("Bir işe Ali tek başına 12 günde, Veli tek başına 6 günde bitirebiliyor. İkisi birlikte bu işi kaç günde bitirir?", "4", "3;2;9", "Problemler"),
#     ("6 litrelik %30 tuz içeren bir suya 4 litre saf su ekleniyor. Yeni karışımın tuz oranı yaklaşık yüzde kaç olur?", "%18", "%20;%30;%24", "Problemler"),
#     ("Bir otomobil birinci yarı yolu saatte 60 km hızla, ikinci yarı yolu 90 km hızla gidiyor. Toplam ortalama hızı (yaklaşık) kaç km/saattir?", "72 km/sa", "75 km/sa;70 km/sa;65 km/sa", "Problemler"),
#     ("Bir kenarının uzunluğu n olan bir karenin çevresi aşağıdakilerden hangisidir?", "4n", "n^2;2n;n+4", "Problemler"),
#     ("Bir dikdörtgenin uzun kenarı kısa kenarının 3 katıdır. Çevresi 80 cm ise kısa kenar uzunluğu kaç cm'dir?", "10", "5;15;20", "Problemler"),
#     ("Bir otobüs hızını %20 artırırsa 5 saatte aldığı yolu kaç saatte alır?", "4 saat", "6 saat;5 saat;3 saat", "Problemler"),
#     ("Fiyatı 200 TL olan bir ürüne %10 zam yapılıp ardından %10 indirim yapılıyor. Son fiyat kaç TL olur?", "198", "200;180;220", "Problemler"),
#     ("Bir işi Ali 8 günde, Ayşe 12 günde bitiriyor. İkisi birlikte çalışarak işin 3 gününde ne kadarlık kısmını bitirirler?", "3/5", "1/2;2/3;3/4", "Problemler"),
#     ("Ardışık üç sayının toplamı 72'dir. Bu sayılar nedir?", "23, 24, 25", "24, 25, 26;21, 24, 27;20, 24, 28", "Problemler"),
#     ("Bir sınıftaki öğrencilerin 1/3'ü kızdır. Kızlar 10 kişi ise sınıfta kaç öğrenci vardır?", "30", "13;15;20", "Problemler"),
#     ("Bir kutuda 8 kırmızı, 6 mavi, 4 yeşil top vardır. Bu kutudan rastgele çekilen bir topun yeşil olma olasılığı nedir?", "1/3", "1/2;2/3;4/18", "Problemler"),
#     ("İki basamaklı bir sayının onlar basamağı birler basamağının 3 katıdır. Sayı 82'den büyüktür. Bu şartları sağlayan sayı aşağıdakilerden hangisidir?", "93", "31;62;73", "Problemler"),
#     ("Bir köydeki toplam koyun ve tavuk sayısı 40'tır. Toplam ayak sayısı 100 olduğuna göre kaç koyun vardır? (koyun 4 ayak, tavuk 2 ayak)", "10", "20;30;5", "Problemler"),
#     ("Bir zar atılıyor. Çift sayı gelme olasılığı nedir?", "1/2", "1/6;1/3;2/3", "Problemler")
# ]

# genel_deneme_8 = [
#     ("Bir para %50 zararla 75 TL'ye satıldıysa, ilk fiyatı kaç TL idi?", "150", "50;125;100", "Genel Deneme"),
#     ("x + 1 = 0 denkleminin çözümü nedir?", "x = -1", "x = 1; x = 0; çözüm yok", "Genel Deneme"),
#     ("10^0 = ?", "1", "0;10; -1", "Genel Deneme"),
#     ("Bir işi Ali 8 günde, Ayşe 12 günde bitiriyor. İkisi birlikte çalışarak işin 3 gününde ne kadarlık kısmını bitirirler?", "3/5", "1/2;2/3;3/4", "Genel Deneme"),
#     ("Bir dikdörtgenler prizmasının ayrıt uzunlukları 2, 3, 4 ise hacmi kaç birim küptür?", "24", "9;12;20", "Genel Deneme"),
#     ("Ali ile Veli'nin yaşları toplamı 40'tır. Ali, Veli'den 8 yaş büyüktür. Ali ve Veli'nin yaşları nedir?", "24 ve 16", "20 ve 20;26 ve 14;22 ve 18", "Genel Deneme"),
#     ("(x + 2)(x - 2) = ? (çarpımı)", "x^2 - 4", "x^2 + 4; x^2 - 2x; x^2 - 4x + 4", "Genel Deneme"),
#     ("Eş üçgenler için aşağıdakilerden hangisi doğrudur?", "Tüm açıları ve kenarları eşittir", "Sadece açıları eşittir;Sadece kenarları eşittir;Alanları farklı olabilir", "Genel Deneme"),
#     ("3-4-5 üçgeni nedir?", "Dik üçgen (özeldir)", "Eşkenar üçgen;İkizkenar üçgen;Benzer üçgen", "Genel Deneme"),
#     ("4^-2 = ?", "1/16", "-16;16; -1/16", "Genel Deneme"),
#     ("Bir havuz iki muslukla 8 saatte doluyor. Musluklardan biri tek başına 12 saatte doldurursa, diğer musluk tek başına kaç saatte doldurur?", "24", "6;18;12", "Genel Deneme"),
#     ("2^3 + 3^2 = ?", "17", "36;13;12", "Genel Deneme"),
#     ("Yamukta yalnız bir çift kenar için ne söylenebilir?", "Paralel", "Dik;Eş;Çakışık", "Genel Deneme"),
#     ("100 sayfası olan bir kitabın %30'u okundu. Kaç sayfa okunmuştur?", "30", "70;3;100", "Genel Deneme"),
#     ("9x^2 - 4 ifadesi çarpanlarına ayrılırsa hangisi elde edilir?", "(3x - 2)(3x + 2)", "(9x - 4)(x + 1);(3x - 4)(3x + 1);(9x - 2)(x + 2)", "Genel Deneme"),
#     ("3x + 4 = 4x - 5 denkleminde x kaçtır?", "9", "1; -9; -1", "Genel Deneme"),
#     ("80 sayısının %25 fazlası kaçtır?", "100", "85;120;75", "Genel Deneme"),
#     ("0,121212... ondalık sayısı kesir olarak nedir?", "12/99", "12/100;11/90;1212/9999", "Genel Deneme"),
#     ("Bir doğru orantıda orantı sabiti nasıl bulunur?", "y/x (sabit)", "x*y (sabit);x^2 (sabit);y^2 (sabit)", "Genel Deneme"),
#     ("Bir öğrenci sınavda soruların %75'ini doğru yaptı. 60 soruluk sınavda kaç soruyu yanlış yaptı?", "15", "45;15;20", "Genel Deneme")
# ]



# # # You can later extend your master data list as follows:
# # # data.extend(data_css)

# data = data + kesirler_8 + oran_oranti_8 + cebirsel_ifadeler_8 + geometri_8 + problemler_8  + genel_deneme_8
# for row in data:
#     if len(row) == 4:
#         soru_metni, dogru_cevap, false_opts, konu = row

#         # Split the false options into a list and remove extra spaces
#         options = [opt.strip() for opt in false_opts.split(';')]

#         # Append the correct answer into the options list
#         options.append(dogru_cevap)

#         # Randomly shuffle so the correct answer appears in one of the four positions
#         random.shuffle(options)

#         # Take the first four options
#         secenek1, secenek2, secenek3, secenek4 = options[:4]

#         # Use parameterized queries to prevent SQL injection
#         values.append((soru_metni, dogru_cevap, secenek1, secenek2, secenek3, secenek4, konu))  # Correct number of elements

#     else:
#         print(f"Skipping row with unexpected format: {row}")

# # Insert data using parameterized queries
# insert_stmt = """
#     INSERT INTO sorular (soru_metni, dogru_cevap, secenek1, secenek2, secenek3, secenek4, konu)
#     VALUES (?, ?, ?, ?, ?, ?, ?)
# """

# try:
#     cursor.executemany(insert_stmt, values)  # Using executemany for efficiency
#     conn.commit()  # Commit the transaction
#     print(f"Successfully inserted {len(values)} rows.")
# except Exception as e:
#     print(f"Error inserting data: {e}")
# finally:
#     conn.close()  # Close the connection to the database