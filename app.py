from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import os
import re
import uuid
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import PyPDF2
from io import BytesIO
from wordcloud import WordCloud
import base64
import validators
from collections import Counter

app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)

# Login Manager Setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(100))
    reset_expiry = db.Column(db.DateTime)
    searches = db.relationship('SearchLog', backref='user', lazy=True)


class SearchLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    pdfs = db.relationship('PDFDocument', backref='search', lazy=True)


class PDFDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    search_id = db.Column(db.Integer, db.ForeignKey('search_log.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    original_url = db.Column(db.String(500), nullable=False)
    word_stats = db.Column(db.JSON, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Helper Functions
def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset-salt')


def verify_reset_token(token, max_age=60):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=max_age)
        return email
    except:
        return None


def extract_pdf_stats(pdf_content):
    pdf = PyPDF2.PdfReader(BytesIO(pdf_content))
    text = ""
    for page in pdf.pages:
        text += page.extract_text()
    words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
    stop_words = set(['the', 'and', 'of', 'to', 'in', 'a', 'is', 'that', 'for', 'it'])
    filtered = [w for w in words if w not in stop_words and len(w) > 3]
    return dict(Counter(filtered).most_common(10))


def generate_wordcloud_data(pdf_ids):
    text = ""
    for pdf_id in pdf_ids:
        pdf = PDFDocument.query.get(pdf_id)
        with open(os.path.join(app.config['UPLOAD_FOLDER'], pdf.filename), 'rb') as f:
            pdf_content = f.read()
            pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_content))
            for page in pdf_reader.pages:
                text += page.extract_text()
    return generate_wordcloud(text)


def crawl_website(url, max_level):
    results = {'pdfs': [], 'error': None}
    visited = set()
    domain = urlparse(url).netloc

    def recursive_crawl(current_url, current_level):
        if current_level > max_level or current_url in visited:
            return
        visited.add(current_url)

        try:
            response = requests.get(current_url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.content, 'html.parser')

            # PDF detection
            for link in soup.find_all('a', href=True):
                if link['href'].lower().endswith('.pdf'):
                    pdf_url = requests.compat.urljoin(current_url, link['href'])
                    try:
                        pdf_response = requests.get(pdf_url, timeout=10)
                        if pdf_response.status_code == 200:
                            filename = f"{uuid.uuid4()}.pdf"
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            with open(filepath, 'wb') as f:
                                f.write(pdf_response.content)
                            word_stats = extract_pdf_stats(pdf_response.content)
                            results['pdfs'].append({
                                'url': pdf_url,
                                'filename': filename,
                                'source': current_url,
                                'level': current_level,
                                'word_stats': word_stats
                            })
                    except Exception as e:
                        print(f"Error downloading PDF {pdf_url}: {str(e)}")

            # Recursive crawling
            if current_level < max_level:
                for link in soup.find_all('a', href=True):
                    next_url = requests.compat.urljoin(current_url, link['href'])
                    next_domain = urlparse(next_url).netloc

                    # Level-based filtering
                    if max_level == 1:
                        continue
                    elif max_level == 2 and next_domain != domain:
                        continue

                    recursive_crawl(next_url, current_level + 1)

        except Exception as e:
            results['error'] = str(e)

    recursive_crawl(url, 1)
    return results


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nickname = request.form.get('nickname').strip()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')

        errors = {}
        if not nickname:
            errors['nickname'] = 'Nickname is required'
        elif User.query.filter_by(nickname=nickname).first():
            errors['nickname'] = 'Nickname already exists'

        if not email or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            errors['email'] = 'Valid email is required'
        elif User.query.filter_by(email=email).first():
            errors['email'] = 'Email already registered'

        if not password or len(password) < 8:
            errors['password'] = 'Password must be at least 8 characters'

        if not errors:
            try:
                user = User(
                    nickname=nickname,
                    email=email,
                    password=generate_password_hash(password)
                )
                db.session.add(user)
                db.session.commit()
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Registration failed. Please try again.', 'danger')
        else:
            return render_template('register.html', errors=errors, form_data=request.form)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_reset_token(email)
            user.reset_token = token
            user.reset_expiry = datetime.utcnow() + timedelta(seconds=60)
            db.session.commit()

            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f'Click to reset your password (valid for 60 seconds): {reset_url}'
            mail.send(msg)

        flash('If an account exists with this email, a reset link has been sent', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user or user.reset_token != token or user.reset_expiry < datetime.utcnow():
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
        else:
            user.password = generate_password_hash(password)
            user.reset_token = None
            user.reset_expiry = None
            db.session.commit()
            flash('Password updated successfully! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        nickname = request.form.get('nickname').strip()
        email = request.form.get('email').strip().lower()
        new_password = request.form.get('new_password')

        errors = {}
        if not nickname:
            errors['nickname'] = 'Nickname is required'
        elif nickname != current_user.nickname and User.query.filter_by(nickname=nickname).first():
            errors['nickname'] = 'Nickname already exists'

        if not email or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            errors['email'] = 'Valid email is required'
        elif email != current_user.email and User.query.filter_by(email=email).first():
            errors['email'] = 'Email already registered'

        if new_password and len(new_password) < 8:
            errors['new_password'] = 'Password must be at least 8 characters'

        if not errors:
            try:
                current_user.nickname = nickname
                current_user.email = email
                if new_password:
                    current_user.password = generate_password_hash(new_password)
                db.session.commit()
                flash('Profile updated successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Profile update failed. Please try again.', 'danger')
        else:
            return render_template('profile.html', errors=errors)

    return render_template('profile.html')


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        url = request.form.get('url')
        level = int(request.form.get('level', 1))

        if not validators.url(url):
            flash('Invalid URL format', 'danger')
            return redirect(url_for('search'))

        try:
            crawl_results = crawl_website(url, level)
            if crawl_results['error']:
                flash(f"Crawling error: {crawl_results['error']}", 'danger')
                return redirect(url_for('search'))

            search_log = SearchLog(
                user_id=current_user.id,
                url=url,
                level=level
            )
            db.session.add(search_log)

            for pdf in crawl_results['pdfs']:
                pdf_doc = PDFDocument(
                    search_id=search_log.id,
                    filename=pdf['filename'],
                    original_url=pdf['url'],
                    word_stats=pdf['word_stats']
                )
                db.session.add(pdf_doc)

            db.session.commit()
            flash('Crawling completed successfully!', 'success')
            return redirect(url_for('history'))

        except Exception as e:
            db.session.rollback()
            flash(f'Crawling failed: {str(e)}', 'danger')

    return render_template('search.html')


@app.route('/history')
@login_required
def history():
    searches = SearchLog.query.filter_by(user_id=current_user.id).order_by(SearchLog.timestamp.desc()).all()
    return render_template('history.html', searches=searches)


@app.route('/search-pdfs', methods=['GET', 'POST'])
@login_required
def search_pdfs():
    if request.method == 'POST':
        search_term = request.form.get('search_term').lower()
        matching_pdfs = []

        for search_log in current_user.searches:
            for pdf in search_log.pdfs:
                if search_term in [w.lower() for w in pdf.word_stats.keys()]:
                    matching_pdfs.append({
                        'pdf': pdf,
                        'search_log': search_log,
                        'count': pdf.word_stats.get(search_term, 0)
                    })

        return render_template('search_pdfs.html', results=matching_pdfs, search_term=search_term)

    return render_template('search_pdfs.html')


@app.route('/wordcloud', methods=['GET', 'POST'])
@login_required
def wordcloud():
    if request.method == 'POST':
        pdf_ids = request.form.getlist('pdf_ids')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        if pdf_ids:
            wordcloud_image = generate_wordcloud_data(pdf_ids)
        elif start_date and end_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%dT%H:%M')
                end = datetime.strptime(end_date, '%Y-%m-%dT%H:%M')
                pdfs = PDFDocument.query.join(SearchLog).filter(
                    SearchLog.user_id == current_user.id,
                    PDFDocument.timestamp.between(start, end)
                ).all()
                wordcloud_image = generate_wordcloud_data([pdf.id for pdf in pdfs])
            except ValueError:
                flash('Invalid date format', 'danger')
                return redirect(url_for('wordcloud'))
        else:
            flash('Please select PDFs or a date range', 'danger')
            return redirect(url_for('wordcloud'))

        return render_template('wordcloud.html', wordcloud_image=wordcloud_image)

    # Get all user's PDFs for selection
    pdfs = PDFDocument.query.join(SearchLog).filter(
        SearchLog.user_id == current_user.id
    ).order_by(PDFDocument.timestamp.desc()).all()

    return render_template('wordcloud.html', pdfs=pdfs)


@app.route('/download-pdf/<filename>')
@login_required
def download_pdf(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    with app.app_context():
        os.makedirs('database', exist_ok=True)
        os.makedirs('pdfs', exist_ok=True)
        db.create_all()
    app.run(debug=True)