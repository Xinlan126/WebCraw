import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = '123#456'
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'database/crawler.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

MAIL_SERVER = 'smtp.example.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'email@example.com'
MAIL_PASSWORD = 'email-password'
MAIL_DEFAULT_SENDER = 'email@gmail.com'

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'pdfs')
ALLOWED_EXTENSIONS = {'pdf'}

# Crawler Configuration
MAX_CRAWL_TIME = 60  # seconds
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebCrawler/1.0'