import os
import time
import socket
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from sqlalchemy import text
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional
from datetime import datetime
from flask_wtf.file import FileField, FileAllowed, MultipleFileField
from wtforms import ValidationError
from werkzeug.utils import secure_filename
import random
from apscheduler.schedulers.background import BackgroundScheduler
import openai
import string
from datetime import datetime, timedelta
import io
from PIL import Image
import base64
import resend

try:
    import cloudinary
    import cloudinary.uploader
    import cloudinary.api

    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME')
    cloud_api_key = os.environ.get('CLOUDINARY_API_KEY')
    cloud_api_secret = os.environ.get('CLOUDINARY_API_SECRET')

    cloudinary_enabled = bool(cloud_name and cloud_api_key and cloud_api_secret)
    if cloudinary_enabled:
        cloudinary.config(
            cloud_name=cloud_name,
            api_key=cloud_api_key,
            api_secret=cloud_api_secret,
            secure=True
        )
    else:
        cloudinary_enabled = False
except ImportError:
    cloudinary_enabled = False

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-dev-key-change-me')
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
database_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if database_url.startswith('postgresql'):
    if 'sslmode' not in database_url:
        database_url += '?sslmode=require'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

mail = Mail(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

VERIFICATION_CODE_EXPIRE_MINUTES = 10
openai_client = openai.OpenAI(api_key=os.environ.get("OPEN_API_KEY"))
def generate_ai_post():
    with app.app_context():
        try:
            bot = User.query.filter_by(username="AI_Bot").first()
            if not bot:
                app.logger.error("AI_Bot не найден в БД")
                return
            prompt = os.environ.get("AI_PROMPT", 
                "Напиши короткий, интересный пост (150-250 символов) для социальной сети. Мысль должна быть закончена за это количество времени"
            )
            response = openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "Ты креативный философ."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=250,
                temperature=0.8
            )
            content = response.choices[0].message.content.strip()
            post = Post(content=content, author=bot)
            db.session.add(post)
            db.session.commit()
            app.logger.info(f"✅ AI-бот создал пост: {content[:50]}...")
        except Exception as e:
            app.logger.error(f"❌ Ошибка генерации поста: {e}")
scheduler = BackgroundScheduler()
scheduler.add_job(func=generate_ai_post, trigger="interval", hours=4, id="ai_post_job")
scheduler.start()
import atexit
atexit.register(lambda: scheduler.shutdown())
def check_smtp_connection():
    host = app.config['MAIL_SERVER']
    port = app.config['MAIL_PORT']
    try:
        with socket.create_connection((host, port), timeout=10):
            app.logger.info(f"✅ SMTP доступен {host}:{port}")
            return True
    except Exception as e:
        app.logger.error(f"❌ SMTP недоступен {host}:{port}: {e}")
        return False

def generate_verification_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_verification_email(recipient, code):
    """Отправляет код подтверждения через Resend."""
    resend.api_key = os.environ.get("RESEND_API_KEY")
    try:
        resend.Emails.send({
            "from": "noreply@iltp05-10corp.ru",
            "to": recipient,
            "subject": "Код подтверждения регистрации",
            "html": f"<strong>Ваш код подтверждения: {code}</strong><br>Код действителен {VERIFICATION_CODE_EXPIRE_MINUTES} минут.",
            "text": f"Ваш код подтверждения: {code}. Код действителен {VERIFICATION_CODE_EXPIRE_MINUTES} минут."
        })
        app.logger.info(f"Код {code} отправлен на {recipient} через Resend")
    except Exception as e:
        app.logger.error(f"Ошибка отправки через Resend: {e}")
        raise e
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    can_post = db.Column(db.Boolean, default=False)
    avatar = db.Column(
        db.String(300),
        default='https://res.cloudinary.com/dssim246k/image/upload/v1775454177/default_ehpw4u.jpg'
    )
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    messages_sent = db.relationship(
        'PrivateMessage',
        foreign_keys='PrivateMessage.sender_id',
        back_populates='sender',
        lazy='dynamic'
    )
    messages_received = db.relationship(
        'PrivateMessage',
        foreign_keys='PrivateMessage.recipient_id',
        back_populates='recipient',
        lazy='dynamic'
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    attachments = db.relationship('Attachment', backref='post', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    sticker_id = db.Column(db.Integer, db.ForeignKey('stickers.id'), nullable=True)
    likes_count = db.Column(db.Integer, default=0)

class Attachment(db.Model):
    __tablename__ = 'attachments'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    file_url = db.Column(db.String(300), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)

class Like(db.Model):
    __tablename__ = 'likes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)

    user = db.relationship('User', backref=db.backref('likes', lazy=True))
    post = db.relationship('Post', backref=db.backref('likes', lazy=True))

chat_participants = db.Table(
    'chat_participants',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('chat_id', db.Integer, db.ForeignKey('chats.id'), primary_key=True),
    db.Column('status', db.String(20), default='pending'),  # pending, accepted, declined
    db.Column('last_read_message_id', db.Integer, nullable=True),
    db.Column('joined_at', db.DateTime, default=datetime.utcnow)
)

class Chat(db.Model):
    __tablename__ = 'chats'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_group = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100), nullable=True)

    participants = db.relationship(
        'User',
        secondary=chat_participants,
        lazy='dynamic',
        backref=db.backref('chats', lazy='dynamic')
    )
    messages = db.relationship('Message', backref='chat', lazy='dynamic', cascade='all, delete-orphan')

    def last_message(self):
        return self.messages.order_by(Message.timestamp.desc()).first()

    def unread_count(self, user_id):
        """Количество непрочитанных сообщений для конкретного пользователя."""
        participant_data = db.session.query(chat_participants).filter_by(
            chat_id=self.id, user_id=user_id
        ).first()
        last_read = participant_data.last_read_message_id if participant_data else 0
        return self.messages.filter(Message.id > last_read).count()

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)  # можно заменить на связь many-to-many, но оставим для простоты

    sender = db.relationship('User', backref='messages_sent_new')

class Sticker(db.Model):
    __tablename__ = 'stickers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image_file = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f'<Sticker {self.name}>'
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
with app.app_context():
    db.create_all()
    print("✅ Таблицы созданы или уже существуют в Supabase.")
    bot_username = "AI_Bot"
    bot_email = "ai_bot@iltp05-10corp.ru"
    bot = User.query.filter_by(username=bot_username).first()
    if not bot:
        bot = User(
            username=bot_username,
            email=bot_email,
            is_admin=False,
            can_post=True,
            avatar="https://res.cloudinary.com/dssim246k/image/upload/v1772282449/default_avatar_i5bg2p.png"
        )
        bot.set_password(os.urandom(24).hex())
        db.session.add(bot)
        db.session.commit()
        print("✅ Пользователь AI_Bot создан")
    else:
        print("✅ AI_Bot уже существует")
    try:
        if Sticker.query.count() == 0:
            stickers = [
                Sticker(name='smile', image_file='stickers/smile.png', description='😊'),
                Sticker(name='heart', image_file='stickers/heart.png', description='❤️'),
                Sticker(name='thumbsup', image_file='stickers/thumbsup.png', description='👍'),
                Sticker(name='cry', image_file='stickers/cry.png', description='😢'),
                Sticker(name='fire', image_file='stickers/fire.png', description='🔥'),
            ]
            db.session.add_all(stickers)
            db.session.commit()
            print("✅ Начальные стикеры созданы.")
        else:
            print("✅ Стикеры уже есть.")
    except Exception as e:
        db.session.rollback()
        print(f"⚠️ Ошибка при создании стикеров: {e}")
class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class PostForm(FlaskForm):
    content = TextAreaField('Текст поста', validators=[DataRequired()])
    files = MultipleFileField('Прикрепить файлы (изображения, документы)',
                              validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif', 'txt', 'pdf'], 'Только изображения и документы!')])
    sticker = SelectField('Стикер', coerce=int, validators=[Optional()])
    submit = SubmitField('Опубликовать')

    def __init__(self, *args, **kwargs):
        super(PostForm, self).__init__(*args, **kwargs)
        self.sticker.choices = [(0, 'Без стикера')] + [(s.id, s.name) for s in Sticker.query.all()]

class ProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=2, max=20)])
    avatar = FileField('Аватар', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Только изображения!')])
    old_password = PasswordField('Старый пароль', validators=[Optional()])
    new_password = PasswordField('Новый пароль', validators=[Optional(), Length(min=6, max=20)])
    confirm_new_password = PasswordField('Подтвердите новый пароль', validators=[Optional(), EqualTo('new_password')])
    submit = SubmitField('Обновить профиль')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Это имя уже занято. Выберите другое.')

class MessageForm(FlaskForm):
    chat_id = HiddenField('Chat ID', validators=[DataRequired()])
    content = TextAreaField('Сообщение', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Отправить')
@app.route('/')
def index():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    stickers = Sticker.query.all()
    return render_template('index.html', posts=posts, stickers=stickers)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email уже зарегистрирован', 'danger')
            return redirect(url_for('register'))
        code = generate_verification_code()
        session['reg_data'] = {
            'username': form.username.data,
            'email': form.email.data,
            'password_hash': generate_password_hash(form.password.data),
            'code': code,
            'code_time': datetime.utcnow().isoformat()
        }
        try:
            send_verification_email(form.email.data, code)
            flash('Код подтверждения отправлен на ваш email.', 'info')
            return redirect(url_for('verify'))
        except Exception as e:
            import traceback
            app.logger.error(f"Ошибка отправки письма на {form.email.data}: {e}\n{traceback.format_exc()}")
            flash('Ошибка при отправке письма. Попробуйте позже.', 'danger')
            session.pop('reg_data', None)
            return redirect(url_for('register'))

    return render_template('register.html', form=form)

@app.route('/verify', methods=['GET', 'POST'])
@csrf.exempt
def verify():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    reg_data = session.get('reg_data')
    if not reg_data:
        flash('Сессия истекла. Начните регистрацию заново.', 'warning')
        return redirect(url_for('register'))

    if request.method == 'POST':
        user_code = request.form.get('code', '').strip()
        stored_code = reg_data['code']
        code_time = datetime.fromisoformat(reg_data['code_time'])
        if datetime.utcnow() - code_time > timedelta(minutes=VERIFICATION_CODE_EXPIRE_MINUTES):
            flash('Код устарел. Запросите новый.', 'danger')
            session.pop('reg_data', None)
            return redirect(url_for('register'))

        if user_code == stored_code:
            user = User(
                username=reg_data['username'],
                email=reg_data['email'],
                password_hash=reg_data['password_hash']
            )
            db.session.add(user)
            db.session.commit()
            session.pop('reg_data', None)
            login_user(user)
            flash('Регистрация успешно завершена!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный код подтверждения.', 'danger')
            return redirect(url_for('verify'))
    return render_template('verify.html', email=reg_data['email'])

@app.route('/resend-code')
def resend_code():
    reg_data = session.get('reg_data')
    if not reg_data:
        flash('Нет активной регистрации.', 'warning')
        return redirect(url_for('register'))

    new_code = generate_verification_code()
    reg_data['code'] = new_code
    reg_data['code_time'] = datetime.utcnow().isoformat()
    session['reg_data'] = reg_data

    try:
        send_verification_email(reg_data['email'], new_code)
        flash('Новый код отправлен.', 'info')
    except Exception as e:
        flash('Ошибка отправки. Попробуйте позже.', 'danger')

    return redirect(url_for('verify'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Вход выполнен успешно', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Неверный email или пароль', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        if form.username.data != current_user.username:
            current_user.username = form.username.data
        cropped_avatar = request.form.get('cropped_avatar')
        if cropped_avatar and cropped_avatar.startswith('data:image'):
            try:
                image_data = cropped_avatar.split(',')[1]
                image_binary = base64.b64decode(image_data)
                upload_result = cloudinary.uploader.upload(
                    image_binary,
                    folder="avatars",
                    public_id=f"user_{current_user.id}",
                    overwrite=True,
                    transformation=[{'width': 300, 'height': 300, 'crop': 'fill'}]
                )
                current_user.avatar = upload_result['secure_url']
            except Exception as e:
                flash(f'Ошибка при загрузке аватара: {str(e)}', 'danger')
        if form.old_password.data and form.new_password.data:
            if not current_user.check_password(form.old_password.data):
                flash('Неверный старый пароль', 'danger')
                return redirect(url_for('profile'))
            current_user.set_password(form.new_password.data)

        db.session.commit()
        flash('Профиль успешно обновлён', 'success')
        return redirect(url_for('profile'))

    form.username.data = current_user.username
    return render_template('profile.html', form=form)

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.date_posted.desc()).all()
    comments_count = Comment.query.filter_by(user_id=user.id).count()
    return render_template('user_profile.html', user=user, posts=posts, comments_count=comments_count)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('content')
    if not content or content.strip() == '':
        flash('Комментарий не может быть пустым', 'danger')
        return redirect(url_for('post_detail', post_id=post_id))

    comment = Comment(content=content, author=current_user, post=post)
    db.session.add(comment)
    db.session.commit()
    flash('Комментарий добавлен', 'success')
    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/post/<int:post_id>')
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post_detail.html', post=post)

@app.route('/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    try:
        if 'avatar' not in request.files:
            return jsonify({'success': False, 'error': 'Файл не найден'}), 400

        file = request.files['avatar']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Файл не выбран'}), 400

        upload_result = cloudinary.uploader.upload(
            file,
            folder="avatars",
            public_id=f"user_{current_user.id}",
            overwrite=True,
            transformation=[{'width': 300, 'height': 300, 'crop': 'fill'}]
        )

        current_user.avatar = upload_result['secure_url']
        db.session.commit()

        return jsonify({'success': True, 'url': upload_result['secure_url']})

    except Exception as e:
        app.logger.error(f"Avatar upload error: {e}")
        return jsonify({'success': False, 'error': 'Внутренняя ошибка сервера'}), 500

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        user = User.query.get_or_404(user_id)
        if action == 'grant':
            user.can_post = True
            flash(f'Пользователю {user.username} разрешено создавать посты', 'success')
        elif action == 'revoke':
            user.can_post = False
            flash(f'У пользователя {user.username} отнято право создавать посты', 'warning')
        db.session.commit()
        return redirect(url_for('admin_users'))

    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/debug-smtp')
def debug_smtp():
    import socket
    results = {}
    for port in [587, 465, 25, 2525]:
        try:
            with socket.create_connection(('smtp.gmail.com', port), timeout=5):
                results[port] = '✅ Доступен'
        except Exception as e:
            results[port] = f'❌ Ошибка: {e}'
    return str(results)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if not (current_user.is_admin or current_user.can_post):
        flash('У вас нет прав на создание постов', 'danger')
        return redirect(url_for('index'))

    form = PostForm()
    if form.validate_on_submit():
        sticker_id = form.sticker.data if form.sticker.data != 0 else None
        post = Post(content=form.content.data, author=current_user, sticker_id=sticker_id)
        db.session.add(post)
        db.session.flush()

        if form.files.data:
            for file in form.files.data:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    new_filename = f"post_{post.id}_{int(time.time())}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    file.save(file_path)
                    attachment = Attachment(filename=filename, file_url=new_filename, post_id=post.id)
                    db.session.add(attachment)

        db.session.commit()
        flash('Пост опубликован', 'success')
        return redirect(url_for('index'))

    return render_template('create_post.html', form=form)

@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not (current_user.is_admin or current_user.id == post.user_id):
        flash('У вас нет прав на редактирование этого поста', 'danger')
        return redirect(url_for('index'))

    form = PostForm(obj=post)
    if form.validate_on_submit():
        post.content = form.content.data
        post.sticker_id = form.sticker.data if form.sticker.data != 0 else None

        if form.files.data:
            for file in form.files.data:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    new_filename = f"post_{post.id}_{int(time.time())}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    file.save(file_path)
                    attachment = Attachment(filename=filename, file_url=new_filename, post_id=post.id)
                    db.session.add(attachment)

        db.session.commit()
        flash('Пост обновлён', 'success')
        return redirect(url_for('index'))

    return render_template('edit_post.html', form=form, post=post)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not (current_user.is_admin or current_user.id == post.user_id):
        flash('У вас нет прав на удаление этого поста', 'danger')
        return redirect(url_for('index'))

    Like.query.filter_by(post_id=post.id).delete()

    for att in post.attachments:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], att.file_url)
        if os.path.exists(file_path):
            os.remove(file_path)

    db.session.delete(post)
    db.session.commit()
    flash('Пост удалён', 'success')
    return redirect(url_for('index'))

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id
    if not (current_user.is_admin or current_user.id == comment.user_id):
        flash('У вас нет прав на удаление этого комментария', 'danger')
        return redirect(url_for('post_detail', post_id=post_id))

    db.session.delete(comment)
    db.session.commit()
    flash('Комментарий удалён', 'success')
    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/attachment/<int:attachment_id>/delete', methods=['POST'])
@login_required
def delete_attachment(attachment_id):
    att = Attachment.query.get_or_404(attachment_id)
    post = att.post
    if not (current_user.is_admin or current_user.id == post.user_id):
        flash('Нет прав', 'danger')
        return redirect(url_for('index'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], att.file_url)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(att)
    db.session.commit()
    flash('Вложение удалено', 'success')
    return redirect(url_for('edit_post', post_id=post.id))

from sqlalchemy import or_


@app.route('/messages')
@login_required
def messages():
    """Главная страница чатов (левая панель со списком)."""
    # Получаем все чаты, где текущий пользователь — участник со статусом 'accepted'
    user_chats = current_user.chats.join(
        chat_participants,
        and_(
            chat_participants.c.chat_id == Chat.id,
            chat_participants.c.user_id == current_user.id,
            chat_participants.c.status == 'accepted'
        )
    ).order_by(Chat.updated_at.desc()).all()

    # Также получаем приглашения (pending) для отображения в отдельной вкладке
    pending_chats = current_user.chats.join(
        chat_participants,
        and_(
            chat_participants.c.chat_id == Chat.id,
            chat_participants.c.user_id == current_user.id,
            chat_participants.c.status == 'pending'
        )
    ).all()

    return render_template('messages.html',
                           chats=user_chats,
                           pending_chats=pending_chats,
                           active_chat=None)


@app.route('/messages/send', methods=['GET', 'POST'])
@login_required
def send_message():
    form = MessageForm()
    if form.validate_on_submit():
        message = PrivateMessage(
            sender_id=current_user.id,
            recipient_id=form.recipient.data,
            content=form.content.data
        )
        db.session.add(message)
        db.session.commit()
        flash('Сообщение отправлено', 'success')
        return redirect(url_for('messages'))

    return render_template('send_message.html', form=form)

@app.route('/messages/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = PrivateMessage.query.get_or_404(message_id)
    if message.sender_id != current_user.id and message.recipient_id != current_user.id:
        flash('У вас нет прав на удаление этого сообщения', 'danger')
        return redirect(url_for('messages'))

    db.session.delete(message)
    db.session.commit()
    flash('Сообщение удалено', 'success')
    return redirect(url_for('messages'))

@app.route('/chat/<int:chat_id>')
@login_required
def chat_view(chat_id):
    """Просмотр переписки в конкретном чате."""
    chat = Chat.query.get_or_404(chat_id)

    # Проверка доступа
    participant = db.session.query(chat_participants).filter_by(
        chat_id=chat_id, user_id=current_user.id, status='accepted'
    ).first()
    if not participant:
        flash('У вас нет доступа к этому чату.', 'danger')
        return redirect(url_for('messages'))

    # Все активные чаты пользователя (для левой панели)
    user_chats = current_user.chats.join(
        chat_participants,
        and_(
            chat_participants.c.chat_id == Chat.id,
            chat_participants.c.user_id == current_user.id,
            chat_participants.c.status == 'accepted'
        )
    ).order_by(Chat.updated_at.desc()).all()

    pending_chats = current_user.chats.join(
        chat_participants,
        and_(
            chat_participants.c.chat_id == Chat.id,
            chat_participants.c.user_id == current_user.id,
            chat_participants.c.status == 'pending'
        )
    ).all()

    # Сообщения чата (последние 50)
    messages_list = chat.messages.order_by(Message.timestamp.desc()).limit(50).all()[::-1]

    # Обновить last_read_message_id для текущего пользователя
    if messages_list:
        last_msg_id = messages_list[-1].id
        stmt = chat_participants.update().where(
            chat_participants.c.chat_id == chat_id,
            chat_participants.c.user_id == current_user.id
        ).values(last_read_message_id=last_msg_id)
        db.session.execute(stmt)
        db.session.commit()

    form = MessageForm(chat_id=chat_id)

    return render_template('messages.html',
                           chats=user_chats,
                           pending_chats=pending_chats,
                           active_chat=chat,
                           messages=messages_list,
                           form=form)
@app.route('/chat/<int:chat_id>/send', methods=['POST'])
@login_required
def send_chat_message(chat_id):
    """Отправка сообщения в чат (поддерживает AJAX)."""
    chat = Chat.query.get_or_404(chat_id)
    participant = db.session.query(chat_participants).filter_by(
        chat_id=chat_id, user_id=current_user.id, status='accepted'
    ).first()
    if not participant:
        return jsonify({'error': 'Access denied'}), 403

    content = request.form.get('content', '').strip()
    if not content:
        flash('Сообщение не может быть пустым.', 'warning')
        return redirect(url_for('chat_view', chat_id=chat_id))

    msg = Message(chat_id=chat_id, sender_id=current_user.id, content=content)
    db.session.add(msg)
    chat.updated_at = datetime.utcnow()
    db.session.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'id': msg.id,
            'content': msg.content,
            'timestamp': msg.timestamp.strftime('%d.%m.%Y %H:%M'),
            'sender': {
                'id': current_user.id,
                'username': current_user.username
            }
        })
    else:
        flash('Сообщение отправлено.', 'success')
        return redirect(url_for('chat_view', chat_id=chat_id))

@app.route('/chat/create', methods=['GET', 'POST'])
@login_required
def create_chat():
    """Создание нового чата (отправка приглашения)."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Пользователь не найден.', 'danger')
            return redirect(url_for('create_chat'))
        if user.id == current_user.id:
            flash('Нельзя создать чат с самим собой.', 'warning')
            return redirect(url_for('create_chat'))

        # Проверяем существующий чат с этим пользователем
        existing_chat = None
        for chat in current_user.chats:
            other = chat.participants.filter(User.id != current_user.id).first()
            if other and other.id == user.id:
                existing_chat = chat
                break

        if existing_chat:
            # Проверяем статус приглашения
            participant = db.session.query(chat_participants).filter_by(
                chat_id=existing_chat.id, user_id=current_user.id
            ).first()
            if participant and participant.status == 'pending':
                flash('Приглашение уже отправлено и ожидает ответа.', 'info')
            elif participant and participant.status == 'declined':
                # Повторно отправляем приглашение
                stmt = chat_participants.update().where(
                    chat_participants.c.chat_id == existing_chat.id,
                    chat_participants.c.user_id == user.id
                ).values(status='pending')
                db.session.execute(stmt)
                db.session.commit()
                flash('Приглашение отправлено повторно.', 'success')
            else:
                flash('Чат с этим пользователем уже существует.', 'info')
            return redirect(url_for('messages'))

        # Создаём новый чат
        chat = Chat()
        db.session.add(chat)
        db.session.flush()

        # Текущий пользователь — принят автоматически
        ins1 = chat_participants.insert().values(
            user_id=current_user.id, chat_id=chat.id, status='accepted'
        )
        db.session.execute(ins1)
        # Приглашаемый пользователь — в ожидании
        ins2 = chat_participants.insert().values(
            user_id=user.id, chat_id=chat.id, status='pending'
        )
        db.session.execute(ins2)
        db.session.commit()

        flash(f'Приглашение отправлено пользователю {user.username}.', 'success')
        return redirect(url_for('messages'))

    return render_template('create_chat.html')

@app.route('/chat/<int:chat_id>/invite_response', methods=['POST'])
@login_required
def invite_response(chat_id):
    """Принять или отклонить приглашение в чат."""
    action = request.form.get('action')
    if action not in ['accept', 'decline']:
        return jsonify({'error': 'Invalid action'}), 400

    chat = Chat.query.get_or_404(chat_id)
    participant = db.session.query(chat_participants).filter_by(
        chat_id=chat_id, user_id=current_user.id, status='pending'
    ).first()
    if not participant:
        flash('Нет активного приглашения.', 'warning')
        return redirect(url_for('messages'))

    if action == 'accept':
        stmt = chat_participants.update().where(
            chat_participants.c.chat_id == chat_id,
            chat_participants.c.user_id == current_user.id
        ).values(status='accepted')
        db.session.execute(stmt)
        db.session.commit()
        flash('Вы присоединились к чату.', 'success')
        return redirect(url_for('chat_view', chat_id=chat_id))
    else:
        stmt = chat_participants.delete().where(
            chat_participants.c.chat_id == chat_id,
            chat_participants.c.user_id == current_user.id
        )
        db.session.execute(stmt)
        db.session.commit()
        flash('Приглашение отклонено.', 'info')
        return redirect(url_for('messages'))

@app.route('/chat/<int:chat_id>/message/<int:msg_id>/delete', methods=['POST'])
@login_required
def delete_chat_message(chat_id, msg_id):
    """Удаление сообщения (только для отправителя)."""
    msg = Message.query.get_or_404(msg_id)
    if msg.chat_id != chat_id:
        abort(404)
    if msg.sender_id != current_user.id:
        flash('Вы можете удалять только свои сообщения.', 'danger')
        return redirect(url_for('chat_view', chat_id=chat_id))

    db.session.delete(msg)
    db.session.commit()
    flash('Сообщение удалено.', 'success')
    return redirect(url_for('chat_view', chat_id=chat_id))
@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        posts = Post.query.filter(Post.content.contains(query)).order_by(Post.date_posted.desc()).all()
    else:
        posts = []
    return render_template('search_results.html', posts=posts, query=query)
@app.route('/test-ai-post')
@login_required
def test_ai_post():
    if not current_user.is_admin:
        flash("Доступ только админу", "danger")
        return redirect(url_for('index'))
    generate_ai_post()
    flash("Пост от AI сгенерирован (проверьте логи)", "info")
    return redirect(url_for('index'))
@app.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    if like:
        db.session.delete(like)
        liked = False
    else:
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        liked = True
    db.session.commit()
    post.likes_count = len(post.likes)
    db.session.commit()
    return jsonify({'liked': liked, 'count': post.likes_count})
@app.route('/ping')
def ping():
    """Простой эндпоинт для keep-alive сервисов."""
    return "OK", 200
@app.context_processor
def utility_processor():
    def avatar_url(user):
        if user is None:
            return 'https://res.cloudinary.com/dssim246k/image/upload/v1775454177/default_ehpw4u.jpg'
        if user.avatar:
            return user.avatar
        return 'https://res.cloudinary.com/dssim246k/image/upload/v1775454177/default_ehpw4u.jpg'

    return dict(avatar_url=avatar_url, current_year=datetime.utcnow().year)

if __name__ == '__main__':
    app.run(debug=True)