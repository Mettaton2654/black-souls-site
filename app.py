import os
import time
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional
from datetime import datetime
from flask_wtf.file import FileField, FileAllowed, MultipleFileField
from wtforms import ValidationError
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Создаём папку для загрузок, если её нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
with app.app_context():
    db.create_all()
    print("Таблицы созданы (или уже существуют)")
# Модели
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    can_post = db.Column(db.Boolean, default=False)  # право создавать посты
    avatar = db.Column(db.String(200), default='default_avatar.png')
    posts = db.relationship('Post', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Связь с вложениями
    attachments = db.relationship('Attachment', backref='post', lazy=True, cascade='all, delete-orphan')

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)      # оригинальное имя
    file_url = db.Column(db.String(300), nullable=False)      # сохранённое имя на диске
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Формы
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
    submit = SubmitField('Опубликовать')

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

# Маршруты
@app.route('/')
def index():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email уже зарегистрирован', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрировались! Теперь войдите.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

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
        # Обновляем имя
        if form.username.data != current_user.username:
            current_user.username = form.username.data

        # Аватар
        if form.avatar.data and form.avatar.data.filename:
            file = form.avatar.data
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            new_filename = f"avatar_{current_user.id}.{ext}" if ext else f"avatar_{current_user.id}.jpg"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            file.save(file_path)
            current_user.avatar = new_filename

        # Смена пароля
        if form.old_password.data and form.new_password.data:
            if not current_user.check_password(form.old_password.data):
                flash('Неверный старый пароль', 'danger')
                return redirect(url_for('profile'))
            current_user.set_password(form.new_password.data)

        db.session.commit()
        flash('Профиль успешно обновлён', 'success')
        return redirect(url_for('profile'))
    else:
        if request.method == 'POST':
            flash('Проверьте правильность заполнения формы', 'danger')

    form.username.data = current_user.username
    return render_template('profile.html', form=form)

# --- Управление пользователями (только админ) ---
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

# --- Создание поста ---
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    # Права: админ или can_post
    if not (current_user.is_admin or current_user.can_post):
        flash('У вас нет прав на создание постов', 'danger')
        return redirect(url_for('index'))
    
    form = PostForm()
    if form.validate_on_submit():
        post = Post(content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.flush()  # чтобы получить id

        # Обработка файлов
        if form.files.data:
            for file in form.files.data:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
                    # Генерируем уникальное имя с временной меткой
                    new_filename = f"post_{post.id}_{int(time.time())}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    file.save(file_path)
                    attachment = Attachment(filename=filename, file_url=new_filename, post_id=post.id)
                    db.session.add(attachment)
        
        db.session.commit()
        flash('Пост опубликован', 'success')
        return redirect(url_for('index'))
    
    return render_template('create_post.html', form=form)

# --- Редактирование поста ---
@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Проверка прав: админ или автор
    if not (current_user.is_admin or current_user.id == post.user_id):
        flash('У вас нет прав на редактирование этого поста', 'danger')
        return redirect(url_for('index'))
    
    form = PostForm(obj=post)
    if form.validate_on_submit():
        post.content = form.content.data
        
        # Добавление новых файлов
        if form.files.data:
            for file in form.files.data:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
                    new_filename = f"post_{post.id}_{int(time.time())}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    file.save(file_path)
                    attachment = Attachment(filename=filename, file_url=new_filename, post_id=post.id)
                    db.session.add(attachment)
        
        db.session.commit()
        flash('Пост обновлён', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit_post.html', form=form, post=post)

# --- Удаление поста ---
@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not (current_user.is_admin or current_user.id == post.user_id):
        flash('У вас нет прав на удаление этого поста', 'danger')
        return redirect(url_for('index'))
    
    # Удаляем файлы с диска
    for att in post.attachments:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], att.file_url)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    db.session.delete(post)
    db.session.commit()
    flash('Пост удалён', 'success')
    return redirect(url_for('index'))

# --- Удаление отдельного вложения ---
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

# Команда для инициализации БД
@app.cli.command('init-db')
def init_db():
    db.create_all()
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        admin = User(username='admin', email='admin@example.com', is_admin=True, can_post=True)
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print('Админ создан: admin@example.com / admin123')
    print('База данных готова.')

if __name__ == '__main__':
    app.run(debug=True)
