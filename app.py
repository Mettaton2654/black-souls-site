import os
import time
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional
from datetime import datetime
from flask_wtf.file import FileField, FileAllowed, MultipleFileField
from wtforms import ValidationError
from werkzeug.utils import secure_filename
import io
from PIL import Image
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-dev-key-change-me')
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    can_post = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200), default='default_avatar.png')
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender_ref', lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient_ref', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attachments = db.relationship('Attachment', backref='post', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    sticker_id = db.Column(db.Integer, db.ForeignKey('sticker.id'), nullable=True)
    likes_count = db.Column(db.Integer, default=0)

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    file_url = db.Column(db.String(300), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)

    user = db.relationship('User', backref=db.backref('likes', lazy=True))
    post = db.relationship('Post', backref=db.backref('likes', lazy=True))
    
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='sent_messages')
class Sticker(db.Model):
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
    print("✅ Таблицы созданы или уже существуют.")
    if not User.query.filter_by(email='xanturi@mail.ru').first():
        admin = User(
            username='admin',
            email='xanturi@mail.ru',
            is_admin=True,
            can_post=True
        )
        admin.set_password('OBURTY3129')
        db.session.add(admin)
        db.session.commit()
        print("✅ Администратор создан: xanturi@mail.ru")
    else:
        print("✅ Администратор уже существует.")

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
    recipient = SelectField('Получатель', coerce=int, validators=[DataRequired()])
    content = TextAreaField('Сообщение', validators=[DataRequired(), Length(min=1, max=1000)])
    submit = SubmitField('Отправить')

    def __init__(self, *args, **kwargs):
        super(MessageForm, self).__init__(*args, **kwargs)
        # Заполняем список получателей (все пользователи кроме текущего)
        self.recipient.choices = [(u.id, u.username) for u in User.query.filter(User.id != current_user.id).all()]

# ---------- МАРШРУТЫ ----------
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
        if form.username.data != current_user.username:
            current_user.username = form.username.data

        if form.avatar.data and form.avatar.data.filename:
            file = form.avatar.data
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            new_filename = f"avatar_{current_user.id}.{ext}" if ext else f"avatar_{current_user.id}.jpg"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            file.save(file_path)
            current_user.avatar = new_filename

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
        return redirect(url_for('index', _anchor=f'post-{post_id}'))

    comment = Comment(content=content, author=current_user, post=post)
    db.session.add(comment)
    db.session.commit()
    flash('Комментарий добавлен', 'success')
    return redirect(url_for('index', _anchor=f'post-{post_id}'))
@app.route('/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'No file'})
    
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    if file:
        filename = secure_filename(file.filename)
        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'png'
        new_filename = f"avatar_{current_user.id}.{ext}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        file.save(file_path)
        
        current_user.avatar = new_filename
        db.session.commit()
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Upload failed'})

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
                    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
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

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not (current_user.is_admin or current_user.id == post.user_id):
        flash('У вас нет прав на удаление этого поста', 'danger')
        return redirect(url_for('index'))

    for att in post.attachments:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], att.file_url)
        if os.path.exists(file_path):
            os.remove(file_path)

    db.session.delete(post)
    db.session.commit()
    flash('Пост удалён', 'success')
    return redirect(url_for('index'))

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

@app.route('/messages')
@login_required
def messages():
    # Получаем все сообщения для текущего пользователя
    received_messages = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.timestamp.desc()).all()
    sent_messages = Message.query.filter_by(sender_id=current_user.id).order_by(Message.timestamp.desc()).all()
    
    # Отмечаем полученные сообщения как прочитанные
    for msg in received_messages:
        if not msg.is_read:
            msg.is_read = True
    db.session.commit()
    
    return render_template('messages.html', received_messages=received_messages, sent_messages=sent_messages)

@app.route('/messages/send', methods=['GET', 'POST'])
@login_required
def send_message():
    form = MessageForm()
    if form.validate_on_submit():
        message = Message(
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
    message = Message.query.get_or_404(message_id)
    if message.sender_id != current_user.id and message.recipient_id != current_user.id:
        flash('У вас нет прав на удаление этого сообщения', 'danger')
        return redirect(url_for('messages'))
    
    db.session.delete(message)
    db.session.commit()
    flash('Сообщение удалено', 'success')
    return redirect(url_for('messages'))
@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        posts = Post.query.filter(Post.content.contains(query)).order_by(Post.date_posted.desc()).all()
    else:
        posts = []
    return render_template('search_results.html', posts=posts, query=query)
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
    return jsonify({'liked': liked, 'count': len(post.likes)})
@app.context_processor
def utility_processor():
    def avatar_url(user, size='medium'):
        base_url = url_for('static', filename='uploads/' + user.avatar)
        cache_buster = int(datetime.utcnow().timestamp())
        return f"{base_url}?v={cache_buster}"
    return dict(avatar_url=avatar_url)
if __name__ == '__main__':
    app.run(debug=True)
