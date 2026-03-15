import os
import time
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
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
import io
from PIL import Image
import base64
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
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

csrf = CSRFProtect(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    can_post = db.Column(db.Boolean, default=False)
    avatar = db.Column(
        db.String(300),
        default='https://res.cloudinary.com/dssim246k/image/upload/v1773220194/avatars/default_avatar.png'
    )
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    messages_sent = db.relationship(
        'Message',
        foreign_keys='Message.sender_id',
        back_populates='sender',
        lazy='dynamic'
    )
    messages_received = db.relationship(
        'Message',
        foreign_keys='Message.recipient_id',
        back_populates='recipient',
        lazy='dynamic'
    )

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

    sender = db.relationship(
        'User',
        foreign_keys=[sender_id],
        back_populates='messages_sent'
    )
    recipient = db.relationship(
        'User',
        foreign_keys=[recipient_id],
        back_populates='messages_received'
    )
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
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        try:
            result = db.session.execute(text("PRAGMA table_info(post)")).fetchall()
            existing_columns = {row[1] for row in result}
            if 'sticker_id' not in existing_columns:
                db.session.execute(text("ALTER TABLE post ADD COLUMN sticker_id INTEGER"))
                db.session.commit()
                print("✅ Добавлена колонка post.sticker_id в схему БД.")
            if 'likes_count' not in existing_columns:
                db.session.execute(text("ALTER TABLE post ADD COLUMN likes_count INTEGER DEFAULT 0"))
                db.session.commit()
                print("✅ Добавлена колонка post.likes_count в схему БД.")
        except Exception as e:
            db.session.rollback()
            print(f"⚠️ Не удалось обновить схему базы данных: {e}")


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

        # Обработка аватара из формы
        cropped_avatar = request.form.get('cropped_avatar')
        if cropped_avatar and cropped_avatar.startswith('data:image'):
            try:
                # Декодируем base64
                image_data = cropped_avatar.split(',')[1]
                image_binary = base64.b64decode(image_data)
                
                # Загружаем в Cloudinary
                upload_result = cloudinary.uploader.upload(
                    image_binary,
                    folder="avatars",
                    public_id=f"user_{current_user.id}",
                    overwrite=True,
                    transformation=[{'width': 300, 'height': 300, 'crop': 'fill'}]
                )
                
                # Сохраняем ссылку
                current_user.avatar = upload_result['secure_url']
                
            except Exception as e:
                flash(f'Ошибка при загрузке аватара: {str(e)}', 'danger')

        # Смена пароля
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
    """Профиль пользователя по ID"""
    user = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.date_posted.desc()).all()
    return render_template('user_profile.html', user=user, posts=posts)
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
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})
    
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    
    try:
        # Загружаем в Cloudinary
        upload_result = cloudinary.uploader.upload(
            file,
            folder="avatars",
            public_id=f"user_{current_user.id}",
            overwrite=True,
            transformation=[
                {'width': 300, 'height': 300, 'crop': 'fill'}
            ]
        )
        
        # Сохраняем прямую ссылку в базу
        current_user.avatar = upload_result['secure_url']
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'url': upload_result['secure_url']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
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

    # Удаляем все лайки этого поста
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
    # Fetch only messages where current user participates (as sender or recipient)
    messages = Message.query.filter(
        or_(
            Message.recipient_id == current_user.id,
            Message.sender_id == current_user.id,
        )
    ).order_by(Message.timestamp.desc()).all()

    received_messages = [m for m in messages if m.recipient_id == current_user.id]
    sent_messages = [m for m in messages if m.sender_id == current_user.id]

    # Mark received messages as read
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
    def avatar_url(user):
        # Максимально простой вариант
        if user is None:
            return 'https://res.cloudinary.com/dssim246k/image/upload/v1773220194/avatars/default_avatar.png'
        
        if user.avatar:
            # Просто возвращаем то, что в базе
            return user.avatar
        
        return 'https://res.cloudinary.com/dssim246k/image/upload/v1773220194/avatars/default_avatar.png'
    
    return dict(avatar_url=avatar_url, current_year=datetime.utcnow().year)
if __name__ == '__main__':
    app.run(debug=True)
