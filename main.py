from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp
import sqlite3
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import bcrypt
import secrets
import re

app = Flask(__name__)
# Генерация безопасного секретного ключа для сессий и CSRF
app.secret_key = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'static/image/avatars'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

# Инициализация менеджера авторизации
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = ''
login_manager.init_app(app)

# Форма для регистрации
class RegisterForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(message='Поле не может быть пустым'), Length(min=3, max=50, message='Имя пользователя должно содержать от 3 до 50 символов')])
    email = StringField('Email', validators=[DataRequired(message='Поле не может быть пустым'), Email(message='Введите корректный email')])
    password = PasswordField('Пароль', validators=[
        DataRequired(message='Поле не может быть пустым'),
        Length(min=8, message='Пароль должен содержать минимум 8 символов'),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&+_-])[A-Za-z\d@$!%*#?&+_-]{8,}$',
               message='Пароль должен содержать минимум 8 символов, включая буквы, цифры и специальные символы (@, $, !, %, *, #, ?, &, +, -, _)')
    ])
    submit = SubmitField('Зарегистрироваться')

# Форма для входа
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message='Поле не может быть пустым'), Email(message='Введите корректный email')])
    password = PasswordField('Пароль', validators=[DataRequired(message='Поле не может быть пустым')])
    submit = SubmitField('Войти')

# Проверка расширения файла для загрузки аватара
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Подключение к базе данных SQLite
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Класс пользователя для flask-login
class User(UserMixin):
    def __init__(self, id, username, email, avatar=None):
        self.id = id
        self.username = username
        self.email = email
        self.avatar = avatar

# Загрузка пользователя для flask-login
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        avatar = user['avatar'] if 'avatar' in user else None
        return User(id=user['id'], username=user['username'], email=user['email'], avatar=avatar)
    return None

# Инициализация базы данных
conn = get_db_connection()
cursor = conn.cursor()

# Создание таблицы пользователей
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    avatar TEXT
)
''')

# Добавление столбца avatar, если он отсутствует
cursor.execute("PRAGMA table_info(users)")
columns = [info[1] for info in cursor.fetchall()]
if 'avatar' not in columns:
    cursor.execute('ALTER TABLE users ADD COLUMN avatar TEXT')

# Создание таблицы покупок
cursor.execute('''
CREATE TABLE IF NOT EXISTS purchases (
    id INTEGER PRIMARY KEY,
    user_email TEXT NOT NULL,
    item_name TEXT NOT NULL,
    purchase_date TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1
)
''')

# Создание таблицы товаров
cursor.execute('''
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL
)
''')

# Создание таблицы корзины
cursor.execute('''
CREATE TABLE IF NOT EXISTS cart (
    id INTEGER PRIMARY KEY,
    user_email TEXT NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (product_id) REFERENCES products(id)
)
''')

# Создание таблицы избранного
cursor.execute('''
CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY,
    user_email TEXT NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (product_id) REFERENCES products(id)
)
''')

# Добавление тестовых данных для покупок
cursor.execute('SELECT COUNT(*) FROM purchases')
if cursor.fetchone()[0] == 0:
    test_purchases = [
        ('user@example.com', 'Футболка', '2025-05-10', 1),
        ('user@example.com', 'Наушники', '2025-05-09', 2),
        ('user@example.com', 'Книга', '2025-05-08', 1)
    ]
    cursor.executemany('INSERT INTO purchases (user_email, item_name, purchase_date, quantity) VALUES (?, ?, ?, ?)', test_purchases)

# Добавление тестовых данных для товаров
cursor.execute('SELECT COUNT(*) FROM products')
if cursor.fetchone()[0] == 0:
    test_products = [
        ('Футболка с принтом', 'Одежда', 29.99),
        ('Джинсы', 'Одежда', 49.99),
        ('Подушка декоративная', 'Товары для дома', 19.99),
        ('Лампа настольная', 'Товары для дома', 39.99),
        ('Конструктор', 'Детские товары', 24.99),
        ('Плюшевая игрушка', 'Детские товары', 14.99),
        ('Смартфон', 'Электроника', 299.99),
        ('Наушники беспроводные', 'Электроника', 89.99),
        ('Шахматы', 'Хобби и развлечения', 34.99),
        ('Гитара акустическая', 'Хобби и развлечения', 129.99)
    ]
    cursor.executemany('INSERT INTO products (name, category, price) VALUES (?, ?, ?)', test_products)

conn.commit()
conn.close()

# Главная страница
@app.route('/')
@app.route('/home')
def home():
    return render_template('main.html')

# Страница товаров с поиском и фильтрацией по категориям
@app.route('/products')
@app.route('/products/<category>')
def products(category=None):
    conn = get_db_connection()
    query = request.args.get('query', '').strip()
    if query:
        # Поиск нечувствительный к регистру с использованием COLLATE NOCASE
        products = conn.execute('SELECT * FROM products WHERE name LIKE ? COLLATE NOCASE',
                               (f'%{query}%',)).fetchall()
    elif category:
        products = conn.execute('SELECT * FROM products WHERE category = ?', (category,)).fetchall()
    else:
        products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    categories = ['Одежда', 'Товары для дома', 'Детские товары', 'Электроника', 'Хобби и развлечения']
    return render_template('products.html', products=products, categories=categories, selected_category=category, query=query)

# Добавление товара в корзину
@app.route('/add_to_cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    if product:
        existing = conn.execute('SELECT * FROM cart WHERE user_email = ? AND product_id = ?',
                               (current_user.email, product_id)).fetchone()
        if existing:
            conn.execute('UPDATE cart SET quantity = quantity + 1 WHERE user_email = ? AND product_id = ?',
                         (current_user.email, product_id))
        else:
            conn.execute('INSERT INTO cart (user_email, product_id, quantity) VALUES (?, ?, ?)',
                         (current_user.email, product_id, 1))
        conn.commit()
        flash('Товар добавлен в корзину!', 'success')
    conn.close()
    return redirect(request.referrer or url_for('products'))

# Удаление товара из корзины
@app.route('/remove_from_cart/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM cart WHERE user_email = ? AND product_id = ?',
                 (current_user.email, product_id))
    conn.commit()
    conn.close()
    flash('Товар удалён из корзины!', 'success')
    return redirect(request.referrer or url_for('cart'))

# Изменение количества товаров в корзине
@app.route('/adjust_cart_quantity/<int:product_id>/<action>')
@login_required
def adjust_cart_quantity(product_id, action):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM cart WHERE user_email = ? AND product_id = ?',
                       (current_user.email, product_id)).fetchone()
    if item:
        if action == 'increase':
            conn.execute('UPDATE cart SET quantity = quantity + 1 WHERE user_email = ? AND product_id = ?',
                         (current_user.email, product_id))
        elif action == 'decrease' and item['quantity'] > 1:
            conn.execute('UPDATE cart SET quantity = quantity - 1 WHERE user_email = ? AND product_id = ?',
                         (current_user.email, product_id))
        elif action == 'decrease' and item['quantity'] == 1:
            conn.execute('DELETE FROM cart WHERE user_email = ? AND product_id = ?',
                         (current_user.email, product_id))
        conn.commit()
        flash('Количество обновлено!', 'success')
    conn.close()
    return redirect(request.referrer or url_for('cart'))

# Добавление товара в избранное
@app.route('/add_to_favorites/<int:product_id>')
@login_required
def add_to_favorites(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    if product:
        existing = conn.execute('SELECT * FROM favorites WHERE user_email = ? AND product_id = ?',
                               (current_user.email, product_id)).fetchone()
        if existing:
            conn.execute('UPDATE favorites SET quantity = quantity + 1 WHERE user_email = ? AND product_id = ?',
                         (current_user.email, product_id))
        else:
            conn.execute('INSERT INTO favorites (user_email, product_id, quantity) VALUES (?, ?, ?)',
                         (current_user.email, product_id, 1))
        conn.commit()
        flash('Товар добавлен в избранное!', 'success')
    conn.close()
    return redirect(request.referrer or url_for('products'))

# Удаление товара из избранного
@app.route('/remove_from_favorites/<int:product_id>')
@login_required
def remove_from_favorites(product_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM favorites WHERE user_email = ? AND product_id = ?',
                 (current_user.email, product_id))
    conn.commit()
    conn.close()
    flash('Товар удалён из избранного!', 'success')
    return redirect(request.referrer or url_for('favorites'))

# Изменение количества товаров в избранном
@app.route('/adjust_favorites_quantity/<int:product_id>/<action>')
@login_required
def adjust_favorites_quantity(product_id, action):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM favorites WHERE user_email = ? AND product_id = ?',
                       (current_user.email, product_id)).fetchone()
    if item:
        if action == 'increase':
            conn.execute('UPDATE favorites SET quantity = quantity + 1 WHERE user_email = ? AND product_id = ?',
                         (current_user.email, product_id))
        elif action == 'decrease' and item['quantity'] > 1:
            conn.execute('UPDATE favorites SET quantity = quantity - 1 WHERE user_email = ? AND product_id = ?',
                         (current_user.email, product_id))
        elif action == 'decrease' and item['quantity'] == 1:
            conn.execute('DELETE FROM favorites WHERE user_email = ? AND product_id = ?',
                         (current_user.email, product_id))
        conn.commit()
        flash('Количество обновлено!', 'success')
    conn.close()
    return redirect(request.referrer or url_for('favorites'))

# Страница корзины
@app.route('/cart')
@login_required
def cart():
    conn = get_db_connection()
    cart_items = conn.execute('SELECT p.*, c.quantity FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_email = ?',
                             (current_user.email,)).fetchall()
    conn.close()
    return render_template('cart.html', cart_items=cart_items)

# Оформление заказа
@app.route('/checkout')
@login_required
def checkout():
    conn = get_db_connection()
    cart_items = conn.execute('SELECT p.*, c.quantity FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_email = ?',
                             (current_user.email,)).fetchall()
    if cart_items:
        purchase_date = datetime.now().strftime('%Y-%m-%d')
        for item in cart_items:
            conn.execute('INSERT INTO purchases (user_email, item_name, purchase_date, quantity) VALUES (?, ?, ?, ?)',
                         (current_user.email, item['name'], purchase_date, item['quantity']))
        conn.execute('DELETE FROM cart WHERE user_email = ?', (current_user.email,))
        conn.commit()
        flash('Заказ успешно оформлен!', 'success')
    else:
        flash('Корзина пуста.', 'error')
    conn.close()
    return redirect(url_for('profile'))

# Страница избранного
@app.route('/favorites')
@login_required
def favorites():
    conn = get_db_connection()
    favorite_items = conn.execute('SELECT p.*, f.quantity FROM favorites f JOIN products p ON f.product_id = p.id WHERE f.user_email = ?',
                                 (current_user.email,)).fetchall()
    conn.close()
    return render_template('favorites.html', favorite_items=favorite_items)

# Удаление товара (только для админа)
@app.route('/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    if current_user.username != 'admin':
        flash('Только администратор может удалять товары.', 'error')
        return redirect(request.referrer or url_for('products'))
    conn = get_db_connection()
    conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.execute('DELETE FROM cart WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM favorites WHERE product_id = ?', (product_id,))
    conn.commit()
    conn.close()
    flash('Товар успешно удалён!', 'success')
    return redirect(request.referrer or url_for('products'))

# Страница профиля
@app.route('/profile')
@login_required
def profile():
    user_email = current_user.email
    conn = get_db_connection()
    user = conn.execute('SELECT username, avatar FROM users WHERE email = ?', (user_email,)).fetchone()
    cart_items = conn.execute('SELECT p.*, c.quantity FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_email = ?',
                             (user_email,)).fetchall()
    purchases = conn.execute('SELECT item_name, purchase_date, quantity FROM purchases WHERE user_email = ?',
                            (user_email,)).fetchall()
    conn.close()
    if not user:
        flash('Пользователь не найден.', 'error')
        return redirect(url_for('login'))
    avatar = user['avatar'] if user['avatar'] else None
    return render_template('profile.html', username=user['username'], cart_items=cart_items, user_email=user_email, avatar=avatar, purchases=purchases)

# Загрузка аватара
@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('Файл не выбран.', 'error')
        return redirect(url_for('profile'))
    file = request.files['avatar']
    if file.filename == '':
        flash('Файл не выбран.', 'error')
        return redirect(url_for('profile'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        conn = get_db_connection()
        conn.execute('UPDATE users SET avatar = ? WHERE email = ?', (filename, current_user.email))
        conn.commit()
        conn.close()
        flash('Аватар успешно обновлён!', 'success')
    else:
        flash('Недопустимый формат файла. Используйте PNG, JPG или JPEG.', 'error')
    return redirect(url_for('profile'))

# Обновление имени пользователя
@app.route('/update_username', methods=['POST'])
@login_required
def update_username():
    new_username = request.form['username']
    if not new_username:
        flash('Имя пользователя не может быть пустым.', 'error')
        return redirect(url_for('profile'))
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET username = ? WHERE email = ?', (new_username, current_user.email))
        conn.commit()
        flash('Имя пользователя успешно обновлено!', 'success')
    except sqlite3.IntegrityError:
        flash('Это имя пользователя уже занято.', 'error')
    conn.close()
    return redirect(url_for('profile'))

# Добавление нового товара
@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        try:
            price = float(request.form['price'])
        except ValueError:
            flash('Цена должна быть числом.', 'error')
            return redirect(url_for('add_product'))
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO products (name, category, price) VALUES (?, ?, ?)',
                         (name, category, price))
            conn.commit()
            flash('Товар успешно добавлен!', 'success')
            return redirect(url_for('profile'))
        except sqlite3.Error as e:
            flash(f'Ошибка при добавлении товара: {str(e)}', 'error')
        finally:
            conn.close()
    categories = ['Одежда', 'Товары для дома', 'Детские товары', 'Электроника', 'Хобби и развлечения']
    return render_template('add_product.html', categories=categories)

# Страница регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, hashed_password))
            conn.commit()
            flash('Регистрация прошла успешно! Пожалуйста, войдите.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Имя пользователя или email уже заняты.', 'error')
        finally:
            conn.close()
    return render_template('register.html', form=form)

# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            avatar = user['avatar'] if 'avatar' in user else None
            user_obj = User(id=user['id'], username=user['username'], email=user['email'], avatar=avatar)
            login_user(user_obj)
            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Неверный email или пароль.', 'error')
    return render_template('login.html', form=form)

# Выход из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)