import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Configuración de la aplicación
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['DATABASE'] = 'blog.db'

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'
login_manager.login_message_category = 'danger'

# Clase User para Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def get(user_id):
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user is None:
            return None
        return User(user['id'], user['username'], user['password_hash'])

# Funciones de base de datos
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    
    # Crear tablas directamente desde app.py
    db.executescript('''
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS posts;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL
        );

        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
    ''')
    
    db.commit()

@app.cli.command('init-db')
def init_db_command():
    """Inicializa la base de datos."""
    init_db()
    print('Base de datos inicializada.')

# También podemos inicializar la BD si no existe al iniciar la app
def init_app():
    if not os.path.exists(app.config['DATABASE']):
        with app.app_context():
            init_db()
            print('Base de datos creada automáticamente.')

init_app()

app.teardown_appcontext(close_db)

# User loader para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Rutas
@app.route('/')
def index():
    db = get_db()
    posts = db.execute('''
        SELECT p.id, p.title, p.content, p.created_at, u.username
        FROM posts p JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    ''').fetchall()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=('GET', 'POST'))
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Se requiere un nombre de usuario.'
        elif not password:
            error = 'Se requiere una contraseña.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
            error = f'El usuario {username} ya está registrado.'

        if error is None:
            db.execute(
                'INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
                (username, generate_password_hash(password), datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            db.commit()
            flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))

        flash(error, 'danger')

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form
        db = get_db()
        error = None
        
        user_data = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user_data is None:
            error = 'Usuario incorrecto.'
        else:
            user = User(user_data['id'], user_data['username'], user_data['password_hash'])
            if not user.check_password(password):
                error = 'Contraseña incorrecta.'
            else:
                login_user(user, remember=remember)
                flash('Has iniciado sesión correctamente.', 'success')
                
                # Redirigir a la página solicitada originalmente (si existe)
                next_page = request.args.get('next')
                if next_page:
                    return redirect(next_page)
                return redirect(url_for('dashboard'))

        flash(error, 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    posts = db.execute('''
        SELECT id, title, content, created_at
        FROM posts
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (current_user.id,)).fetchall()
    return render_template('dashboard.html', posts=posts)

@app.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        error = None

        if not title:
            error = 'Se requiere un título.'
        elif not content:
            error = 'Se requiere contenido.'

        if error is None:
            db = get_db()
            db.execute(
                'INSERT INTO posts (title, content, user_id, created_at) VALUES (?, ?, ?, ?)',
                (title, content, current_user.id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            db.commit()
            flash('Post creado exitosamente.', 'success')
            return redirect(url_for('dashboard'))

        flash(error, 'danger')

    return render_template('create_post.html')

@app.route('/<int:id>/edit', methods=('GET', 'POST'))
@login_required
def edit(id):
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (id,)).fetchone()

    if post is None:
        flash('El post no existe.', 'danger')
        return redirect(url_for('dashboard'))
    
    if post['user_id'] != current_user.id:
        flash('No tienes permiso para editar este post.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        error = None

        if not title:
            error = 'Se requiere un título.'
        elif not content:
            error = 'Se requiere contenido.'

        if error is None:
            db.execute(
                'UPDATE posts SET title = ?, content = ? WHERE id = ?',
                (title, content, id)
            )
            db.commit()
            flash('Post actualizado exitosamente.', 'success')
            return redirect(url_for('dashboard'))

        flash(error, 'danger')

    return render_template('edit_post.html', post=post)

@app.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (id,)).fetchone()

    if post is None:
        flash('El post no existe.', 'danger')
        return redirect(url_for('dashboard'))
    
    if post['user_id'] != current_user.id:
        flash('No tienes permiso para eliminar este post.', 'danger')
        return redirect(url_for('dashboard'))

    db.execute('DELETE FROM posts WHERE id = ?', (id,))
    db.commit()
    flash('Post eliminado exitosamente.', 'success')
    return redirect(url_for('dashboard'))

# Contexto para el año actual en el footer
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

if __name__ == '__main__':
    app.run(debug=True)
