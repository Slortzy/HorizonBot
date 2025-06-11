import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import datetime, timedelta
import jwt
from functools import wraps
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration
BOT_API_URL = "http://localhost:5000/api"  # URL de l'API du bot Discord
PORT = int(os.getenv('WEB_PORT', 3000))
HOST = os.getenv('WEB_HOST', '0.0.0.0')

class User(UserMixin):
    """Modèle utilisateur"""
    def __init__(self, user_id, username, password_hash=None):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash

# Utilisateur de démonstration (à remplacer par une base de données en production)
users = {
    '1': User('1', 'admin', generate_password_hash('admin'))
}

def create_app():
    """Crée et configure l'application Flask"""
    app = Flask(__name__)
    app.secret_key = os.getenv('WEB_SECRET_KEY')
    
    if not app.secret_key:
        raise ValueError("WEB_SECRET_KEY n'est pas défini dans le fichier .env")
    
    # Configuration
    app.config['TEMPLATES_AUTO_RELOAD'] = False
    
    # Initialiser Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    @login_manager.user_loader
    def load_user(user_id):
        """Charge un utilisateur à partir de son ID"""
        return users.get(user_id)
    
    def admin_required(f):
        """Décorateur pour les routes réservées aux administrateurs"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.username != 'admin':
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function

    # Routes de base
    @app.route('/')
    @login_required
    def index():
        return render_template('index.html')
    
    @app.route('/tickets')
    @login_required
    def tickets():
        return render_template('tickets.html')
    
    @app.route('/licenses')
    @login_required
    def licenses():
        return render_template('licenses.html')
        
    @app.route('/messages')
    @login_required
    def messages():
        return render_template('messages.html')
    
    @app.route('/settings')
    @login_required
    @admin_required
    def settings():
        return render_template('settings.html')
    
    # Gestion de l'authentification
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
            
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Vérification simple (à remplacer par une vraie vérification)
            if username == 'admin' and check_password_hash(users['1'].password_hash, password):
                user = users['1']
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                flash('Identifiants invalides', 'error')
        
        return render_template('login.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))
    
    # API Routes
    @app.route('/api/send_message', methods=['POST'])
    @login_required
    def send_message():
        try:
            data = request.get_json()
            channel_id = data.get('channel_id')
            message = data.get('message')
            
            if not channel_id or not message:
                return jsonify({'error': 'Missing channel_id or message'}), 400
            
            # Ici, vous pourriez envoyer le message au bot Discord
            # Par exemple, via une requête HTTP vers l'API du bot
            
            return jsonify({
                'status': 'success',
                'data': {
                    'channel_id': channel_id,
                    'message': message,
                    'timestamp': datetime.utcnow().isoformat()
                }
            }), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return app

def run_web_interface():
    """Démarre le serveur web de l'interface d'administration"""
    app = create_app()
    print(f"Démarrage du serveur web sur http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)

if __name__ == '__main__':
    run_web_interface()
