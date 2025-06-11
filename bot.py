import os
import discord
import random
import string
import asyncio
from discord.ext import commands
from flask import Flask, jsonify, request
import threading
import json
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from typing import Dict, List, Optional

# Charger les variables d'environnement
load_dotenv()

# Configuration
TOKEN = os.getenv('DISCORD_BOT_TOKEN')
SECRET_KEY = os.getenv('SECRET_KEY')
API_AUTH_TOKEN = os.getenv('API_AUTH_TOKEN')

# Vérifier que le token est bien chargé
if not TOKEN:
    raise ValueError("Aucun token Discord trouvé. Vérifiez votre fichier .env")

# Initialisation de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app)

# Initialisation du bot Discord
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Stockage en mémoire (à remplacer par une base de données en production)
users = {
    'admin': {
        'password': generate_password_hash('admin'),
        'role': 'admin',
        'id': 1
    }
}

# Stockage des clés générées (à remplacer par une base de données en production)
license_keys: Dict[str, dict] = {}

# Stockage des tickets et messages
tickets = {}
ticket_messages = {}

def create_ticket(user_id: int, subject: str, description: str) -> dict:
    """Crée un nouveau ticket"""
    ticket_id = len(tickets) + 1
    ticket = {
        'id': ticket_id,
        'user_id': user_id,
        'subject': subject,
        'description': description,
        'status': 'open',  # open, pending, closed
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat()
    }
    tickets[ticket_id] = ticket
    ticket_messages[ticket_id] = []
    return ticket

def add_message_to_ticket(ticket_id: int, user_id: int, content: str) -> dict:
    """Ajoute un message à un ticket"""
    if ticket_id not in tickets:
        raise ValueError("Ticket non trouvé")
    
    message = {
        'id': len(ticket_messages[ticket_id]) + 1,
        'ticket_id': ticket_id,
        'user_id': user_id,
        'content': content,
        'created_at': datetime.utcnow().isoformat()
    }
    
    ticket_messages[ticket_id].append(message)
    tickets[ticket_id]['updated_at'] = datetime.utcnow().isoformat()
    return message

def get_ticket(ticket_id: int) -> Optional[dict]:
    """Récupère un ticket par son ID"""
    return tickets.get(ticket_id)

def get_ticket_messages(ticket_id: int) -> List[dict]:
    """Récupère les messages d'un ticket"""
    return ticket_messages.get(ticket_id, [])

def get_user_tickets(user_id: int) -> List[dict]:
    """Récupère tous les tickets d'un utilisateur"""
    return [t for t in tickets.values() if t['user_id'] == user_id]

def update_ticket_status(ticket_id: int, status: str) -> Optional[dict]:
    """Met à jour le statut d'un ticket"""
    if ticket_id not in tickets:
        return None
    
    tickets[ticket_id]['status'] = status
    tickets[ticket_id]['updated_at'] = datetime.utcnow().isoformat()
    return tickets[ticket_id]

# Configuration des produits (peut être chargé depuis une base de données)
products = {
    'premium': {
        'name': 'Abonnement Premium',
        'description': 'Accès premium à toutes les fonctionnalités',
        'price': 9.99,
        'duration_days': 30
    },
    'vip': {
        'name': 'Abonnement VIP',
        'description': 'Accès VIP avec avantages exclusifs',
        'price': 19.99,
        'duration_days': 30
    }
}

def generate_license_key(product_id: str, user_id: Optional[int] = None, duration_days: Optional[int] = None) -> dict:
    """Génère une nouvelle clé de licence"""
    if product_id not in products:
        raise ValueError("Produit non valide")
    
    # Générer une clé aléatoire
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    
    # Définir la durée
    duration = duration_days or products[product_id]['duration_days']
    expires_at = datetime.utcnow() + timedelta(days=duration)
    
    # Créer l'entrée de la clé
    license_key = {
        'key': key,
        'product_id': product_id,
        'user_id': user_id,
        'created_at': datetime.utcnow().isoformat(),
        'expires_at': expires_at.isoformat(),
        'is_used': False,
        'used_at': None,
        'used_by': None
    }
    
    # Stocker la clé
    license_keys[key] = license_key
    return license_key

def validate_license_key(key: str, user_id: Optional[int] = None) -> dict:
    """Valide une clé de licence"""
    license_data = license_keys.get(key)
    if not license_data:
        return {'valid': False, 'message': 'Clé de licence invalide'}
    
    if license_data['is_used']:
        return {'valid': False, 'message': 'Clé déjà utilisée'}
    
    if datetime.fromisoformat(license_data['expires_at']) < datetime.utcnow():
        return {'valid': False, 'message': 'Clé expirée'}
    
    return {'valid': True, 'license': license_data}

# Middleware d'authentification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data['username']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# Routes API
@app.route('/api/login', methods=['POST'])
def login():
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Authentification requise'}), 401
    
    user = users.get(auth.username)
    if not user or not check_password_hash(user['password'], auth.password):
        return jsonify({'message': 'Identifiants invalides'}), 401
    
    token = jwt.encode(
        {'user_id': user['id'], 'username': auth.username, 'exp': datetime.utcnow() + timedelta(hours=1)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    
    return jsonify({'token': token, 'user_id': user['id'], 'username': auth.username})

@app.route('/api/keys/generate', methods=['POST'])
@token_required
def generate_key(current_user):
    data = request.json
    product_id = data.get('product_id')
    duration_days = data.get('duration_days')
    
    if not product_id or product_id not in products:
        return jsonify({'error': 'Produit invalide'}), 400
    
    try:
        license_key = generate_license_key(product_id, duration_days=duration_days)
        return jsonify({
            'status': 'success',
            'key': license_key['key'],
            'expires_at': license_key['expires_at'],
            'product': products[product_id]['name']
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/validate', methods=['POST'])
@token_required
def validate_key(current_user):
    data = request.json
    key = data.get('key')
    user_id = data.get('user_id')
    
    if not key:
        return jsonify({'error': 'Clé manquante'}), 400
    
    try:
        result = validate_license_key(key, user_id)
        if result['valid']:
            # Marquer la clé comme utilisée
            license_data = license_keys[key]
            license_data['is_used'] = True
            license_data['used_at'] = datetime.utcnow().isoformat()
            license_data['used_by'] = user_id
            
            return jsonify({
                'status': 'success',
                'valid': True,
                'product': products[license_data['product_id']]['name'],
                'expires_at': license_data['expires_at']
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'valid': False,
                'message': result['message']
            }), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/list', methods=['GET'])
@token_required
def list_keys(current_user):
    try:
        # Ne renvoyer que les informations non sensibles
        keys_list = []
        for key, data in license_keys.items():
            keys_list.append({
                'key': key,
                'product': products[data['product_id']]['name'],
                'created_at': data['created_at'],
                'expires_at': data['expires_at'],
                'is_used': data['is_used'],
                'used_by': data['used_by']
            })
        
        return jsonify({'status': 'success', 'keys': keys_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Routes API pour les tickets
@app.route('/api/tickets', methods=['GET'])
@token_required
def get_tickets(current_user):
    """Récupère tous les tickets de l'utilisateur connecté"""
    try:
        user_tickets = get_user_tickets(current_user['user_id'])
        return jsonify({'tickets': user_tickets})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tickets', methods=['POST'])
@token_required
def create_new_ticket(current_user):
    """Crée un nouveau ticket"""
    try:
        data = request.get_json()
        if not data or not data.get('subject') or not data.get('description'):
            return jsonify({'error': 'Le sujet et la description sont requis'}), 400
        
        ticket = create_ticket(
            user_id=current_user['user_id'],
            subject=data['subject'],
            description=data['description']
        )
        
        # Ajouter un message initial
        add_message_to_ticket(
            ticket_id=ticket['id'],
            user_id=current_user['user_id'],
            content=f"Ticket créé: {data['description']}"
        )
        
        return jsonify(ticket), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
@token_required
def get_single_ticket(current_user, ticket_id):
    """Récupère un ticket spécifique"""
    try:
        ticket = get_ticket(ticket_id)
        if not ticket:
            return jsonify({'error': 'Ticket non trouvé'}), 404
            
        if ticket['user_id'] != current_user['user_id'] and current_user['username'] != 'admin':
            return jsonify({'error': 'Non autorisé'}), 403
            
        messages = get_ticket_messages(ticket_id)
        return jsonify({'ticket': ticket, 'messages': messages})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tickets/<int:ticket_id>/messages', methods=['POST'])
@token_required
def add_ticket_message(current_user, ticket_id):
    """Ajoute un message à un ticket"""
    try:
        data = request.get_json()
        if not data or not data.get('content'):
            return jsonify({'error': 'Le contenu du message est requis'}), 400
            
        ticket = get_ticket(ticket_id)
        if not ticket:
            return jsonify({'error': 'Ticket non trouvé'}), 404
            
        if ticket['user_id'] != current_user['user_id'] and current_user['username'] != 'admin':
            return jsonify({'error': 'Non autorisé'}), 403
            
        message = add_message_to_ticket(
            ticket_id=ticket_id,
            user_id=current_user['user_id'],
            content=data['content']
        )
        
        # Mettre à jour le statut du ticket
        if ticket['status'] == 'closed':
            update_ticket_status(ticket_id, 'pending')
            
        return jsonify(message), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tickets/<int:ticket_id>/status', methods=['PUT'])
@token_required
def update_ticket(current_user, ticket_id):
    """Met à jour le statut d'un ticket"""
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'error': 'Le statut est requis'}), 400
            
        ticket = get_ticket(ticket_id)
        if not ticket:
            return jsonify({'error': 'Ticket non trouvé'}), 404
            
        if ticket['user_id'] != current_user['user_id'] and current_user['username'] != 'admin':
            return jsonify({'error': 'Non autorisé'}), 403
            
        updated_ticket = update_ticket_status(ticket_id, data['status'])
        
        # Ajouter un message système
        status_messages = {
            'open': 'a rouvert le ticket',
            'pending': 'a marqué le ticket comme en attente',
            'closed': 'a fermé le ticket'
        }
        
        add_message_to_ticket(
            ticket_id=ticket_id,
            user_id=current_user['user_id'],
            content=f"{current_user['username']} {status_messages.get(data['status'], 'a mis à jour le statut')}"
        )
        
        return jsonify(updated_ticket)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Commandes Discord pour la gestion des clés
@bot.command(name='genkey')
async def generate_key_cmd(ctx, product_id: str, duration_days: int = None):
    """Génère une nouvelle clé de licence"""
    if product_id not in products:
        await ctx.send(f"Produit inconnu. Produits disponibles: {', '.join(products.keys())}")
        return
    
    try:
        license_key = generate_license_key(product_id, ctx.author.id, duration_days)
        await ctx.author.send(
            f"Clé générée pour {products[product_id]['name']}:\n"
            f"`{license_key['key']}`\n"
            f"Expire le: {license_key['expires_at']}"
        )
        await ctx.message.add_reaction('✅')
    except Exception as e:
        await ctx.send(f"Erreur: {str(e)}")

@bot.command(name='redeem')
async def redeem_key(ctx, key: str):
    """Utilise une clé de licence"""
    try:
        result = validate_license_key(key, ctx.author.id)
        if result['valid']:
            license_data = license_keys[key]
            license_data['is_used'] = True
            license_data['used_at'] = datetime.utcnow().isoformat()
            license_data['used_by'] = ctx.author.id
            
            # Ici, vous pourriez ajouter le rôle à l'utilisateur
            # role = discord.utils.get(ctx.guild.roles, name=license_data['product_id'].upper())
            # await ctx.author.add_roles(role)
            
            await ctx.send(
                f"✅ Clé valide ! Vous avez maintenant accès à {products[license_data['product_id']]['name']} "
                f"jusqu'au {license_data['expires_at']}"
            )
        else:
            await ctx.send(f"❌ {result['message']}")
    except Exception as e:
        await ctx.send(f"Erreur: {str(e)}")

# Commandes du bot
@bot.event
async def on_ready():
    print(f'Bot connecté en tant que {bot.user.name}')

@bot.command(name='ping')
async def ping(ctx):
    await ctx.send('Pong!')

def run_flask():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

def run_bot():
    """Fonction pour démarrer le bot Discord"""
    try:
        # Démarrer Flask dans un thread séparé
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
        
        # Démarrer le bot Discord
        print("Démarrage du bot Discord...")
        bot.run(TOKEN)
    except Exception as e:
        print(f"Erreur lors du démarrage du bot: {e}")
        raise

if __name__ == '__main__':
    run_bot()
