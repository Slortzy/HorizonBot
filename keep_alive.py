from flask import Flask, send_from_directory
from threading import Thread
import os
import signal
import sys
import threading
import time
from dotenv import load_dotenv
from bot import run_bot
from web_interface import run_web_interface

# Charger les variables d'environnement
load_dotenv()

app = Flask(__name__)

# Route pour la page d'accueil
@app.route('/')
def home():
    return "ArkeonProject Bot is running!"

# Servir les fichiers statiques
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

def signal_handler(sig, frame):
    """Gère les signaux d'arrêt pour un arrêt propre"""
    print("\nArrêt en cours...")
    sys.exit(0)

def run_bot_in_thread():
    """Lance le bot Discord dans un thread séparé"""
    print("Démarrage du bot Discord...")
    try:
        from bot import run_bot
        run_bot()
    except Exception as e:
        print(f"Erreur lors du démarrage du bot: {e}")
        sys.exit(1)

def run_web_in_thread():
    """Lance l'interface web dans un thread séparé"""
    print("Démarrage du serveur web...")
    try:
        from web_interface import run_web_interface
        run_web_interface()
    except Exception as e:
        print(f"Erreur lors du démarrage du serveur web: {e}")
        sys.exit(1)

def main():
    # Configuration des gestionnaires de signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("=" * 50)
    print("Démarrage du système de gestion du bot Discord")
    print("=" * 50)
    
    try:
        # Démarrer le bot Discord dans un thread séparé
        bot_thread = threading.Thread(target=run_bot_in_thread, daemon=True)
        bot_thread.start()
        
        # Démarrer l'interface web dans le thread principal
        run_web_in_thread()
        
    except KeyboardInterrupt:
        print("\nArrêt demandé par l'utilisateur...")
    except Exception as e:
        print(f"Erreur critique: {e}")
    finally:
        print("Arrêt du système...")
        sys.exit(0)

if __name__ == "__main__":
    main()
