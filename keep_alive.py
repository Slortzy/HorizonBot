from flask import Flask, send_from_directory
from threading import Thread
import os
from dotenv import load_dotenv
import bot
import web_interface

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

# Configuration pour le serveur Flask
class WebServer:
    def __init__(self):
        self.app = app
        self.port = int(os.getenv('WEB_PORT', 8080))
        self.host = os.getenv('WEB_HOST', '0.0.0.0')
    
    def run(self):
        self.app.run(host=self.host, port=self.port)

def run_web_server():
    web_server = WebServer()
    web_server.run()

def signal_handler(sig, frame):
    """Gère les signaux d'arrêt pour un arrêt propre"""
    print("\nArrêt en cours...")
    sys.exit(0)

def run_bot_in_thread():
    """Lance le bot Discord dans un thread séparé"""
    print("Démarrage du bot Discord...")
    run_bot()

def run_web_in_thread():
    """Lance l'interface web dans un thread séparé"""
    print("Démarrage du serveur web...")
    run_web_interface()

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
        
    except Exception as e:
        print(f"Erreur critique: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
