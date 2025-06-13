import telebot
import requests
from flask import Flask, request

TELEGRAM_TOKEN = "7524106069:AAHTVeLJyfgnDrH1TGn_zzM1Qvx2e66ETb4"
VT_API_KEY = "c629d1ca5dc31166d066be6f3a007f473b28650311e35998c7d1743291d05256"
WEBHOOK_URL = "https://telegram-bot-hadji.onrender.com"  # remplace ce lien par l’URL Render de ton service

bot = telebot.TeleBot(TELEGRAM_TOKEN)
app = Flask(__name__)

def analyse_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
        stats = result.json()["data"]["attributes"]["stats"]
        positives = stats["malicious"] + stats["suspicious"]

        if positives > 3:
            return f"🔴 Lien dangereux détecté ({positives} rapports suspects)"
        elif positives > 0:
            return f"🟡 Lien potentiellement suspect ({positives} alertes)"
        else:
            return "✅ Ce lien semble sûr"
    return "Erreur lors de l'analyse."

@bot.message_handler(func=lambda message: message.text and message.text.startswith("http"))
def handle_message(message):
    url = message.text.strip()
    bot.send_message(message.chat.id, "🔍 Analyse en cours...")
    verdict = analyse_virustotal(url)
    bot.send_message(message.chat.id, verdict)

@app.route("/", methods=["POST"])
def webhook():
    json_str = request.get_data().decode("UTF-8")
    update = telebot.types.Update.de_json(json_str)
    bot.process_new_updates([update])
    return "!", 200

@app.route("/", methods=["GET"])
def index():
    return "Bot en ligne via Webhook", 200

# Supprimer tout ancien webhook
bot.remove_webhook()
# Définir le nouveau webhook
bot.set_webhook(url=WEBHOOK_URL)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
