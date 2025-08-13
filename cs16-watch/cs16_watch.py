import os
import time
import requests
from telegram import Bot

# Ortam değişkenlerini oku
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
SERVER_IP = os.getenv("SERVER_IP")  # Ör: "127.0.0.1:27015"
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", 60))  # saniye

bot = Bot(token=TELEGRAM_TOKEN)

def get_server_status(ip):
    try:
        url = f"http://api.steampowered.com/IGameServersService/GetServerList/v1/?filter=addr\\{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()
        if data.get("response", {}).get("servers"):
            return True
    except Exception as e:
        print(f"Hata: {e}")
    return False

last_status = None

while True:
    status = get_server_status(SERVER_IP)
    if status != last_status:
        if status:
            bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=f"✅ Sunucu {SERVER_IP} aktif!")
        else:
            bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=f"❌ Sunucu {SERVER_IP} kapalı!")
        last_status = status
    time.sleep(CHECK_INTERVAL)
