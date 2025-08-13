#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import struct
import time
import requests
from typing import List, Tuple

# ==== KONFİG ====
SERVER_IP = os.getenv("CS16_SERVER_IP", "95.173.173.212")
SERVER_PORT = int(os.getenv("CS16_SERVER_PORT", "27015"))
POLL_INTERVAL_SEC = int(os.getenv("CS16_POLL_INTERVAL", "20"))

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")  # @kullaniciadi veya -1001234567890

MIN_NOTIFY_INTERVAL_PER_NAME = int(os.getenv("MIN_NOTIFY_INTERVAL_PER_NAME", "300"))

# ==== A2S sabitleri ====
A2S_HEADER = b"\xFF\xFF\xFF\xFF"
A2S_INFO = A2S_HEADER + b"TSource Engine Query\x00"
A2S_PLAYER = A2S_HEADER + b"\x55"
CHALLENGE_REQUEST = struct.pack("<l", -1)


class ServerQuery:
    def __init__(self, host: str, port: int, timeout: float = 2.5):
        self.addr = (host, port)
        self.timeout = timeout

    def _sock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        return s

    def get_info(self) -> dict:
        with self._sock() as s:
            s.sendto(A2S_INFO, self.addr)
            data, _ = s.recvfrom(4096)
        if not data.startswith(A2S_HEADER):
            raise RuntimeError("Geçersiz INFO yanıtı")

        i = 4
        header = data[i]
        i += 1

        def read_cstring(buf: bytes, start: int) -> Tuple[str, int]:
            end = buf.index(b"\x00", start)
            return buf[start:end].decode(errors="ignore"), end + 1

        server_name, i = read_cstring(data, i)
        current_map, i = read_cstring(data, i)
        folder, i = read_cstring(data, i)
        game, i = read_cstring(data, i)
        app_id = struct.unpack_from("<H", data, i)[0]
        i += 2
        players = data[i]
        i += 1
        max_players = data[i]
        i += 1
        bots = data[i]

        return {
            "name": server_name,
            "map": current_map,
            "folder": folder,
            "game": game,
            "app_id": app_id,
            "players": players,
            "max_players": max_players,
            "bots": bots,
        }

    def _get_player_challenge(self) -> int:
        with self._sock() as s:
            s.sendto(A2S_PLAYER + CHALLENGE_REQUEST, self.addr)
            data, _ = s.recvfrom(4096)
        if not data.startswith(A2S_HEADER):
            raise RuntimeError("Geçersiz challenge yanıtı")
        if data[4] != 0x41:
            raise RuntimeError("Challenge bekleniyordu (0x41)")
        challenge = struct.unpack_from("<i", data, 5)[0]
        return challenge

    def get_players(self) -> List[dict]:
        challenge = self._get_player_challenge()
        with self._sock() as s:
            pkt = A2S_PLAYER + struct.pack("<i", challenge)
            s.sendto(pkt, self.addr)
            data, _ = s.recvfrom(65535)
        if not data.startswith(A2S_HEADER) or data[4] != 0x44:
            raise RuntimeError("Geçersiz PLAYER yanıtı")
        i = 5
        num = data[i]
        i += 1
        players = []
        for _ in range(num):
            _index = data[i]
            i += 1
            end = data.index(b"\x00", i)
            name = data[i:end].decode(errors="ignore")
            i = end + 1
            score = struct.unpack_from("<i", data, i)[0]
            i += 4
            duration = struct.unpack_from("<f", data, i)[0]
            i += 4
            players.append({"name": name, "score": score, "duration": duration})
        return players


def send_telegram_message(text: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text
    }
    r = requests.post(url, data=payload)
    if r.status_code != 200:
        print(f"[TELEGRAM] Hata: {r.text}")


def format_player_list(players: List[dict]) -> str:
    if not players:
        return "(şu an oyuncu yok)"
    return "\n".join(
        f"- {p['name']} (score={p['score']}, time={p['duration']:.0f}s)"
        for p in players
    )


def main():
    print(f"Sunucu: {SERVER_IP}:{SERVER_PORT}")
    query = ServerQuery(SERVER_IP, SERVER_PORT)

    last_seen_names = set()
    last_notify_time = {}

    while True:
        try:
            info = query.get_info()
            players = query.get_players()
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(POLL_INTERVAL_SEC)
            continue

        current_names = {p["name"] for p in players if p["name"]}
        joined = current_names - last_seen_names

        now = time.time()
        for name in sorted(joined):
            last = last_notify_time.get(name, 0)
            if now - last < MIN_NOTIFY_INTERVAL_PER_NAME:
                continue
            message = (
                f"🎮 Oyuncu girdi: {name}\n"
                f"Sunucu: {info.get('name','?')}\n"
                f"Harita: {info.get('map','?')}\n"
                f"Oyuncular: {info.get('players','?')}/{info.get('max_players','?')}\n\n"
                f"Şu anki liste:\n{format_player_list(players)}"
            )
            send_telegram_message(message)
            last_notify_time[name] = now
            print(f"[TG] Mesaj gönderildi: {name}")

        last_seen_names = current_names
        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Çıkılıyor…")
