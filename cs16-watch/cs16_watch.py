#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CS 1.6 Sunucu Oyuncu Takip & E-Posta Uyarı
=========================================

Ne yapar?
- Belirttiğiniz CS 1.6/GoldSrc sunucusuna (örn: 95.173.173.212:27015) A2S
  sorguları (INFO ve PLAYER) gönderir.
- Çevrim içi oyuncu listesini çeker, yeni giren oyuncuları tespit eder.
- Yeni giriş olduğunda size e‑posta gönderir.

Bağımlılık: YOK (yalnızca Python standart kütüphanesi)

Kullanım
1) Python 3.9+ önerilir.
2) Aşağıdaki KONFIG bölümünü düzenleyin (sunucu IP/port ve e‑posta ayarları).
3) Çalıştırın:  python3 cs16_watch.py

İpucu
- CS 1.6 varsayılan query portu çoğunlukla 27015'tir; sunucu farklı bir
  port kullanıyorsa PORT değerini buna göre değiştirin.
- Gmail kullanacaksanız uygulama şifresi oluşturmanız gerekir.
- Script'i arkaplanda çalıştırmak için systemd, pm2 ya da screen/tmux
  kullanabilirsiniz.

Not
- Oyuncu tespiti isim (nickname) üzerinden yapılır. Aynı isimle tekrar
  bağlanmalar için basit bir anti-spam süzgeci vardır.
- UDP paketleri firewall tarafından engellenmemelidir.
"""

import os
import socket
import struct
import time
import smtplib
from email.message import EmailMessage
from typing import List, Tuple

# ==== KONFIG ====
SERVER_IP = os.getenv("CS16_SERVER_IP", "95.173.173.212")
SERVER_PORT = int(os.getenv("CS16_SERVER_PORT", "27015"))  # Query port
POLL_INTERVAL_SEC = int(os.getenv("CS16_POLL_INTERVAL", "20"))  # kaç saniyede bir kontrol edilsin

# E‑posta ayarları
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "example@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "APP_PASSWORD")  # Uygulama şifresi önerilir
MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER)
MAIL_TO = os.getenv("MAIL_TO", "you@example.com")  # virgülle çoklu alıcı verebilirsiniz
MAIL_SUBJECT_PREFIX = os.getenv("MAIL_SUBJECT_PREFIX", "CS1.6 Giriş Uyarı")

# Anti-spam: aynı ismin bildirimleri arası minimum saniye
MIN_NOTIFY_INTERVAL_PER_NAME = int(os.getenv("MIN_NOTIFY_INTERVAL_PER_NAME", "300"))

# ==== A2S sabitleri (GoldSrc/Source) ====
A2S_HEADER = b"\xFF\xFF\xFF\xFF"
A2S_INFO = A2S_HEADER + b"TSource Engine Query\x00"  # 0x54 + metin
A2S_PLAYER = A2S_HEADER + b"\x55"  # 0x55 + challenge
CHALLENGE_REQUEST = struct.pack("<l", -1)  # 0xFFFFFFFF


class ServerQuery:
    def __init__(self, host: str, port: int, timeout: float = 2.5):
        self.addr = (host, port)
        self.timeout = timeout

    def _sock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        return s

    def get_info(self) -> dict:
        """A2S_INFO döner (harita, oyuncu sayısı, vb.)."""
        with self._sock() as s:
            s.sendto(A2S_INFO, self.addr)
            data, _ = s.recvfrom(4096)
        # Basit doğrulama
        if not data.startswith(A2S_HEADER):
            raise RuntimeError("Geçersiz INFO yanıtı")
        # 4xFF + 0x49 (I) sonrasında alanlar (değişebilir). Burada yalnızca oyuncu sayısını okuyoruz.
        # Protokol: https://developer.valvesoftware.com/wiki/Server_queries
        # Byte 4: header (0x49)
        # Sonraki alanlar: name\0 map\0 folder\0 game\0 id(2) players(1) max_players(1) bots(1) ...
        # Basit bir parser: null-terminated stringleri sırayla oku
        i = 4
        header = data[i]
        if header != 0x49:
            # Bazı GoldSrc sunucularında 0x6D (m) olabilir; yine de deneyelim.
            pass
        i += 1

        def read_cstring(buf: bytes, start: int) -> Tuple[str, int]:
            end = buf.index(b"\x00", start)
            return buf[start:end].decode(errors="ignore"), end + 1

        server_name, i = read_cstring(data, i)
        current_map, i = read_cstring(data, i)
        folder, i = read_cstring(data, i)
        game, i = read_cstring(data, i)
        if i + 7 > len(data):
            raise RuntimeError("INFO paketi beklenenden kısa")
        app_id = struct.unpack_from("<H", data, i)[0]
        i += 2
        players = data[i]
        i += 1
        max_players = data[i]
        i += 1
        bots = data[i]
        # Diğer alanları atlıyoruz
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
        # 4xFF + 0x41 + challenge(int32)
        if data[4] != 0x41:
            raise RuntimeError("Challenge bekleniyordu (0x41)")
        challenge = struct.unpack_from("<i", data, 5)[0]
        return challenge

    def get_players(self) -> List[dict]:
        """A2S_PLAYER ile oyuncu listesini döner."""
        challenge = self._get_player_challenge()
        with self._sock() as s:
            pkt = A2S_PLAYER + struct.pack("<i", challenge)
            s.sendto(pkt, self.addr)
            data, _ = s.recvfrom(65535)
        if not data.startswith(A2S_HEADER) or data[4] != 0x44:  # 0x44 = 'D'
            raise RuntimeError("Geçersiz PLAYER yanıtı")
        i = 5
        if i >= len(data):
            return []
        num = data[i]
        i += 1
        players = []
        for _ in range(num):
            if i >= len(data):
                break
            _index = data[i]  # sıra
            i += 1
            # name\0
            end = data.index(b"\x00", i)
            name = data[i:end].decode(errors="ignore")
            i = end + 1
            # score (int32)
            if i + 4 > len(data):
                break
            score = struct.unpack_from("<i", data, i)[0]
            i += 4
            # duration (float32)
            if i + 4 > len(data):
                break
            duration = struct.unpack_from("<f", data, i)[0]
            i += 4
            players.append({"name": name, "score": score, "duration": duration})
        return players


def send_email(subject: str, body: str):
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = MAIL_TO
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)


def format_player_list(players: List[dict]) -> str:
    if not players:
        return "(şu an oyuncu yok)"
    lines = [f"- {p['name']} (score={p['score']}, time={p['duration']:.0f}s)" for p in players]
    return "\n".join(lines)


def main():
    print(f"Sunucu: {SERVER_IP}:{SERVER_PORT}")
    query = ServerQuery(SERVER_IP, SERVER_PORT)

    last_seen_names = set()  # anlık takip
    last_notify_time = {}  # name -> epoch

    while True:
        try:
            info = query.get_info()
            players = query.get_players()
        except (socket.timeout, OSError) as e:
            print(f"[WARN] Zaman aşımı / ağ hatası: {e}")
            time.sleep(POLL_INTERVAL_SEC)
            continue
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(POLL_INTERVAL_SEC)
            continue

        current_names = {p["name"] for p in players if p["name"]}
        # Yeni girenler = şu an var olup önce yok olanlar
        joined = current_names - last_seen_names

        # Bildirim gönder
        now = time.time()
        for name in sorted(joined):
            last = last_notify_time.get(name, 0)
            if now - last < MIN_NOTIFY_INTERVAL_PER_NAME:
                continue  # çok sık bildirme
            subject = f"{MAIL_SUBJECT_PREFIX}: {name} oyuna girdi"
            body = (
                f"Sunucu: {SERVER_IP}:{SERVER_PORT}\n"
                f"Sunucu adı: {info.get('name','?')}\n"
                f"Harita: {info.get('map','?')}\n"
                f"Toplam oyuncu: {info.get('players','?')}/{info.get('max_players','?')} (botlar: {info.get('bots','?')})\n\n"
                f"Şu anki liste:\n{format_player_list(players)}\n"
            )
            try:
                send_email(subject, body)
                last_notify_time[name] = now
                print(f"[MAIL] Gönderildi: {subject}")
            except Exception as e:
                print(f"[MAIL][HATA] {e}")

        # Son durum güncelle
        last_seen_names = current_names

        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Çıkılıyor…")
