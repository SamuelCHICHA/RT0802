import socket
import threading
import logging
import logging.config
import sys
import json

with open("logging_conf.json", "r") as logging_config_file:
    logging.config.dictConfig(json.load(logging_config_file))
site_logger = logging.getLogger('site')

def main(ip_address: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip_address, 53))
    site_logger.info(f"Connected to {ip_address}")
    sock.sendall(f"yikes".encode())

if __name__ == "__main__":
    ip_address = sys.argv[1]
    main(ip_address)