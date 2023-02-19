import socket
import threading
import logging
import logging.config
import sys
import json

def listen(ip_address: str):
    sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # site_logger.debug(f"IP: {ip_address}")
    sock_server.bind(("0.0.0.0", 53))
    site_logger.info("Listening 0.0.0.0 on port 53")
    sock_server.listen(5)
    while True:
        (sock_src, address_src) = sock_server.accept()
        site_logger.info(f"Accepting new connection from {address_src[0]}")
        msg = sock_src.recv(2048).decode()
        site_logger.info(f"Received from {address_src[0]}: {msg}")

def main(id_site: str, ip_address: str):
    site_logger.info(f"Site {id_site} started")
    thread = threading.Thread(target=listen, args=[ip_address])
    thread.start()
    if id_site == "A":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip_address, 53))
        sock.sendall("yikes".encode())
    

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise ValueError("Invalid number of arguments.")
    if sys.argv[1] not in ["A", "B"]:
        raise ValueError("Invalid site identifier.")
    with open("logging_conf.json", "r") as logging_config_file:
        logging.config.dictConfig(json.load(logging_config_file))
    id_site = sys.argv[1]
    ip_address = sys.argv[2]
    site_logger = logging.getLogger(f"site{id_site}")
    main(id_site, ip_address)
else:
    raise RuntimeError("Not the target")