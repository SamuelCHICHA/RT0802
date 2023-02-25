import socket
import threading
import logging
import logging.config
import sys
import json
from TCPServer import TCPServer
    
def start_tcp_server(id_site: str, logger: logging.Logger):
    with TCPServer(("0.0.0.0", 1024), logger) as server:
        server.serve_forever()

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
    site_logger.info("Starting server")
    threading.Thread(target=start_tcp_server, args=(id_site, site_logger)).start()
    if id_site == "A":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip_address, 1024))
            sock.sendall("B: Salut, je m'appelle B".encode())

    