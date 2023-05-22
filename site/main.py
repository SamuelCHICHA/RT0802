import logging
import logging.config
import sys
import json
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from Site import Site
import socket
import threading
    

if len(sys.argv) != 3:
    raise ValueError("Invalid number of arguments.")
if sys.argv[1] not in ["A", "B", "C"]:
    raise ValueError("Invalid site identifier.")
with open("logging_conf.json", "r") as logging_config_file:
    logging.config.dictConfig(json.load(logging_config_file))
id_site = sys.argv[1]
ip_address = sys.argv[2]
site_logger = logging.getLogger(f"site{id_site}")
with Site(("0.0.0.0", 1024), id_site, ip_address, site_logger) as site:
    thread = threading.Thread(target=lambda: site.serve_forever())
    thread.start()
    if site.id == "A":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((site.root_ip, 1024))
            s.sendall(f"B:[{1}]".encode())
    # elif site.id == "B":
    #     # Code for B only
    #     pass
    # else:
    #     # Code for C only
    #     pass
    thread.join()