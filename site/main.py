import logging
import logging.config
import sys
import json
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from Site import Site
    

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise ValueError("Invalid number of arguments.")
    if sys.argv[1] not in ["A", "B", "C"]:
        raise ValueError("Invalid site identifier.")
    with open("logging_conf.json", "r") as logging_config_file:
        logging.config.dictConfig(json.load(logging_config_file))
    id_site = sys.argv[1]
    ip_address = sys.argv[2]
    site_logger = logging.getLogger(f"site{id_site}")
    site = Site(id_site, ip_address, site_logger)
    site.start()