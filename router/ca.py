import logging
import json
import socket

def main():
    with open("logging_conf.json", "r") as logging_config_file:
        logging.config.dictConfig(json.load(logging_config_file))
    ca_logger = logging.getLogger('ca')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 1025))
    sock.listen(5)
    while True:
        (sock_src, (address_src, port_src)) = sock.accept()
        

if __name__ == "__main__":
    pass