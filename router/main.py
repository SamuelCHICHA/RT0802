import socket
import threading
import logging
import logging.config
import json

with open("logging_conf.json", "r") as logging_config_file:
    logging.config.dictConfig(json.load(logging_config_file))

router_logger = logging.getLogger('router')
ca_logger = logging.getLogger('ca')

interfaces = [
    {
        "network": "A",
        "ip": "192.168.1.2"
    },
    {
        "network": "B",
        "ip": "192.168.2.2"
    }
]

def routing(interface_ip_address: str):
    router_logger.debug(f"Inside thread {threading.current_thread().name}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # En écoute sur le couple adresse ip, port
    sock.bind((interface_ip_address, 53))
    router_logger.info(f"Listening on {interface_ip_address} port {53}")
    # Paramètre de listen: Nombre de connexions non acceptés autorisé à être en attente
    sock.listen(5)
    while True:
        (client_sock, address) = sock.accept()
        router_logger.info(f"Connection with {address} started")
        received = client_sock.recv(2048).decode()
        router_logger.info(f"Received from {address}: {received}")
        

def main():
    router_logger.info("Router starting")
    ca_logger.info("Certificate authority Starting")
    threads = []
    for interface in interfaces:
        router_logger.debug(f"interface ip {interface['ip']}")
        thread = threading.Thread(target=routing, args=[interface['ip']], name=f"thread-{interface['network']}")
        threads.append(thread)
        thread.start()
        

if __name__ == "__main__":
    main()