import socket
import threading
import logging
import logging.config
import json



def routing(sock_src: socket.socket, ip_address_src: str, ip_address_dest: str):
    # router_logger.debug(f"src: {ip_address_src}, dest: {ip_address_dest}")
    msg = sock_src.recv(2048).decode()
    if msg != "":
        sock_src.close()
        router_logger.info(f"Receiving from {ip_address_src}: {msg}")
        sock_dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_dest.connect((ip_address_dest, 1024))
        router_logger.info(f"Connecting to {ip_address_dest}")
        sock_dest.sendall(msg.encode())
        router_logger.info(f"Sending to {ip_address_dest}: {msg}")
    

def main():
    router_logger.info("Router starting")
    sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # En écoute sur le couple adresse ip, port
    sock_server.bind(("0.0.0.0", 1024))
    router_logger.info("Router listening on 0.0.0.0 on port 53.")
    # Paramètre de listen: Nombre de connexions non acceptés autorisé à être en attente
    sock_server.listen(5)
    while True:
        (sock_src, (address_src, port_src)) = sock_server.accept()
        router_logger.info(f"Accepting new connection from {address_src}:{port_src}")
        client_src = next(filter(lambda client: client['ip'] == address_src, accepted_clients), None)
        if client_src is not None:
            # router_logger.debug(f"{client_src['ip']} is authorized")
            client_dest = next(filter(lambda client: client['ip'] != address_src, accepted_clients), None)
            if client_dest is not None:
                # router_logger.debug("Routing")
                thread = threading.Thread(target=routing, args=[sock_src, client_src['ip'], client_dest['ip']])
                thread.start()
            else:
                router_logger.error(f"Could not find the other client")
        else:
            router_logger.warning(f"Unauthorized client: {address_src}")


if __name__ == "__main__":
    with open("logging_conf.json", "r") as logging_config_file:
        logging.config.dictConfig(json.load(logging_config_file))

    router_logger = logging.getLogger('router')

    # interfaces = [
    #     {
    #         "network": "A",
    #         "ip": "192.168.1.2"
    #     },
    #     {
    #         "network": "B",
    #         "ip": "192.168.2.2"
    #     }
    # ]

    accepted_clients = [
        {
            "network": "A",
            "ip": "192.168.1.3"
        },
        {
            "network": "B",
            "ip": "192.168.2.3"
        }
    ]
    main()
else:
    raise RuntimeError("Not the target")