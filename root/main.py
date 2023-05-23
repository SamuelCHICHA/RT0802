import logging
import logging.config
import json
from Router import Router
from CA import CA
import threading
from OpenSSL import crypto
    
def start_router():
    router_logger.info("Router starting")
    with Router(("0.0.0.0", 1024), router_logger, routing_table) as router:
        router.serve_forever()
        
def start_ca():
    ca_logger.info("CA starting")
    with CA(("0.0.0.0", 1025), ca_logger) as ca:
        ca.serve_forever()

if __name__ == "__main__":
    # Loading the logging configuration
    with open("logging_conf.json", "r") as logging_config_file:
        logging.config.dictConfig(json.load(logging_config_file))
    # Loading the routing table
    with open("routing_table.json", "r") as routing_table_file:
        routing_table = json.load(routing_table_file)
    router_logger = logging.getLogger('router')
    ca_logger = logging.getLogger('ca')
    router_thread = threading.Thread(target=start_router, name="Thread Router")
    ca_thread = threading.Thread(target=start_ca, name="Thread CA")
    ca_thread.start()
    router_thread.start()
    ca_thread.join()
    router_thread.join()
    
    
    