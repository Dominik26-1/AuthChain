from node import Node


def create_node_instance(name: str, ip_address: str, port: int, mac_address: str, model: str,
                         serial_number: str) -> Node:
    node = Node(name, ip_address, port, mac_address, model, serial_number)
    return node
