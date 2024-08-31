import socket


def forward_query(query: bytes, resolver_address: tuple) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver_socket:
        resolver_socket.sendto(query, resolver_address)
        response, _ = resolver_socket.recvfrom(512)
    return response
