import socket
from .dns import *


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            header = DNSHeader.from_bytes(buf)
            header.qr = 1  # This is a response
            header.rcode = 4
            header.ancount = header.qdcount  # Number of answers will match the number of queries

            questions = []
            offset = 12

            for _ in range(header.qdcount):
                qname, offset = decompress_labels(buf, offset)
                qtype = int.from_bytes(buf[offset:offset + 2], byteorder="big")
                qclass = int.from_bytes(buf[offset + 2:offset + 4], byteorder="big")
                offset += 4
                questions.append(DNSQuestion(qname, qtype, qclass))

            response = header.encode()

            for question in questions:
                response += question.to_bytes()

            for question in questions:
                if question.qtype == 1 and question.qclass == 1:  # Only handle A records in IN class
                    answer = DNSAnswer(
                        name=question.to_bytes()[:-4],  # Exclude QTYPE and QCLASS
                        _type=1,  # A record
                        _class=1,  # IN class
                        ttl=60,  # TTL
                        rdlength=4,  # IPv4 address length
                        rdata=b'\x08\x08\x08\x08'  # Example IP address 8.8.8.8
                    )
                    response += answer.encode()

            udp_socket.sendto(response, source)

        except Exception as e:
            print(f"Error: {e}")
            break


def decompress_labels(buf, offset):
    labels = []
    while True:
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # Pointer
            pointer = int.from_bytes(buf[offset:offset + 2], byteorder="big") & 0x3FFF
            labels.append(decompress_labels(buf, pointer)[0])
            offset += 2
            break
        else:
            offset += 1
            labels.append(buf[offset:offset + length].decode())
            offset += length
    return ".".join(labels), offset


if __name__ == "__main__":
    main()
