import socket

from .dns import DNSHeader, DNSAnswer


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            header = DNSHeader.from_bytes(buf[:12])

            header.qr = 1  # Set QR to indicate a response
            header.aa = 0  # Not authoritative
            header.tc = 0  # Not truncated
            header.ra = 0  # Recursion not available
            header.rcode = 0 if header.opcode == 0 else 4  # No error or not implemented
            header.ancount = 1  # Assuming 1 answer for simplicity
            header.nscount = 0
            header.arcount = 0

            response = header.encode()

            question_section = buf[12:]
            response += question_section

            domain_name = question_section[:-4]  # Exclude the type and class
            answer = DNSAnswer(
                name=domain_name,  # Use the domain name from the query
                _type=1,  # A record
                _class=1,  # IN (Internet)
                ttl=60,  # TTL of 60 seconds
                rdlength=4,  # Length of the RDATA (IPv4 address)
                rdata=b'\x08\x08\x08\x08'  # IP address 8.8.8.8
            )
            response += answer.encode()
            udp_socket.sendto(response, source)

        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
