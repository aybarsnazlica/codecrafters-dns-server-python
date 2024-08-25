import socket

from .dns import DNSHeader, DNSAnswer


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            # Receive DNS query
            buf, source = udp_socket.recvfrom(512)

            # Extract the header and question section
            question_section = buf[12:]
            domain_name = question_section[:-4]  # The last 4 bytes are type and class

            # Create DNS header
            header = DNSHeader(
                id=1234,
                qr=1,  # Response
                opcode=0,
                aa=0,  # Not authoritative
                tc=0,  # Not truncated
                rd=0,  # Recursion not desired
                ra=0,  # Recursion not available
                rcode=0,  # No error
                qdcount=1,
                ancount=1,  # 1 answer
                nscount=0,
                arcount=0,
            )

            # Encode header
            response = header.encode()

            # Add the question section to the response
            response += question_section

            # Create and encode DNS answer
            answer = DNSAnswer(
                name=domain_name,  # Use the domain name from the query
                _type=1,  # A record
                _class=1,  # IN (Internet)
                ttl=60,  # TTL of 60 seconds
                rdlength=4,  # Length of the RDATA (IPv4 address)
                rdata=b"\x08\x08\x08\x08",  # IP address 8.8.8.8
            )
            response += answer.encode()

            # Send response back to the client
            udp_socket.sendto(response, source)

        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
