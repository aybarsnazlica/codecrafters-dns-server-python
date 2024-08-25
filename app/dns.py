from dataclasses import dataclass


@dataclass
class DNSHeader:
    id: int  # packet identifier (16 bits)
    qr: int  # query/response indicator (1 bit)
    opcode: int  # operation code (4 bits)
    aa: int  # authoritative answer (1 bit)
    tc: int  # truncation (1 bit)
    rd: int  # recursion desired (1 bit)
    ra: int  # recursion available (1 bit)
    rcode: int  # response code (4 bits)
    qdcount: int  # question count (16 bits)
    ancount: int  # answer record count (16 bits)
    nscount: int  # authority record count (16 bits)
    arcount: int  # additional record count (16 bits)

    def encode(self) -> bytes:
        # First byte (qr, opcode, aa, tc, rd)
        byte1 = (
                (self.qr << 7)
                | (self.opcode << 3)
                | (self.aa << 2)
                | (self.tc << 1)
                | self.rd
        )

        # Second byte (ra, rz, rcode)
        byte2 = (self.ra << 7) | self.rcode

        # Convert everything to bytes
        return (
                self.id.to_bytes(2, "big")  # ID is 16 bits
                + byte1.to_bytes(1, "big")  # 1 byte for qr, opcode, aa, tc, rd
                + byte2.to_bytes(1, "big")  # 1 byte for ra, rz, rcode
                + self.qdcount.to_bytes(2, "big")
                + self.ancount.to_bytes(2, "big")
                + self.nscount.to_bytes(2, "big")
                + self.arcount.to_bytes(2, "big")
        )


@dataclass
class DNSAnswer:
    name: bytes  # Encoded domain name as label sequence
    _type: int  # Type of the record (e.g., 1 for A record)
    _class: int  # Class of the record (e.g., 1 for IN)
    ttl: int  # Time-To-Live
    rdlength: int  # Length of the RDATA field
    rdata: bytes  # RDATA, e.g., the IP address for A record

    def encode(self) -> bytes:
        # Convert fields to bytes and concatenate them
        return (
                self.name  # Name as label sequence
                + self._type.to_bytes(2, "big")  # Type (2 bytes)
                + self._class.to_bytes(2, "big")  # Class (2 bytes)
                + self.ttl.to_bytes(4, "big")  # TTL (4 bytes)
                + self.rdlength.to_bytes(2, "big")  # RDLENGTH (2 bytes)
                + self.rdata  # RDATA (e.g., IP address for A record, 4 bytes)
        )
