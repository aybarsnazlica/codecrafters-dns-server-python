from dataclasses import dataclass


@dataclass
class DNSQuestion:
    name: str
    qtype: int
    qclass: int = 1

    def to_bytes(self) -> bytes:
        name = self.name.split(".")
        result = b""
        for label in name:
            result += len(label).to_bytes(1, byteorder="big")
            result += label.encode()
        result += b"\x00"
        result += self.qtype.to_bytes(2, byteorder="big")
        result += self.qclass.to_bytes(2, byteorder="big")
        return result


@dataclass
class DNSHeader:
    id: int
    qr: int = 0  # Query/Response Flag
    opcode: int = 0  # Opcode (0 for standard query)
    aa: int = 0  # Authoritative Answer Flag
    tc: int = 0  # Truncation Flag
    rd: int = 1  # Recursion Desired Flag
    ra: int = 0  # Recursion Available Flag
    z: int = 0  # Reserved
    rcode: int = 0  # Response Code
    qdcount: int = 0  # Number of questions
    ancount: int = 0  # Number of answers
    nscount: int = 0  # Number of authority records
    arcount: int = 0  # Number of additional records

    @classmethod
    def from_bytes(cls, data: bytes):
        id = int.from_bytes(data[0:2], byteorder='big')
        flags = int.from_bytes(data[2:4], byteorder='big')
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 1
        tc = (flags >> 9) & 1
        rd = (flags >> 8) & 1
        ra = (flags >> 7) & 1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF
        qdcount = int.from_bytes(data[4:6], byteorder='big')
        ancount = int.from_bytes(data[6:8], byteorder='big')
        nscount = int.from_bytes(data[8:10], byteorder='big')
        arcount = int.from_bytes(data[10:12], byteorder='big')
        return cls(id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount)

    def encode(self) -> bytes:
        flags = (
                (self.qr << 15) |
                (self.opcode << 11) |
                (self.aa << 10) |
                (self.tc << 9) |
                (self.rd << 8) |
                (self.ra << 7) |
                (self.z << 4) |
                self.rcode
        )
        return (
                self.id.to_bytes(2, byteorder="big") +
                flags.to_bytes(2, byteorder="big") +
                self.qdcount.to_bytes(2, byteorder="big") +
                self.ancount.to_bytes(2, byteorder="big") +
                self.nscount.to_bytes(2, byteorder="big") +
                self.arcount.to_bytes(2, byteorder="big")
        )


@dataclass
class DNSAnswer:
    name: bytes
    _type: int
    _class: int
    ttl: int
    rdlength: int
    rdata: bytes

    def encode(self) -> bytes:
        return (
                self.name +
                self._type.to_bytes(2, byteorder="big") +
                self._class.to_bytes(2, byteorder="big") +
                self.ttl.to_bytes(4, byteorder="big") +
                self.rdlength.to_bytes(2, byteorder="big") +
                self.rdata
        )
