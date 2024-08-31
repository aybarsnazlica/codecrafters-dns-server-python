import socket
import struct
from dataclasses import dataclass

from .utils import forward_query


@dataclass
class Header:
    id: int
    qr: bool
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    reserved: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    HEADER_FORMAT = ">HHHHHH"
    HEADER_SIZE = 12

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Invalid DNS header size")

        fields = struct.unpack(cls.HEADER_FORMAT, data[:cls.HEADER_SIZE])
        identifier, flags, question_count, answer_record_count, authority_record_count, additional_record_count = fields

        return cls(
            id=identifier,
            qr=(flags & 0x8000) != 0,
            opcode=(flags & 0x7800) >> 11,
            aa=(flags & 0x0400) != 0,
            tc=(flags & 0x0200) != 0,
            rd=(flags & 0x0100) != 0,
            ra=(flags & 0x0080) != 0,
            reserved=(flags & 0x0070) >> 4,
            rcode=flags & 0x000F,
            qdcount=question_count,
            ancount=answer_record_count,
            nscount=authority_record_count,
            arcount=additional_record_count,
        )

    def to_bytes(self) -> bytes:
        flags = (
                (int(self.qr) << 15) |
                (self.opcode << 11) |
                (int(self.aa) << 10) |
                (int(self.tc) << 9) |
                (int(self.rd) << 8) |
                (int(self.ra) << 7) |
                (self.reserved << 4) |
                self.rcode
        )
        return struct.pack(
            self.HEADER_FORMAT,
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount
        )


@dataclass
class Question:
    names: list[str]
    qtype: int
    qclass: int

    @classmethod
    def from_bytes(cls, current_data: bytes, complete_packet: bytes):
        names, current_data = cls.parse_names(current_data, complete_packet)
        if len(current_data) < 4:
            raise ValueError("Invalid DNS question format")
        qtype, qclass = struct.unpack(">HH", current_data[:4])
        return cls(names=names, qtype=qtype, qclass=qclass), current_data[4:]

    def to_bytes(self) -> bytes:
        return self.serialize_names(self.names) + struct.pack(">HH", self.qtype, self.qclass)

    @staticmethod
    def parse_names(current_data: bytes, complete_packet: bytes):
        names = []
        while True:
            if len(current_data) < 1:
                raise ValueError("Invalid name format")
            length = current_data[0]
            current_data = current_data[1:]

            if length == 0:
                break
            if (length >> 6) == 0:
                names.append(current_data[:length].decode())
                current_data = current_data[length:]
            elif (length >> 6) == 3:
                offset = ((length & 0b0011_1111) << 8) | current_data[0]
                current_data = current_data[1:]
                names += Question.parse_names(complete_packet[offset:], complete_packet)[0]
                break

        return names, current_data

    @staticmethod
    def serialize_names(names: list[str]) -> bytes:
        return b"".join(struct.pack(">B", len(name)) + name.encode() for name in names) + b"\x00"


class Forwarder:
    def __init__(self, resolver: tuple):
        self.resolver = resolver
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def handle_request(self, request: bytes, client_address: tuple):
        header, questions, remaining_data = self.parse_request(request)

        response_header = Header(
            id=header.id,
            qr=True,
            opcode=header.opcode,
            aa=False,
            tc=False,
            rd=header.rd,
            ra=True,
            reserved=0,
            rcode=0 if header.opcode == 0 else 4,
            qdcount=header.qdcount,
            ancount=header.qdcount,
            nscount=0,
            arcount=0,
        )

        response = response_header.to_bytes()

        for question in questions:
            response += question.to_bytes()

        for question in questions:
            response += self.get_answer(question)

        self.socket.sendto(response, client_address)

    @staticmethod
    def parse_request(request: bytes):
        header = Header.from_bytes(request)
        remaining_data = request[Header.HEADER_SIZE:]
        questions = []

        for _ in range(header.qdcount):
            question, remaining_data = Question.from_bytes(remaining_data, request)
            questions.append(question)

        return header, questions, remaining_data

    def get_answer(self, question: Question) -> bytes:
        request_header = Header(
            id=1234,
            qr=False,
            opcode=0,
            aa=False,
            tc=False,
            rd=True,
            ra=False,
            reserved=0,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
        )
        request = request_header.to_bytes() + question.to_bytes()
        response = forward_query(request, self.resolver)
        _, remaining_data = Question.from_bytes(response[Header.HEADER_SIZE:], response)

        return remaining_data

    def start(self, host="0.0.0.0", port=2053):
        self.socket.bind((host, port))
        while True:
            try:
                request, client_address = self.socket.recvfrom(512)
                self.handle_request(request, client_address)
            except Exception as e:
                print(f"Error: {e}")
