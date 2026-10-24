"""
Binary Packet Framing & Type Definitions
Fixed 6-byte header with AES-256-GCM authenticated payload framing.

Author: Nguyen Huynh Dang Nhut (@nhutnhd)
For Educational & Defensive Network Protocol Research Only.
"""

import struct
from enum import IntEnum
from typing import Tuple, Optional


class PacketType(IntEnum):
    """Protocol packet type identifiers."""
    HANDSHAKE = 0x01
    COMMAND = 0x02
    RESPONSE = 0x03
    HEARTBEAT = 0x04
    STREAM_FRAME = 0x05
    FILE_TRANSFER = 0x06
    DISCONNECT = 0xFF


# Fixed 6-byte header format:
# Byte 0: Packet Type (!B)
# Byte 1: Nonce Length (!B, 12 bytes for AES-GCM)
# Byte 2-5: Ciphertext Length (!I, 4 bytes big-endian)
HEADER_FORMAT = "!BBI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
STANDARD_NONCE_LENGTH = 12


def pack_packet(packet_type: PacketType, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Serializes a binary packet with fixed 6-byte header, variable nonce, and ciphertext.
    """
    if len(nonce) > 255:
        raise ValueError("Nonce length exceeds 255 bytes.")
    
    header = struct.pack(HEADER_FORMAT, int(packet_type), len(nonce), len(ciphertext))
    return header + nonce + ciphertext


def unpack_header(header_bytes: bytes) -> Tuple[PacketType, int, int]:
    """
    Parses a 6-byte binary header.
    Returns: (packet_type, nonce_length, ciphertext_length)
    """
    if len(header_bytes) < HEADER_SIZE:
        raise ValueError(f"Header too short: expected {HEADER_SIZE} bytes, got {len(header_bytes)}")
        
    p_type_val, nonce_len, ct_len = struct.unpack(HEADER_FORMAT, header_bytes[:HEADER_SIZE])
    try:
        p_type = PacketType(p_type_val)
    except ValueError:
        raise ValueError(f"Unknown packet type identifier: 0x{p_type_val:02X}")
        
    return p_type, nonce_len, ct_len
