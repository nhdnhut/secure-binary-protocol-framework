"""
Session State Machine & Anti-Replay Guard
Tracks session state, sequence numbers, and validates packet integrity.

Author: Nguyen Huynh Dang Nhut (@nhutnhd)
For Educational & Defensive Network Protocol Research Only.
"""

import time
from typing import Dict, Any, Optional
from .packet import PacketType, pack_packet, unpack_header, HEADER_SIZE
from .crypto import ProtocolCryptoEngine


class ProtocolSession:
    """Manages full duplex packet framing and sequence tracking."""
    def __init__(self, key: Optional[bytes] = None, session_id: str = "sim-session-01"):
        self.session_id = session_id
        self.crypto = ProtocolCryptoEngine(key)
        self.sequence_number = 0
        self.last_received_seq = -1
        self.is_authenticated = False

    def create_message(self, packet_type: PacketType, payload_data: Dict[str, Any]) -> bytes:
        """Wraps payload with session metadata, encrypts, and serializes packet."""
        self.sequence_number += 1
        wrapped = {
            "session_id": self.session_id,
            "seq": self.sequence_number,
            "timestamp": time.time(),
            "data": payload_data
        }
        nonce, ciphertext = self.crypto.encrypt_payload(wrapped)
        return pack_packet(packet_type, nonce, ciphertext)

    def process_message(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Parses packet header, decrypts payload, and verifies anti-replay sequence."""
        packet_type, nonce_len, ct_len = unpack_header(raw_bytes[:HEADER_SIZE])
        
        offset = HEADER_SIZE
        nonce = raw_bytes[offset : offset + nonce_len]
        offset += nonce_len
        ciphertext = raw_bytes[offset : offset + ct_len]
        
        payload = self.crypto.decrypt_payload(nonce, ciphertext)
        
        # Verify sequence invariant
        seq = payload.get("seq", 0)
        if seq <= self.last_received_seq:
            raise ValueError(f"Replay attack detected: incoming seq {seq} <= last {self.last_received_seq}")
        self.last_received_seq = seq
        
        return {
            "type": packet_type,
            "session_id": payload.get("session_id"),
            "seq": seq,
            "timestamp": payload.get("timestamp"),
            "data": payload.get("data")
        }
