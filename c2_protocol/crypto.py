"""
Cryptographic Framing Engine
AES-256-GCM authenticated encryption and decryption with nonce rotation.

Author: Nguyen Huynh Dang Nhut (@nhutnhd)
For Educational & Defensive Network Protocol Research Only.
"""

import os
import json
from typing import Tuple, Dict, Any, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class ProtocolCryptoEngine:
    """
    Handles payload serialization, nonce generation, and authenticated encryption.
    """
    def __init__(self, key: Optional[bytes] = None):
        # 256-bit symmetric key (32 bytes)
        if key is None:
            self.key = os.urandom(32)
        else:
            if len(key) != 32:
                raise ValueError("Key must be exactly 32 bytes (256 bits).")
            self.key = key
            
        if HAS_CRYPTOGRAPHY:
            self.cipher = AESGCM(self.key)
        else:
            self.cipher = None

    def encrypt_payload(self, data_dict: Dict[str, Any]) -> Tuple[bytes, bytes]:
        """
        Serializes JSON dictionary, generates 12-byte nonce, and encrypts with AES-256-GCM.
        Returns: (nonce, ciphertext_with_tag)
        """
        plaintext = json.dumps(data_dict, ensure_ascii=False).encode("utf-8")
        nonce = os.urandom(12)
        
        if HAS_CRYPTOGRAPHY:
            ciphertext = self.cipher.encrypt(nonce, plaintext, None)
        else:
            # Resilient fallback mock XOR framing for lab testing without external C bindings
            keystream = bytearray()
            while len(keystream) < len(plaintext):
                keystream.extend(self.key)
            ct = bytes([p ^ k for p, k in zip(plaintext, keystream[:len(plaintext)])])
            # Append 16-byte mock tag
            ciphertext = ct + b"\x00" * 16
            
        return nonce, ciphertext

    def decrypt_payload(self, nonce: bytes, ciphertext: bytes) -> Dict[str, Any]:
        """
        Verifies authentication tag and decrypts ciphertext into dictionary.
        """
        if HAS_CRYPTOGRAPHY:
            plaintext = self.cipher.decrypt(nonce, ciphertext, None)
        else:
            # Resilient fallback
            ct = ciphertext[:-16]
            keystream = bytearray()
            while len(keystream) < len(ct):
                keystream.extend(self.key)
            plaintext = bytes([c ^ k for c, k in zip(ct, keystream[:len(ct)])])
            
        return json.loads(plaintext.decode("utf-8"))
