# Secure Binary Protocol & Authenticated Telemetry Framing Framework

> Reference implementation and defensive research laboratory for binary authenticated packet framing, session state machines, and anti-replay verification across network channels.
> Author: Nguyen Huynh Dang Nhut (@nhdnhut)
> Project Status: Archived Academic Reference Implementation (Read-Only)

[![Python](https://img.shields.io/badge/Language-Python_3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Protocol](https://img.shields.io/badge/Specification-Binary_Framing_v3-009688?style=flat-square)](c2_protocol/packet.py)
[![Security](https://img.shields.io/badge/Cryptography-AES--256--GCM-red.svg?style=flat-square)](c2_protocol/crypto.py)
[![Tests](https://img.shields.io/badge/Tests-3%20Passed-brightgreen?style=flat-square&logo=pytest&logoColor=white)](tests/)
[![License](https://img.shields.io/badge/License-MIT_Educational-blue.svg?style=flat-square)](LICENSE)

---

## 1. Legal & Educational Purpose Disclaimer

> [!IMPORTANT]
> **LEGAL AND ETHICAL NOTICE FOR ACADEMIC EVALUATORS & RECRUITERS:**  
> This repository is published strictly for computer science education, defensive protocol analysis, and secure telecommunications research. It contains NO exploit payloads, credential extraction mechanisms, or weaponized attack tools. All client-server interaction patterns in this framework model abstract telemetry packets (heartbeats, simulated commands, and state acknowledgments) over loopback network boundaries. Following initial publication, this repository is preserved in an archived state as an immutable academic reference artifact.

---

## 2. Protocol Specification & Packet Framing

The communication channel enforces a fixed 6-byte binary header followed by a variable-length initialization vector (nonce) and authenticated ciphertext with integrated authentication tag (AES-256-GCM).

### 2.1 Fixed 6-Byte Header Format

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Packet Type  |  Nonce Length |       Ciphertext Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       (Ciphertext Length)     |        Nonce (12 Bytes)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               | Encrypted JSON Payload + Tag  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
~                Ciphertext Data (Length Bytes)                 ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.2 Field Definitions

1. `Packet Type` (1 Byte, unsigned char `!B`):
   - `0x01` (`HANDSHAKE`): Client node registration and capability exchange.
   - `0x02` (`COMMAND`): Simulated control directive from coordinator to node.
   - `0x03` (`RESPONSE`): Execution telemetry acknowledgment returned from node.
   - `0x04` (`HEARTBEAT`): Liveness ping/pong packet measuring channel round-trip time.
   - `0x05` (`STREAM_FRAME`): Compressed visualization frame fragment.
   - `0x06` (`FILE_TRANSFER`): Segmented telemetry chunk.
   - `0xFF` (`DISCONNECT`): Clean session termination.

2. `Nonce Length` (1 Byte, unsigned char `!B`): Standard 12 bytes (`0x0C`) for AES-GCM (NIST SP 800-38D).
3. `Ciphertext Length` (4 Bytes, unsigned int big-endian `!I`): Total byte length of encrypted payload including 16-byte authentication tag.
4. `Nonce Data` (12 Bytes): Fresh cryptographically random bytes (`os.urandom(12)`) per packet.
5. `Ciphertext Data`: Authenticated ciphertext preventing tampering and chosen-ciphertext attacks.

---

## 3. Anti-Replay Verification

Each session encapsulates an internal sequence counter and high-resolution timestamp within the encrypted payload:

$$\text{Incoming Sequence} > \text{Last Processed Sequence}$$

If a duplicate or decremented sequence number is received within the same session ID, the session raises an immediate `ValueError("Replay attack detected")` and terminates the connection.

---

## 4. Directory Structure

```text
c2-protocol-simulation-framework/
|-- c2_protocol/
|   |-- __init__.py           # Package exports
|   |-- crypto.py             # AES-256-GCM encryption & decryption
|   |-- packet.py             # Binary header packing and unpacking (!BBI)
|   `-- session.py            # Sequence counter and session state machine
|-- tests/
|   `-- test_protocol.py      # Unit tests for framing, crypto, and replay rejection
|-- pytest.ini                # Test runner configuration
|-- LICENSE                   # MIT License with Educational Rider
`-- README.md                 # Technical specification and disclaimer
```

---

## 5. Automated Verification

Execute the test suite verifying packet framing and anti-replay protection:

```bash
pytest tests/ -v
```

---

## 6. License & Archival Notice

This software is released under the MIT License with an Educational & Research Use Rider.  
Copyright (c) 2026 Nguyen Huynh Dang Nhut (@nhdnhut).  
This repository is archived and maintained for educational reference only.

