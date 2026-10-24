import os
import pytest
from c2_protocol import PacketType, pack_packet, unpack_header, HEADER_SIZE, ProtocolCryptoEngine, ProtocolSession


def test_packet_framing():
    nonce = os.urandom(12)
    ciphertext = b"test_encrypted_payload_bytes_with_tag"
    packed = pack_packet(PacketType.HANDSHAKE, nonce, ciphertext)
    
    p_type, n_len, c_len = unpack_header(packed[:HEADER_SIZE])
    assert p_type == PacketType.HANDSHAKE
    assert n_len == 12
    assert c_len == len(ciphertext)


def test_crypto_roundtrip():
    key = os.urandom(32)
    engine = ProtocolCryptoEngine(key)
    
    payload = {"status": "ok", "agent_id": "lab-node-01", "cpu_pct": 14.5}
    nonce, ct = engine.encrypt_payload(payload)
    decrypted = engine.decrypt_payload(nonce, ct)
    
    assert decrypted["status"] == "ok"
    assert decrypted["agent_id"] == "lab-node-01"
    assert decrypted["cpu_pct"] == 14.5


def test_session_state_and_replay_protection():
    shared_key = os.urandom(32)
    sender = ProtocolSession(shared_key, session_id="session-node-alpha")
    receiver = ProtocolSession(shared_key, session_id="session-node-alpha")
    
    # 1. Message 1 (Handshake)
    msg1 = sender.create_message(PacketType.HANDSHAKE, {"hostname": "mock-ubuntu-host"})
    res1 = receiver.process_message(msg1)
    assert res1["type"] == PacketType.HANDSHAKE
    assert res1["seq"] == 1
    assert res1["data"]["hostname"] == "mock-ubuntu-host"
    
    # 2. Message 2 (Heartbeat)
    msg2 = sender.create_message(PacketType.HEARTBEAT, {"uptime": 3600})
    res2 = receiver.process_message(msg2)
    assert res2["type"] == PacketType.HEARTBEAT
    assert res2["seq"] == 2
    
    # 3. Replay Message 1 -> Must raise ValueError
    with pytest.raises(ValueError, match="Replay attack detected"):
        receiver.process_message(msg1)
