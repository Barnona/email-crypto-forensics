"""
Vertical-slice pipeline: PCAP -> reassembled streams -> EmailSession -> risk findings.

This is the real ingestion path (stream_reassembly + protocol_identifier +
starttls_detector), stopping short of TLS handshake parsing since that
requires actual TLS bytes in the capture (handshake_parser.py is still
stubbed -- see innovation_roadmap.md build order). For plaintext-only
sessions like this one, that's enough to produce a real, non-mock
EmailSession and run it through the unmodified risk engine.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from ecforensics.ingestion.stream_reassembly import TCPStreamReassembler
from ecforensics.ingestion.protocol_identifier import identify_protocol, is_implicit_tls_port
from ecforensics.tls.starttls_detector import detect_starttls
from ecforensics.models.session import EmailSession
from ecforensics.risk_engine.scorer import assess_sessions, overall_severity


def build_sessions_from_pcap(pcap_path: str | Path) -> list[EmailSession]:
    reassembler = TCPStreamReassembler()
    streams = reassembler.reassemble(pcap_path)

    sessions = []
    for stream_id, stream in streams.items():
        protocol = identify_protocol(stream.server_port, stream.server_to_client[:64])

        if protocol.value == "UNKNOWN":
            continue  # not an email protocol stream, skip

        session = EmailSession(
            session_id=f"pcap-stream-{stream_id}",
            protocol=protocol,
            src_ip=stream.client_ip,
            src_port=stream.client_port,
            dst_ip=stream.server_ip,
            dst_port=stream.server_port,
            start_time=datetime.now(timezone.utc),
        )

        if is_implicit_tls_port(stream.server_port):
            # TLS from byte 0 -- handshake_parser.py needed to populate
            # tls_session; not yet implemented, so leave it None for now
            # rather than fabricating a TLSSession we didn't actually parse.
            pass
        else:
            starttls = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
            session.starttls_offered = starttls.offered
            session.starttls_used = starttls.negotiated
            # tls_session stays None until handshake_parser.py is implemented
            # to parse the bytes after starttls.upgrade_offset.

        sessions.append(session)

    return sessions


if __name__ == "__main__":
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_pcaps/smtp_starttls_unused.pcap"
    sessions = assess_sessions(build_sessions_from_pcap(pcap_path))

    for s in sessions:
        print(f"{s.session_id}  {s.protocol.value}  {s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}")
        print(f"  starttls_offered={s.starttls_offered}  starttls_used={s.starttls_used}")
        print(f"  severity={overall_severity(s).value}  risk_score={s.risk_score}")
        for f in s.findings:
            print(f"    [{f.rule_id}] {f.description}")
