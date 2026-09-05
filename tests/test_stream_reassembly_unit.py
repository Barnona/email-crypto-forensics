from ecforensics.ingestion.stream_reassembly import _reassemble_direction, _stream_meta_from_rows


def test_reassembles_out_of_order_segments():
    payload, gap = _reassemble_direction([
        (1004, b"EFGH"),
        (1000, b"ABCD"),
    ])
    assert payload == b"ABCDEFGH"
    assert not gap


def test_discards_exact_retransmission():
    payload, gap = _reassemble_direction([
        (1000, b"ABCD"),
        (1000, b"ABCD"),
        (1004, b"EF"),
    ])
    assert payload == b"ABCDEF"
    assert not gap


def test_trims_overlapping_retransmission():
    payload, gap = _reassemble_direction([
        (1000, b"ABCD"),
        (1002, b"CDEF"),
    ])
    assert payload == b"ABCDEF"
    assert not gap


def test_detects_sequence_gap():
    payload, gap = _reassemble_direction([
        (1000, b"AB"),
        (1004, b"EF"),
    ])
    assert payload == b"ABEF"
    assert gap


def test_empty_direction_is_incomplete():
    payload, gap = _reassemble_direction([])
    assert payload == b""
    assert not gap


def test_discovers_smtp_stream_when_capture_has_no_syn():
    rows = "42\t10.0.0.2\t\t25\t10.0.0.1\t\t51000\n"
    streams = _stream_meta_from_rows(rows, set())
    assert streams == [{
        "stream_id": "42",
        "client_ip": "10.0.0.1",
        "client_port": 51000,
        "server_ip": "10.0.0.2",
        "server_port": 25,
    }]
