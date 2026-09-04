from ecforensics.ingestion.stream_reassembly import _reassemble_direction


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
