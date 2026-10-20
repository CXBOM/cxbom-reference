"""Relay framing, JSON-RPC shapes, pending ids, single writers (spec 8.2). Owner: ATACE Working Group."""
import os
import threading
import time

import pytest

from cxbom import jsonstrict, relay


def feed(chunks, max_line=relay.MAX_LINE, chunk=65536):
    r, w = os.pipe()

    def writer():
        for c in chunks:
            os.write(w, c)
        os.close(w)

    t = threading.Thread(target=writer)
    t.start()
    try:
        return list(relay.read_lines(r, max_line=max_line, chunk=chunk))
    finally:
        t.join()
        os.close(r)


def test_read_lines_splits_across_chunks_and_skips_empty_lines():
    out = feed([b'{"a":', b'1}\n\n{"b":2}\n{"c"', b':3}'], chunk=4)
    assert out == [b'{"a":1}', b'{"b":2}', b'{"c":3}']


def test_read_lines_keeps_bytes_exactly():
    assert feed([b'{"a" : 1.0}\r\n']) == [b'{"a" : 1.0}\r']


def test_read_lines_skips_a_blank_crlf_line():
    out = feed([b'{"a":1}\n\r\n{"b":2}\n'])
    assert out == [b'{"a":1}', b'{"b":2}']


def test_read_lines_keeps_a_line_of_other_whitespace_for_the_parser_to_reject():
    out = feed([b'{"a":1}\n \t\x0b\x0c\n{"b":2}\n'])
    assert out == [b'{"a":1}', b' \t\x0b\x0c', b'{"b":2}']
    with pytest.raises(jsonstrict.StrictJSONError):
        relay.classify(out[1])


def test_read_lines_wraps_os_read_failures_in_relay_error():
    r, w = os.pipe()
    os.close(r)
    with pytest.raises(relay.RelayError):
        list(relay.read_lines(r))
    os.close(w)


def test_oversize_line_is_discarded_and_reading_continues():
    out = feed([b"x" * 40 + b"\n", b'{"ok":1}\n', b"y" * 50], max_line=32, chunk=16)
    assert out == [relay.OVERSIZE, b'{"ok":1}', relay.OVERSIZE]


def test_line_exactly_at_the_limit_is_kept():
    assert feed([b"z" * 32 + b"\n"], max_line=32) == [b"z" * 32]


@pytest.mark.parametrize("raw, kind, method, key", [
    (b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}', "request", "tools/list", ("number", "1")),
    (b'{"jsonrpc":"2.0","id":"1","method":"ping","params":{}}', "request", "ping", ("string", "1")),
    (b'{"jsonrpc":"2.0","id":1.0,"method":"ping"}', "request", "ping", ("number", "1.0")),
    (b'{"jsonrpc":"2.0","method":"notifications/initialized"}', "notification", "notifications/initialized", None),
    (b'{"jsonrpc":"2.0","id":9007199254740993,"result":{}}', "result", None, ("number", "9007199254740993")),
    (b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}', "error", None, ("null",)),
])
def test_classify_shapes(raw, kind, method, key):
    m = relay.classify(raw)
    assert (m.kind, m.method, m.id_key) == (kind, method, key)
    if key is not None:
        assert m.id_raw == raw[m.node.get("id").start:m.node.get("id").end]


@pytest.mark.parametrize("raw, needle", [
    (b'[{"jsonrpc":"2.0","method":"a"}]', "batch"),
    (b'"hello"', "not a JSON object"),
    (b'{"jsonrpc":"1.0","id":1,"method":"a"}', "jsonrpc"),
    (b'{"id":1,"method":"a"}', "jsonrpc"),
    (b'{"jsonrpc":"2.0","id":1,"method":"a","extra":1}', "unexpected member"),
    (b'{"jsonrpc":"2.0","id":null,"method":"a"}', "request id"),
    (b'{"jsonrpc":"2.0","id":{},"method":"a"}', "request id"),
    (b'{"jsonrpc":"2.0","id":1,"method":"a","params":[1]}', "params"),
    (b'{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}', "exactly one"),
    (b'{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"x"}}', "error.code"),
    (b'{"jsonrpc":"2.0","id":1,"error":{"code":1}}', "error.message"),
    (b'{"jsonrpc":"2.0"}', "neither"),
])
def test_classify_rejects_non_shapes(raw, needle):
    with pytest.raises(relay.ShapeError, match=needle):
        relay.classify(raw)


@pytest.mark.parametrize("shape, needle", [
    (b'"method":"ping"', "request id"),
    (b'"result":{}', "result id"),
    (b'"error":{"code":1,"message":"x"}', "error id"),
])
def test_classify_refuses_an_id_over_the_byte_bound(shape, needle):
    # A quoted string, not a bare number: jsonstrict's own 400-char number
    # cap would otherwise raise StrictJSONError first and never exercise
    # this bound.
    huge = b'"' + b"i" * relay.MAX_ID_RAW + b'"'
    raw = b'{"jsonrpc":"2.0","id":' + huge + b"," + shape + b"}"
    with pytest.raises(relay.ShapeError, match=needle):
        relay.classify(raw)


def test_classify_accepts_an_id_exactly_at_the_byte_bound():
    at_bound = b'"' + b"a" * (relay.MAX_ID_RAW - 2) + b'"'
    assert len(at_bound) == relay.MAX_ID_RAW
    m = relay.classify(b'{"jsonrpc":"2.0","id":' + at_bound + b',"method":"ping"}')
    assert m.id_raw == at_bound


@pytest.mark.parametrize("raw", [
    b'{"jsonrpc":"2.0","id":1,"method":"a","method":"b"}',
    b'{"jsonrpc":"2.0","id":1e400,"method":"a"}',
    b'{"jsonrpc":"2.0","id":"\\ud800","method":"a"}',
    b'{"jsonrpc":"2.0","id":1,"method":"\xff"}',
])
def test_classify_propagates_strict_parse_errors(raw):
    with pytest.raises(jsonstrict.StrictJSONError):
        relay.classify(raw)


def test_classify_refuses_a_carriage_return_used_to_smuggle_a_second_message():
    # A raw \r inside params, immediately before bytes shaped like a full
    # result object, then another \r before the closing braces. jsonstrict
    # parses this as one valid, nested JSON value, since \r is legal JSON
    # whitespace, but a universal-newline reader (Popen(text=True),
    # TextIOWrapper) splits it into more than one line.
    raw = (b'{"jsonrpc":"2.0","method":"m","params":{"x":\r'
           b'{"jsonrpc":"2.0","id":1,"result":{}}\r}}')
    with pytest.raises(relay.ShapeError, match="carriage return"):
        relay.classify(raw)


def test_classify_still_accepts_a_trailing_carriage_return():
    m = relay.classify(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\r')
    assert (m.kind, m.method) == ("request", "tools/list")


@pytest.mark.parametrize("seq", [b"\xe2\x80\xa8", b"\xe2\x80\xa9", b"\xc2\x85"])
def test_classify_refuses_unicode_line_terminators_inside_a_string(seq):
    raw = b'{"jsonrpc":"2.0","id":1,"method":"m","params":{"note":"a' + seq + b'b"}}'
    with pytest.raises(relay.ShapeError, match="line-terminator"):
        relay.classify(raw)


def test_shape_error_and_duplicate_id_are_relay_errors():
    assert issubclass(relay.ShapeError, relay.RelayError)
    assert issubclass(relay.DuplicateId, relay.RelayError)


def test_message_accessors():
    m = relay.classify(b'{"jsonrpc":"2.0","id":"a","method":"tools/list","params":'
                       b'{"cursor":"c2","_meta":{"k":1}}}')
    assert m.param("cursor").value == "c2"
    assert m.meta() == {"k": 1}
    assert m.id_python() == "a"


def test_pending_types_directions_and_duplicates():
    t = relay.PendingTable()
    t.add(relay.Pending(relay.C2S, ("number", "1"), "tools/list"))
    t.add(relay.Pending(relay.S2C, ("number", "1"), "sampling/createMessage"))
    with pytest.raises(relay.DuplicateId):
        t.add(relay.Pending(relay.C2S, ("number", "1"), "ping"))
    assert t.take(relay.C2S, ("string", "1")) is None
    assert t.take(relay.C2S, ("number", "1.0")) is None
    assert t.take(relay.C2S, ("number", "1")).method == "tools/list"
    assert t.take(relay.C2S, ("number", "1")) is None
    assert t.take(relay.S2C, ("number", "1")).method == "sampling/createMessage"


def test_cancelled_entry_is_kept_for_the_retention_window():
    t = relay.PendingTable(retention=30.0)
    t.add(relay.Pending(relay.C2S, ("number", "5"), "tools/call"))
    assert t.cancel(relay.C2S, ("number", "5"), now=100.0).cancelled_at == 100.0
    assert t.outstanding(relay.C2S) == []
    t.expire(now=129.9)
    assert t.get(relay.C2S, ("number", "5")) is not None
    with pytest.raises(relay.DuplicateId):
        t.add(relay.Pending(relay.C2S, ("number", "5"), "tools/call"))
    t.expire(now=130.0)
    assert t.get(relay.C2S, ("number", "5")) is None


def test_proxy_ids_have_the_session_prefix():
    ids = relay.ProxyIds("3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11")
    assert ids.next() == "cxbom-3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11-1"
    assert ids.next().endswith("-2")


def test_line_writer_is_ordered_and_stop_flushes():
    r, w = os.pipe()
    writer = relay.LineWriter(w, "test")
    for i in range(200):
        writer.send(b'{"n":%d}' % i)
    assert writer.stop() is True
    os.close(w)
    data = b""
    while True:
        chunk = os.read(r, 65536)
        if not chunk:
            break
        data += chunk
    os.close(r)
    assert data.split(b"\n")[:-1] == [b'{"n":%d}' % i for i in range(200)]
    assert writer.error is None


def test_line_writer_records_a_broken_pipe_and_keeps_draining():
    r, w = os.pipe()
    os.close(r)
    writer = relay.LineWriter(w, "broken")
    writer.send(b"one")
    writer.send(b"two")
    deadline = time.time() + 2
    while writer.error is None and time.time() < deadline:
        time.sleep(0.01)
    writer.stop()
    os.close(w)
    assert isinstance(writer.error, BrokenPipeError)


def test_send_after_stop_raises_relay_error():
    r, w = os.pipe()
    writer = relay.LineWriter(w, "stopped")
    assert writer.stop() is True
    with pytest.raises(relay.RelayError):
        writer.send(b'{"a":1}')
    os.close(r)
    os.close(w)


def test_send_refuses_a_line_containing_a_newline():
    r, w = os.pipe()
    writer = relay.LineWriter(w, "newline")
    with pytest.raises(relay.RelayError):
        writer.send(b'{"a":1}\n{"b":2}')
    writer.stop()
    os.close(r)
    os.close(w)


def test_line_writer_dup_keeps_the_writer_off_a_reused_fd_number(tmp_path):
    r, w = os.pipe()
    writer = relay.LineWriter(w, "dup")
    writer.send(b'{"n":1}')
    assert writer.stop() is True
    os.close(w)

    # The writer's thread has already ended and its dup is already closed,
    # so w's fd number is free. Reopening it for an unrelated file must see
    # no further activity from the writer.
    reused_path = tmp_path / "reused.bin"
    reused_fd = os.open(str(reused_path), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        time.sleep(0.05)
        assert reused_path.read_bytes() == b""
    finally:
        os.close(reused_fd)

    data = b""
    while True:
        chunk = os.read(r, 65536)
        if not chunk:
            break
        data += chunk
    os.close(r)
    assert data == b'{"n":1}\n'


def test_line_writer_delivers_every_line_when_the_original_fd_is_nonblocking():
    r, w = os.pipe()
    os.set_blocking(w, False)
    writer = relay.LineWriter(w, "nonblocking")
    lines = [b'{"n":%05d}' % i for i in range(5000)]
    received = bytearray()

    def reader():
        while True:
            chunk = os.read(r, 65536)
            if not chunk:
                break
            received.extend(chunk)

    t = threading.Thread(target=reader)
    t.start()
    for line in lines:
        writer.send(line)
    assert writer.stop(timeout=5.0) is True
    os.close(w)
    t.join(5.0)
    os.close(r)
    assert bytes(received).split(b"\n")[:-1] == lines
    assert writer.error is None


def test_line_writer_send_never_blocks_even_when_the_pipe_is_full():
    r, w = os.pipe()
    writer = relay.LineWriter(w, "full")
    big = b"x" * 65536
    start = time.monotonic()
    for _ in range(20):
        writer.send(big)
    assert time.monotonic() - start < 1.0

    drained = bytearray()

    def reader():
        while True:
            chunk = os.read(r, 65536)
            if not chunk:
                break
            drained.extend(chunk)

    t = threading.Thread(target=reader)
    t.start()
    assert writer.stop(timeout=5.0) is True
    os.close(w)
    t.join(5.0)
    os.close(r)
    assert len(drained) == 20 * (len(big) + 1)


def test_line_writer_from_many_threads_delivers_every_line_intact_and_unmixed():
    r, w = os.pipe()
    writer = relay.LineWriter(w, "concurrent")
    received = bytearray()

    def reader():
        while True:
            chunk = os.read(r, 65536)
            if not chunk:
                break
            received.extend(chunk)

    reader_thread = threading.Thread(target=reader)
    reader_thread.start()

    expected = set()

    def sender(tid):
        for i in range(500):
            line = b'{"t":%d,"n":%d}' % (tid, i)
            expected.add(line)
            writer.send(line)

    senders = [threading.Thread(target=sender, args=(tid,)) for tid in range(8)]
    for t in senders:
        t.start()
    for t in senders:
        t.join()
    assert writer.stop(timeout=5.0) is True
    os.close(w)
    reader_thread.join(5.0)
    os.close(r)

    lines = bytes(received).split(b"\n")[:-1]
    assert len(expected) == 4000
    assert len(lines) == 4000
    assert set(lines) == expected
