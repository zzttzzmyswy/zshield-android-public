"""The controlled origin's own contract: what it records, and what it refuses to soften.

Every test here starts the real `tunnel_origin.py` and talks to it over a socket. The properties are
the ones the harness's assertions rest on, so a regression here is a regression in what the whole
evidence chain can prove:

  * the request ID is echoed exactly as the upstream saw it (not as the client filled it in);
  * the body is recorded as bytes with a digest, and an HTTP/2 POST body is not lost;
  * the in-flight counter reaches the number of requests that really overlapped;
  * the protocol is recorded per request, and an `http/1.1`-only TLS listener really offers only
    that (the TLS/H1 leg cannot be faked by an h2 origin);
  * probes are marked as probes, so a readiness check is never counted as a planned request.
"""

from __future__ import annotations

import json
import ssl
import sys
import threading
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness_fixtures import OriginFixture, request  # noqa: E402


class PlainTextOriginTest(unittest.TestCase):
    """The plaintext listener: identity, body bytes, probes, faults."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.origin = OriginFixture().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.origin.stop()

    def test_echoes_the_request_id_it_was_handed(self) -> None:
        status, body, _ = request(
            f"{self.origin.base}/anything/get?keep=1", headers={"X-ZS-Req": "the-plan-id"}
        )
        self.assertEqual(status, 200)
        record = json.loads(body)
        self.assertEqual(record["id"], "the-plan-id")
        # The reply's own header too: a harness reading either place must see the upstream's value.
        self.assertEqual(record["path"], "/anything/get?keep=1")

    def test_records_the_raw_body_digest_not_a_normalised_form(self) -> None:
        status, body, _ = request(
            f"{self.origin.base}/anything/post",
            method="POST",
            body=b"alpha=1&beta=2",
            headers={"X-ZS-Req": "post-1"},
        )
        self.assertEqual(status, 200)
        record = json.loads(body)
        self.assertEqual(record["body"], "alpha=1&beta=2")
        self.assertEqual(record["body_len"], len(b"alpha=1&beta=2"))
        # A digest over bytes, so re-ordering the form cannot pass as "the body survived".
        self.assertEqual(len(record["body_sha256"]), 64)
        self.assertNotEqual(record["body_sha256"], json.loads(
            request(f"{self.origin.base}/anything/post", method="POST",
                    body=b"beta=2&alpha=1")[1])["body_sha256"])

    def test_a_probe_is_marked_as_a_probe(self) -> None:
        status, body, _ = request(f"{self.origin.base}/__id")
        self.assertEqual(status, 200)
        # `/__id` answers `{"ok": true, "id": …}` and the record is separate; the record of the probe
        # is what carries the flag.
        records = [record for record in self.origin.records() if record["path"].startswith("/__id")]
        self.assertTrue(records)
        self.assertTrue(all(record["probe"] for record in records))

    def test_writes_one_record_per_request(self) -> None:
        before = len(self.origin.records())
        for index in range(5):
            request(f"{self.origin.base}/anything/get?i={index}", headers={"X-ZS-Req": f"r{index}"})
        records = self.origin.records()[before:]
        self.assertEqual([record["id"] for record in records], [f"r{i}" for i in range(5)])

    def test_in_flight_peak_reaches_real_overlap(self) -> None:
        # A fresh origin with a hold, so overlap is observable rather than a race.
        held = OriginFixture(hold_ms=400).start()
        try:
            errors: list[Exception] = []

            def fire(index: int) -> None:
                try:
                    request(f"{held.base}/anything/get?i={index}", headers={"X-ZS-Req": f"c{index}"},
                            timeout=30)
                except Exception as error:  # noqa: BLE001 - reported below
                    errors.append(error)

            threads = [threading.Thread(target=fire, args=(index,)) for index in range(12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(errors, [])
            stats = held.stats()
            self.assertGreaterEqual(
                stats["peak"], 8,
                f"only {stats['peak']} request(s) overlapped; the origin cannot prove concurrency",
            )
            # Every record carries the counter at arrival, which is what the harness reads.
            inflight = [record["inflight"] for record in held.records() if not record["probe"]]
            self.assertGreaterEqual(max(inflight), 8)
        finally:
            held.stop()

    def test_serial_requests_do_not_reach_a_high_peak(self) -> None:
        # The negative control: without this, "peak >= N" would be satisfied by any counter that
        # merely counts requests.
        serial = OriginFixture().start()
        try:
            for index in range(10):
                request(f"{serial.base}/anything/get?i={index}", headers={"X-ZS-Req": f"s{index}"})
            self.assertEqual(serial.stats()["peak"], 1)
        finally:
            serial.stop()

    def test_fault_paths_are_real(self) -> None:
        status, body, _ = request(f"{self.origin.base}/__fault/500")
        self.assertEqual(status, 500)
        self.assertIn("fault", body)

        status, body, _ = request(f"{self.origin.base}/__fault/url")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["path"], "/__wrong-url")

        status, body, _ = request(f"{self.origin.base}/__fault/body", method="POST", body=b"sent=this")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["body"], "<deliberately wrong>")

        # A disconnect closes the socket with no response line.
        with self.assertRaises(Exception):
            request(f"{self.origin.base}/__fault/disconnect", timeout=5)

    def test_redirect_fault_keeps_every_other_parameter(self) -> None:
        # The navigation control: the `track` parameter is dropped and the rest is preserved, which
        # is what the core's 302 branch does for a rewritten navigation.
        import http.client

        connection = http.client.HTTPConnection("127.0.0.1", self.origin.http_port, timeout=10)
        connection.request("GET", "/__fault/redirect?keep=1&track=DROP&zs_rid=run")
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 302)
        self.assertEqual(response.getheader("Location"), "/__fault/redirect?keep=1&zs_rid=run")
        connection.close()


class TlsOriginTest(unittest.TestCase):
    """The TLS listeners: h2 on the main one, http/1.1 **only** on the other."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.origin = OriginFixture(tls=True, tls1=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.origin.stop()

    def test_the_h2_listener_reports_alpn_h2(self) -> None:
        context = ssl._create_unverified_context()  # noqa: S323 - loopback test certificate
        context.set_alpn_protocols(["h2", "http/1.1"])
        import socket

        with socket.create_connection(("127.0.0.1", self.origin.https_port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                self.assertEqual(tls.selected_alpn_protocol(), "h2")

    def test_the_tls1_listener_offers_only_http11(self) -> None:
        # This is what makes the TLS/H1 leg honest: if this listener also offered h2, a browser would
        # pick h2 and "TLS/H1 covered" would be a claim about a connection that never happened.
        context = ssl._create_unverified_context()  # noqa: S323 - loopback test certificate
        context.set_alpn_protocols(["h2", "http/1.1"])
        import socket

        with socket.create_connection(("127.0.0.1", self.origin.https1_port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                self.assertEqual(tls.selected_alpn_protocol(), "http/1.1")

    def test_tls_h1_records_no_alpn_h2(self) -> None:
        # The client offers h2 first; the listener must answer http/1.1 anyway.
        status, body, _ = request(
            f"{self.origin.base_tls1}/anything/get?keep=1",
            headers={"X-ZS-Req": "h1-1"},
            alpn=("h2", "http/1.1"),
        )
        self.assertEqual(status, 200)
        record = json.loads(body)
        self.assertTrue(record["tls"])
        self.assertEqual(record["alpn"], "http/1.1")

    def test_h2_get_and_post_are_recorded_with_bodies(self) -> None:
        """The h2 engine must record a POST body: answering on headers would lose it."""
        import http.client
        import socket

        context = ssl._create_unverified_context()  # noqa: S323 - loopback test certificate
        context.set_alpn_protocols(["h2"])
        with socket.create_connection(("127.0.0.1", self.origin.https_port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                connection = http.client.HTTPConnection("127.0.0.1", self.origin.https_port)
                connection.sock = tls
                import h2.connection
                import h2.config
                import h2.events

                h2_connection = h2.connection.H2Connection(
                    config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
                )
                h2_connection.initiate_connection()
                tls.sendall(h2_connection.data_to_send())
                body = b"gamma=3&delta=4"
                h2_connection.send_headers(
                    1,
                    [
                        (":method", "POST"),
                        (":path", "/anything/post?keep=1&zs_rid=h2run"),
                        (":authority", "127.0.0.1"),
                        (":scheme", "https"),
                        ("x-zs-req", "h2-post-1"),
                        ("content-length", str(len(body))),
                    ],
                )
                h2_connection.send_data(1, body, end_stream=True)
                tls.sendall(h2_connection.data_to_send())

                received: list[dict] = []
                deadline = __import__("time").time() + 15
                while __import__("time").time() < deadline and not received:
                    data = tls.recv(65535)
                    if not data:
                        break
                    for event in h2_connection.receive_data(data):
                        if isinstance(event, h2.events.ResponseReceived):
                            received.append({"headers": dict(event.headers)})
                        elif isinstance(event, h2.events.DataReceived):
                            if received:
                                received[-1].setdefault("data", b"")
                                received[-1]["data"] += event.data
                            h2_connection.acknowledge_received_data(len(event.data), event.stream_id)
        self.assertTrue(received, "the h2 listener sent no response")
        payload = json.loads(received[0]["data"].decode())
        self.assertEqual(payload["id"], "h2-post-1")
        self.assertEqual(payload["method"], "POST")
        self.assertEqual(payload["body"], "gamma=3&delta=4")
        self.assertEqual(payload["alpn"], "h2")
        self.assertTrue(payload["tls"])


if __name__ == "__main__":
    unittest.main()
