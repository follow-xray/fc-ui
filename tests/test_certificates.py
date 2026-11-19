import contextlib
import grp
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import cert_service as worker
from certificates import inventory, pair


class CertificateTest(unittest.TestCase):
    def setUp(self):
        clean = contextlib.ExitStack()
        self.addCleanup(clean.close)
        self.tmp = Path(clean.enter_context(tempfile.TemporaryDirectory()))
        self.store = self.tmp / "store"
        self.store.mkdir()
        self.cert, self.key = self.tmp / "chain.pem", self.tmp / "private.key"
        self.ca, self.ca_key = self.tmp / "ca.pem", self.tmp / "ca.key"
        self.openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Test CA",
                     "-addext", "basicConstraints=critical,CA:TRUE", "-days", "2", "-out", self.ca, "-keyout", self.ca_key)
        clean.enter_context(patch.dict(os.environ, SSL_CERT_FILE=str(self.ca)))
        clean.enter_context(patch.object(worker, "STORE", self.store))
        clean.enter_context(patch.object(worker, "PRIVATE", self.tmp))
        clean.enter_context(patch.object(worker.os, "chown"))
        clean.enter_context(patch.object(worker.grp, "getgrnam", return_value=grp.getgrgid(os.getgid())))
        self.issue("*.nodes.example")

    def openssl(self, *args):
        subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)

    def issue(self, san):
        request = self.tmp / "req"
        ext = self.tmp / "ext"
        ext.write_text("subjectAltName=DNS:" + san + "\nextendedKeyUsage=serverAuth\n")
        self.openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                     "-subj", "/CN=leaf", "-keyout", self.key, "-out", request)
        self.openssl("x509", "-req", "-in", request, "-CA", self.ca, "-CAkey", self.ca_key,
                     "-CAcreateserial", "-out", self.cert, "-days", "1", "-extfile", ext)

    def test_path_reuse_and_renewal_rollback(self):
        domain = "first.nodes.example"
        item = worker.register(dict(domain=domain, source="path", chainPath=str(self.cert), keyPath=str(self.key)))
        paths = pair(item["id"], self.store)
        self.assertEqual(worker.register(dict(domain="second.nodes.example", source="acme"))["id"], item["id"])
        self.assertFalse(inventory("too.deep.nodes.example", self.store))
        self.assertEqual(len(inventory(domain, self.store)), 1)
        old = paths[0].resolve()
        self.issue("*.nodes.example")
        worker.maintain()
        self.assertNotEqual(paths[0].resolve(), old)
        self.assertEqual(paths[0].read_bytes(), self.cert.read_bytes())
        good = paths[0].resolve()
        self.issue("unrelated.example")
        worker.maintain()
        self.assertEqual(paths[0].resolve(), good)
        self.assertIn("更新待重试", inventory(domain, self.store)[0]["renewalStatus"])

    def test_dns_inputs_and_trust(self):
        with patch.object(worker, "acme", return_value=(self.cert.read_bytes(), self.key.read_bytes())) as issue:
            base = dict(domain="x.nodes.example", identifier="*.nodes.example", source="acme")
            with self.assertRaises(ValueError):
                worker.register(dict(base, method="http"))
            with self.assertRaises(ValueError):
                worker.register(dict(base, method="dns", provider="cloudflare", token=""))
            issue.assert_not_called()
            data = dict(base, method="dns", provider="cloudflare", token="test_token_only")
            result = worker.register(data)
            record, env = issue.call_args.args
            self.assertEqual(env, {"CF_Token": data["token"]})
            self.assertNotIn("token", record)
            saved = (self.store / result["id"] / "current/record.json").read_text()
            self.assertNotIn(data["token"], saved)
        with self.assertRaises(ValueError):
            worker.register(dict(domain="other.example", source="pem", certificate=self.cert.read_text(), key=self.key.read_text()))
        with patch.dict(os.environ, SSL_CERT_FILE="/dev/null"):
            with self.assertRaises(ValueError):
                worker.verify_pair(self.cert, self.key, "x.nodes.example")
