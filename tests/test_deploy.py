import base64
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"app"))
from cli import ssh_command
from manager import Manager
from catalog import TEMPLATES
from panel import start_panel


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PanelTest(unittest.TestCase):
    def test_loopback_token_origin_and_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = Manager(Path(tmp))
            server = start_panel(mgr, 0)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            self.assertEqual(server.server_address[0], "127.0.0.1")
            token = json.loads(mgr.token.read_text())
            def post(auth="", **headers):
                conn = http.client.HTTPConnection(*server.server_address, timeout=3)
                try:
                    conn.request("POST", "/api", '{"op":"list"}',
                                 {"Content-Type":"application/json", "Authorization":"Bearer "+auth, **headers})
                    res=conn.getresponse()
                    res.read()
                    return res.status
                finally:
                    conn.close()
            self.assertEqual(post(),401)
            self.assertEqual(post(token, Host="other.example"),403)
            self.assertEqual(post(token, Origin="https://other.example"),403)
            self.assertEqual(post(token),200)
            self.assertEqual(ssh_command("vps.example","admin",2222,8787),
                             "ssh -N -L 127.0.0.1:8787:127.0.0.1:8787 -o ExitOnForwardFailure=yes -p 2222 admin@vps.example")
            with self.assertRaises(ValueError): ssh_command("-o","root",22,8787)
            with self.assertRaises(ValueError): mgr.call("panel", {"port":8787})


@unittest.skipUnless(os.environ.get("XRAY_TEST_BIN"), "Set XRAY_TEST_BIN to test an actual Xray executable")
class CoreTest(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.state=Path(self.dir.name)
        self.manager=Manager(self.state,Path(os.environ["XRAY_TEST_BIN"]))
        self.addCleanup(self.cleanup_nodes)

    def cleanup_nodes(self):
        for key in list(self.manager.children): self.manager.stop(key)

    def test_templates_and_links(self):
        # A self-signed certificate is used only to test server configuration.
        key,cert=self.state/"key.pem",self.state/"cert.pem"
        subprocess.run(["openssl","req","-new","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=vps.example",
                        "-keyout",str(key),"-out",str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        links=[]
        for kind in TEMPLATES:
            host = "127.0.0.1" if TEMPLATES[kind].private_only else "vps.example"
            node=self.manager.call("create",{"template":kind,"host":host,"port":free_port(),"name":"测试 "+kind,
                                             "certificate":cert.read_text(),"key":key.read_text(),
                                             "xdrive":{"service":"local","remoteFolder":"qa"}})
            profile=json.loads((self.state/(node["id"]+".json")).read_text())["inbounds"][0]
            self.assertEqual(node["port"],profile["port"])
            self.assertTrue(next(n for n in self.manager.call("list",{}) if n["id"]==node["id"])["running"])
            links.append(node["link"])
            self.assertEqual(urlparse(node["link"]).hostname,host)
            self.manager.call("stop", {"id":node["id"]})
            template = TEMPLATES[kind]
            link = urlparse(node["link"])
            self.assertEqual(link.port, node["port"])
            if template.protocol == "shadowsocks":
                auth = link.username
                decoded = base64.urlsafe_b64decode(auth + "=" * (-len(auth) % 4)).decode()
                self.assertEqual(decoded, template.cipher + ":" + profile["settings"]["password"])
            else:
                params = parse_qs(link.query)
                self.assertEqual(params["type"], [template.network])
                self.assertEqual(params["security"], [template.security])
                account = profile["settings"]["clients"][0]
                if template.protocol == "trojan":
                    self.assertEqual(unquote(link.username), account["password"])
                else:
                    self.assertEqual(link.username, account["id"])
                    self.assertEqual(params.get("flow", [""]), [account.get("flow", "")])
                    self.assertEqual(params["encryption"] == ["none"], not template.needs_encryption)
                if template.h3:
                    self.assertEqual(params["alpn"], ["h3"])
            if TEMPLATES[kind].security=="reality":
                params=parse_qs(urlparse(node["link"]).query)
                self.assertEqual(params["sid"],profile["streamSettings"]["realitySettings"]["shortIds"])
                self.assertNotIn(profile["streamSettings"]["realitySettings"]["privateKey"],node["link"])
        # Optional companion test: use the actual fcxray importer and feed its
        # resulting configs into the actual Xray binary (no external server).
        if os.environ.get("FCXRAY_PACKAGE_CONFIG"):
            results=subprocess.run(["dart","--packages="+os.environ["FCXRAY_PACKAGE_CONFIG"],str(ROOT/"tests/check_links.dart")],
                                   input=json.dumps(links),text=True,capture_output=True,check=True)
            for config in json.loads(results.stdout):
                path=self.state/"client-test.json"; path.write_text(json.dumps(config))
                subprocess.run([str(self.manager.xray),"run","-test","-c",str(path)],stdout=subprocess.DEVNULL,check=True)
        self.assertEqual(self.manager.db.stat().st_mode & 0o777,0o600)

    def test_failure_rollback_and_restart(self):
        port=free_port()
        node=self.manager.call("create",{"template":"ss","host":"vps.example","port":port})
        original=self.manager.db.read_bytes()
        with self.assertRaises(ValueError):
            self.manager.call("create",{"template":"ss","host":"other.example","port":port})
        self.assertEqual(self.manager.db.read_bytes(),original)
        with socket.socket() as s:
            s.bind(("127.0.0.1",0));s.listen()
            with self.assertRaises(ValueError):
                self.manager.call("create",{"template":"ss","host":"vps.example","port":s.getsockname()[1]})
        self.assertEqual(self.manager.db.read_bytes(),original)
        self.manager.stop(node["id"])  # Simulate supervisor restart.
        self.manager=Manager(self.state,self.manager.xray)
        self.manager.reconcile()
        self.assertTrue(self.manager.call("list",{})[0]["running"])
        self.manager.call("stop",{"id":node["id"]})
        self.manager.reconcile()
        self.assertFalse(self.manager.call("list",{})[0]["enabled"])
