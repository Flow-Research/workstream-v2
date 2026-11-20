"""Tiny in-repo S3-compatible provider used by the object-DA drill.

It verifies AWS Signature Version 4, enforces conditional PUT, and persists
objects so an outage/restart exercises restore access from the provider rather
than producer-local state. It is a test fixture, not a production S3 server.
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIGNED_HEADERS = 'host;x-amz-content-sha256;x-amz-date'
ACCESS_KEY = os.environ.get('MOCK_S3_ACCESS_KEY', 'test-key')
SECRET_KEY = os.environ.get('MOCK_S3_SECRET_KEY', 'test-secret').encode()
DB = Path(sys.argv[2])
LOCK = threading.Lock()
OBJECTS = json.loads(DB.read_text()) if DB.exists() else {}


def persist():
    tmp = DB.with_suffix('.tmp')
    tmp.write_text(json.dumps(OBJECTS))
    os.replace(tmp, DB)


def hmac_sha(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def header_map(self):
        return {name.lower(): value for name, value in self.headers.items()}

    def reply(self, status, body=b''):
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if body:
            self.wfile.write(body)

    def verify(self, body):
        headers = self.header_map()
        amz = headers.get('x-amz-date', '')
        payload = headers.get('x-amz-content-sha256', '')
        if len(amz) != 16 or hashlib.sha256(body).hexdigest() != payload:
            return False
        if headers.get('x-amz-content-sha256') != payload:
            return False
        auth = headers.get('authorization', '')
        if not auth.startswith('AWS4-HMAC-SHA256 '):
            return False
        parts = {}
        for field in auth[len('AWS4-HMAC-SHA256 '):].split(', '):
            if '=' in field:
                key, value = field.split('=', 1)
                parts[key] = value
        if parts.get('SignedHeaders') != SIGNED_HEADERS:
            return False
        credential = parts.get('Credential', '').split('/')
        if len(credential) != 5 or credential[0] != ACCESS_KEY:
            return False
        access, date, region, service, terminal = credential
        if (service, terminal) != ('s3', 'aws4_request') or date != amz[:8]:
            return False
        canonical = (
            f'{self.command}\n{self.path}\n\n'
            f'host:{headers.get("host", "")}\n'
            f'x-amz-content-sha256:{payload}\n'
            f'x-amz-date:{amz}\n\n'
            f'{SIGNED_HEADERS}\n{payload}'
        )
        scope = f'{date}/{region}/s3/aws4_request'
        to_sign = (
            f'AWS4-HMAC-SHA256\n{amz}\n{scope}\n'
            f'{hashlib.sha256(canonical.encode()).hexdigest()}'
        )
        key = hmac_sha(b'AWS4' + SECRET_KEY, date.encode())
        key = hmac_sha(key, region.encode())
        key = hmac_sha(key, b's3')
        key = hmac_sha(key, b'aws4_request')
        expected = hmac_sha(key, to_sign.encode()).hex()
        return hmac.compare_digest(expected, parts.get('Signature', ''))

    def body(self):
        length = int(self.header_map().get('content-length', '0'))
        if length > (32 << 20):
            raise ValueError('request too large')
        return self.rfile.read(length)

    def do_PUT(self):
        raw = self.body()
        if not self.verify(raw):
            return self.reply(403, b'bad signature')
        with LOCK:
            if self.header_map().get('if-none-match') == '*' and self.path in OBJECTS:
                return self.reply(412)
            OBJECTS[self.path] = base64.b64encode(raw).decode()
            persist()
        self.reply(204)

    def do_GET(self):
        if not self.verify(b''):
            return self.reply(403, b'bad signature')
        with LOCK:
            raw = base64.b64decode(OBJECTS[self.path]) if self.path in OBJECTS else None
        if raw is None:
            return self.reply(404)
        self.reply(200, raw)

    def do_HEAD(self):
        if not self.verify(b''):
            return self.reply(403, b'bad signature')
        self.reply(200)


if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), Handler)
    server.serve_forever()
