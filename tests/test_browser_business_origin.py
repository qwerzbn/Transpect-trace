"""Actual HTTPS origin component tests, not Chrome/eCapture certification."""
import hashlib
import http.client
import json
import ssl

from test_flow_origin import tls_files
from transpect_trace.flow.browser.origin import BrowserOrigin


def test_controlled_page_attachment_upload_and_counted_duplicates(tls_files):
    ca, certificate, key = tls_files
    source = BrowserOrigin(certificate,key).start()
    context = ssl.create_default_context(cafile=str(ca))
    try:
        def get(path):
            connection = http.client.HTTPSConnection('localhost',source.server.server_port,context=context,timeout=4)
            connection.request('GET',path)
            response = connection.getresponse()
            value = response.read()
            connection.close()
            return response.status,value
        assert get('/')[0] == 200
        status, attachment = get('/attachment.txt')
        assert status == 200 and '假数据'.encode() in attachment
        for _ in range(2):
            connection = http.client.HTTPSConnection('localhost',source.server.server_port,context=context,timeout=4)
            connection.request('POST','/upload',attachment,{'Content-Type':'text/plain'})
            response = connection.getresponse()
            receipt = json.loads(response.read())
            assert response.status == 200 and receipt['body_sha256'] == hashlib.sha256(attachment).hexdigest()
            connection.close()
        assert len(source.receipts) == 2
        assert source.receipts[0]['receipt_id'] != source.receipts[1]['receipt_id']
        assert 'browser_fixture_secret' not in json.dumps(source.receipts)
        assert source.errors == []
    finally: source.close()


def test_origin_will_not_forward_arbitrary_destination(tls_files):
    ca, certificate, key = tls_files
    source = BrowserOrigin(certificate,key).start()
    try:
        connection = http.client.HTTPSConnection('localhost',source.server.server_port,
            context=ssl.create_default_context(cafile=str(ca)),timeout=4)
        connection.request('GET','https://example.com/secret')
        response = connection.getresponse()
        assert response.status == 404
        response.read(); connection.close()
        assert source.receipts == []
    finally: source.close()
