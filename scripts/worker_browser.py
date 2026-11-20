"""Optional headless browser leg of the connected projection drill."""
import hashlib
import json
import re
import sqlite3
import time
from playwright.sync_api import sync_playwright, expect


def exercise(port, private, token, signed, verified):
    origin = f'https://127.0.0.1:{port}'
    evidence = b'worker browser drill evidence'
    digest = hashlib.sha256(evidence).hexdigest()
    account = bytes(signed[0]['account']).hex()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        # Disposable local origin; the dev certificate names the node service.
        page = browser.new_page(ignore_https_errors=True)
        page.goto(origin + '/worker')
        page.fill('#account', account)
        page.click('#find')
        page.get_by_role('button', name='task.released', exact=False).click()
        task = page.input_value('#task')
        for idx, (stage, fixture) in enumerate(zip(('claim','start','bundle','submit'), signed)):
            if idx == 2:
                with sqlite3.connect(private / 'objects.sqlite') as db:
                    db.execute("INSERT INTO grants VALUES(?,?,?,'upload')", ('pilot',task,digest))
                    db.execute('INSERT INTO upload_deadlines VALUES(?,?,?,unixepoch()-1)', ('pilot',task,digest))
                page.fill('#token',token)
                page.set_input_files('#file', {'name':'evidence.bin','mimeType':'application/octet-stream','buffer': evidence})
                expect(page.locator('#content')).to_have_text(digest)
                page.route('**/upload',lambda route:route.abort('connectionreset'))
                page.click('#upload'); expect(page.locator('#uploadState')).to_contain_text('interrupted')
                page.unroute('**/upload'); page.click('#upload')
                expect(page.locator('#uploadState')).to_contain_text('lease expired')
                with sqlite3.connect(private / 'objects.sqlite') as db:
                    db.execute('UPDATE upload_deadlines SET expires=unixepoch()+60')
                page.click('#upload'); expect(page.locator('#uploadState')).to_contain_text('Uploaded')
                page.reload(); expect(page.locator('#uploadState')).to_contain_text('restored acknowledgment')
                assert page.input_value('#task') == task and page.input_value('#token') == ''
            page.select_option('#action',stage); page.fill('#nonce',str(fixture['nonce']['seq']))
            page.click('#preview'); expect(page.locator('#digest')).to_have_text(re.compile('0x[0-9a-f]{64}'))
            # The file is independently signed; the UI verifies the exact preview before forwarding.
            page.set_input_files('#signed', {'name':'signed.json','mimeType':'application/json','buffer':json.dumps(fixture).encode()})
            page.click('#send'); page.wait_for_url('**/explorer?kind=receipt*')
            for _ in range(80):
                if page.locator('strong').inner_text()=='Verified': break
                time.sleep(.1); page.reload()
            expect(page.locator('strong')).to_have_text('Verified')
            assert verified()['height'] == 12 + idx
            page.goto(origin + '/worker')
        browser.close()
    print('Chromium: claim, start, bundle and evidence submission verified; interrupted upload, expired lease, renewal and draft recovery passed', flush=True)
