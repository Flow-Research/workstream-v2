"""Independent browser profile and workspace subject, against real TLS services."""
import hashlib
import json
import re
import sqlite3
import time
from playwright.sync_api import sync_playwright, expect


def exercise_review(port, private, token, fixtures):
    origin = f'https://127.0.0.1:{port}'
    reviewer = bytes(fixtures[15]['account']).hex()
    case = bytes(fixtures[15]['actions'][0]['payload']).hex()
    task = bytes(fixtures[11]['actions'][0]['payload']).hex()
    digest = hashlib.sha256(b'worker browser drill evidence').hexdigest()
    with sqlite3.connect(private / 'objects.sqlite') as db:
        db.execute("INSERT INTO grants VALUES(?,?,?,'read')", ('independent-reviewer',task,digest))
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        url = origin + '/review?submission=' + case
        page.goto(url)
        expect(page.locator('#facts')).to_contain_text(digest)
        for index, reason in [(1, 'author'), (0, 'sponsor')]:
            page.fill('#account', bytes(fixtures[index]['account']).hex())
            expect(page.locator('#role')).to_contain_text('Conflict: '+('submission author' if reason=='author' else 'task sponsor'))
        for stage, fixture in zip(('lease','Accept'), fixtures[15:17]):
            page.goto(url)
            for attempt in range(2 if stage=='Accept' else 1):
                expect(page.locator('#facts')).to_contain_text(digest)
                page.fill('#account',reviewer);page.select_option('#action',stage)
                page.fill('#nonce',str(fixture['nonce']['seq']))
                if stage=='Accept':
                    page.fill('#token',token);page.click('#verify')
                    expect(page.locator('#evidence')).to_have_text('Verified evidence digest')
                page.click('#preview');expect(page.locator('#digest')).to_have_text(re.compile('0x[0-9a-f]{64}'))
                if stage=='Accept' and attempt==0:
                    approved=page.locator('#digest').inner_text(); page.reload()
                    expect(page.locator('#send')).to_be_disabled()
                elif stage=='Accept': assert page.locator('#digest').inner_text()==approved
            page.set_input_files('#signed',{'name':'review.json','mimeType':'application/json','buffer':json.dumps(fixture).encode()})
            with page.expect_response(lambda r:r.url.endswith('/v1/submit')) as submitted:
                page.click('#send')
            first=submitted.value
            page.wait_for_url('**/explorer?kind=receipt*')
            if stage=='Accept':
                replay=page.request.post(first.url,headers=first.request.all_headers(),data=first.request.post_data_buffer)
                decision_url=page.url
                assert replay.ok and decision_url.endswith(replay.json()['data']['tx_hash'])
            for _ in range(80):
                if page.locator('strong').inner_text()=='Verified': break
                time.sleep(.1);page.reload()
            expect(page.locator('strong')).to_have_text('Verified')
        page.goto(url)
        decision=page.locator('#history a').filter(has_text='Accept')
        expect(decision).to_have_count(1)
        assert decision_url.endswith(decision.get_attribute('href')) or decision_url.replace('key=0x','key=').endswith(decision.get_attribute('href'))
        browser.close()
    print('Chromium: author/sponsor conflicts shown; independent reviewer verified evidence, resumed signing and obtained one decision receipt after duplicate delivery',flush=True)
