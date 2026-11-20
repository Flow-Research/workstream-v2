// No signer, automatic submission, credential persistence, or background retry.
const send = document.querySelector('#send');
const result = document.querySelector('#result');
async function post(path, options = {}) {
  return fetch(path, {method: 'POST', credentials: 'omit', redirect: 'error', ...options});
}
send.addEventListener('click', async () => {
  send.disabled = true;
  try {
    const file = document.querySelector('#signed').files[0];
    if (!file || file.size > 64 * 1024) throw Error('Select a signed transaction file of at most 64 KiB.');
    const bytes = new Uint8Array(await file.arrayBuffer());
    const tx = JSON.parse(new TextDecoder().decode(bytes));
    if (!Array.isArray(tx.actions) || !Array.isArray(tx.signature) || !Array.isArray(tx.public_key)) throw Error('Expected signed transaction JSON.');
    const digest = document.querySelector('#digest').textContent;
    const checked = await post(`/sponsor/check/${digest}`, {body: bytes});
    if (!checked.ok) throw Error('Invalid signature or different draft. Review again.');
    const hash = await checked.text();
    if (!/^0x[0-9a-f]{64}$/.test(hash)) throw Error('Invalid transaction identifier.');
    const link = document.createElement('a');
    link.href = `/explorer?kind=receipt&key=${hash}`;
    link.textContent = `Receipt ${hash}`;
    result.replaceChildren(link);
    const session = await post('/v1/session');
    if (!session.ok) throw Error('Session unavailable.');
    const token = (await session.json()).data.token;
    const response = await post('/v1/submit', {headers: {'Content-Type':'application/json', Authorization:`Bearer ${token}`, 'X-Request-Id':hash}, body:JSON.stringify({version:1, api_version:1, tx_bytes:Array.from(bytes)})});
    if (!response.ok || (await response.json()).data?.tx_hash !== hash) throw Error('Admission unconfirmed. Check the receipt before retrying with the same file.');
    location.assign(link.href);
  } catch (error) {
    result.append(document.createTextNode(` ${error instanceof SyntaxError ? 'Invalid JSON file.' : error.message}`));
    send.disabled = false;
  }
});
