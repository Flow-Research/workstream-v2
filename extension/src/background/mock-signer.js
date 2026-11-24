// Placeholder signing capability for issue 3 (#148). It is replaced only when
// the real vault (#174) is available. It never leaves the service worker and
// produces no key material. The mock transaction bytes/hash let the #175
// tracker exercise the API contract without pretending to be real signing.
export function createMockSigner() {
  return async function sign(request) {
    const signature = `mock-signature:${request.id}`;
    const txBytes = Array.from(
      new TextEncoder().encode(
        JSON.stringify({ id: request.id, account: request.account, method: request.method, params: request.params ?? {}, signature }),
      ),
    );
    return {
      signature,
      account: request.account,
      txBytes,
      txHash: `mock-tx:${encodeURIComponent(request.id)}`,
    };
  };
}
