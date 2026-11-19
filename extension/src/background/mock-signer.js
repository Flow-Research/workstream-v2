// Placeholder signing capability for issue 3 (#148). It is replaced only when
// #130/#131 land and the real vault (#174) is available. It never leaves the
// service worker and produces no key material.
export function createMockSigner() {
  return async function sign(request) {
    return {
      signature: `mock-signature:${request.id}`,
      account: request.account,
    };
  };
}
