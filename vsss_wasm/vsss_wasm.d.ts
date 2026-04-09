export function generatesecret(): Uint8Array;
export function combinesecret(sharebytes: Uint8Array): Uint8Array;
export function splitsecret(secret: Uint8Array): Uint8Array;
export function verifysecret(sharebytes: Uint8Array, verifybytes: Uint8Array): boolean;
