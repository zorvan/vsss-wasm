/* tslint:disable */
/* eslint-disable */
/**
* @returns {Uint8Array}
*/
export function generate_secret(): Uint8Array;
/**
* @param {Uint8Array} secret
* @returns {Uint8Array}
*/
export function split_secret(secret: Uint8Array): Uint8Array;
/**
* @param {Uint8Array} share_bytes
* @param {Uint8Array} verifier_bytes
* @returns {boolean}
*/
export function verify_secret(share_bytes: Uint8Array, verifier_bytes: Uint8Array): boolean;
/**
* @param {Uint8Array} share_bytes
* @returns {Uint8Array}
*/
export function combine_secret(share_bytes: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly generate_secret: (a: number) => void;
  readonly split_secret: (a: number, b: number, c: number) => void;
  readonly verify_secret: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly combine_secret: (a: number, b: number, c: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number) => void;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
