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
