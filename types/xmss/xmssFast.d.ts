/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} node
 * @param {Uint32Array[number]} index
 * @param {BDSState} bdsState
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function treeHashSetup(hashFunction: HashFunction, node: Uint8Array, index: Uint32Array[number], bdsState: BDSState, skSeed: Uint8Array, xmssParams: XMSSParams, pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} seed
 */
export function XMSSFastGenKeyPair(hashFunction: HashFunction, xmssParams: XMSSParams, pk: Uint8Array, sk: Uint8Array, bdsState: BDSState, seed: Uint8Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} params
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} newIdx
 * @returns {Uint32Array[number]}
 */
export function xmssFastUpdate(hashFunction: HashFunction, params: XMSSParams, sk: Uint8Array, bdsState: BDSState, newIdx: Uint32Array[number]): Uint32Array[number];
//# sourceMappingURL=xmssFast.d.ts.map