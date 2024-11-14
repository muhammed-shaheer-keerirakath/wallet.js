/**
 * @param {Uint8Array} ePK
 * @returns {Uint8Array}
 */
export function getXMSSAddressFromPK(ePK: Uint8Array): Uint8Array;
/**
 * @param {XMSSParams} xmssParams
 * @param {HashFunction} hashFunction
 * @param {Uint8Array[number]} height
 * @param {Uint8Array} sk
 * @param {Uint8Array} seed
 * @param {BDSState} bdsState
 * @param {QRLDescriptor} desc
 * @returns {XMSS}
 */
export function newXMSS(xmssParams: XMSSParams, hashFunction: HashFunction, height: Uint8Array[number], sk: Uint8Array, seed: Uint8Array, bdsState: BDSState, desc: QRLDescriptor): XMSS;
/**
 * @param {QRLDescriptor} desc
 * @param {Uint8Array} seed
 * @returns {XMSS}
 */
export function initializeTree(desc: QRLDescriptor, seed: Uint8Array): XMSS;
/**
 * @param {Uint8Array} seed
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @param {AddrFormatType} addrFormatType
 * @returns {XMSS}
 */
export function newXMSSFromSeed(seed: Uint8Array, height: Uint8Array[number], hashFunction: HashFunction, addrFormatType: AddrFormatType): XMSS;
/**
 * @param {Uint8Array} extendedSeed
 * @returns {XMSS}
 */
export function newXMSSFromExtendedSeed(extendedSeed: Uint8Array): XMSS;
/**
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @returns {XMSS}
 */
export function newXMSSFromHeight(height: Uint8Array[number], hashFunction: HashFunction): XMSS;
/**
 * @param {Uint32Array[number]} sigSize
 * @param {Uint32Array[number]} wotsParamW
 * @returns {Uint32Array[number]}
 */
export function getHeightFromSigSize(sigSize: Uint32Array[number], wotsParamW: Uint32Array[number]): Uint32Array[number];
/**
 * @param {Uint8Array} address
 * @returns {boolean}
 */
export function isValidXMSSAddress(address: Uint8Array): boolean;
/**
 * @param {HashFunction} hashfunction
 * @param {Uint8Array} pk
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @param {WOTSParams} wotsParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function wotsPKFromSig(hashfunction: HashFunction, pk: Uint8Array, sig: Uint8Array, msg: Uint8Array, wotsParams: WOTSParams, pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} root
 * @param {Uint8Array} leaf
 * @param {Uint32Array[number]} leafIdx
 * @param {Uint8Array} authpath
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} h
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function validateAuthPath(hashFunction: HashFunction, root: Uint8Array, leaf: Uint8Array, leafIdx: Uint32Array[number], authpath: Uint8Array, n: Uint32Array[number], h: Uint32Array[number], pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {WOTSParams} wotsParams
 * @param {Uint8Array} msg
 * @param {Uint8Array} sigMsg
 * @param {Uint8Array} pk
 * @param {Uint32Array[number]} h
 * @returns {boolean}
 */
export function xmssVerifySig(hashFunction: HashFunction, wotsParams: WOTSParams, msg: Uint8Array, sigMsg: Uint8Array, pk: Uint8Array, h: Uint32Array[number]): boolean;
/**
 * @param {Uint8Array} message
 * @param {Uint8Array} signature
 * @param {Uint8Array} extendedPK
 * @param {Uint32Array[number]} wotsParamW
 * @returns {boolean}
 */
export function verifyWithCustomWOTSParamW(message: Uint8Array, signature: Uint8Array, extendedPK: Uint8Array, wotsParamW: Uint32Array[number]): boolean;
/**
 * @param {Uint8Array} message
 * @param {Uint8Array} signature
 * @param {Uint8Array} extendedPK
 * @returns {boolean}
 */
export function verify(message: Uint8Array, signature: Uint8Array, extendedPK: Uint8Array): boolean;
//# sourceMappingURL=xmss.d.ts.map