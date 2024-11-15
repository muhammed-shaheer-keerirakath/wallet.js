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
 * @param {Uint8Array} address
 * @returns {boolean}
 */
export function isValidXMSSAddress(address: Uint8Array): boolean;
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
export class XMSS {
    /**
     * @param {XMSSParams} xmssParams
     * @param {HashFunction} hashFunction
     * @param {Uint8Array[number]} height
     * @param {Uint8Array} sk
     * @param {Uint8Array} seed
     * @param {BDSState} bdsState
     * @param {QRLDescriptor} desc
     */
    constructor(xmssParams: XMSSParams, hashFunction: HashFunction, height: Uint8Array[number], sk: Uint8Array, seed: Uint8Array, bdsState: BDSState, desc: QRLDescriptor);
    /**
     * @param {Uint32Array[number]} newIndex
     * @returns {void}
     */
    setIndex(newIndex: Uint32Array[number]): void;
    /** @returns {Uint8Array[number]} */
    getHeight(): Uint8Array[number];
    /** @returns {Uint8Array} */
    getPKSeed(): Uint8Array;
    /** @returns {Uint8Array} */
    getSeed(): Uint8Array;
    /** @returns {Uint8Array} */
    getExtendedSeed(): Uint8Array;
    /** @returns {string} */
    getHexSeed(): string;
    /** @returns {string} */
    getMnemonic(): string;
    /** @returns {Uint8Array} */
    getRoot(): Uint8Array;
    /** @returns {Uint8Array} */
    getPK(): Uint8Array;
    /** @returns {Uint8Array} */
    getSK(): Uint8Array;
    /** @returns {Uint8Array} */
    getAddress(): Uint8Array;
    /** @returns {Uint32Array[number]} */
    getIndex(): Uint32Array[number];
    /**
     * @param {Uint8Array} message
     * @returns {SignatureReturnType}
     */
    sign(message: Uint8Array): SignatureReturnType;
    xmssParams: XMSSParams;
    hashFunction: number;
    height: number;
    sk: Uint8Array;
    seed: Uint8Array;
    bdsState: BDSState;
    desc: QRLDescriptor;
}
//# sourceMappingURL=xmss.d.ts.map