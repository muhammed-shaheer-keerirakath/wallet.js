/**
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @param {SignatureType} signatureType
 * @param {AddrFormatType} addrFormatType
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptor(height: Uint8Array[number], hashFunction: HashFunction, signatureType: SignatureType, addrFormatType: AddrFormatType): QRLDescriptor;
/**
 * @param {Uint8Array} descriptorBytes
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptorFromBytes(descriptorBytes: Uint8Array): QRLDescriptor;
/**
 * @param {Uint8Array} extendedSeed
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptorFromExtendedSeed(extendedSeed: Uint8Array): QRLDescriptor;
/**
 * @param {Uint8Array} extendedPk
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptorFromExtendedPk(extendedPk: Uint8Array): QRLDescriptor;
export class QRLDescriptor {
    constructor(hashFunction: any, signatureType: any, height: any, addrFormatType: any);
    /** @returns {Uint8Array[number]} */
    getHeight(): Uint8Array[number];
    /** @returns {HashFunction} */
    getHashFunction(): HashFunction;
    /** @returns {SignatureType} */
    getSignatureType(): SignatureType;
    /** @returns {AddrFormatType} */
    getAddrFormatType(): AddrFormatType;
    /** @returns {Uint8Array} */
    getBytes(): Uint8Array;
    hashFunction: any;
    signatureType: any;
    height: any;
    addrFormatType: any;
}
//# sourceMappingURL=classes.d.ts.map