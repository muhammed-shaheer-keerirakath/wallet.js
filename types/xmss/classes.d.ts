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
//# sourceMappingURL=classes.d.ts.map