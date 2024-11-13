import { newWOTSParams } from '@theqrl/qrypto.js/classes';
import { COMMON, CONSTANTS } from './constants.js';

class XMSSParamsClass {
  constructor(n, h, w, k) {
    this.wotsParams = newWOTSParams(n, w);
    this.n = n;
    this.h = h;
    this.k = k;
  }
}

/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} h
 * @param {Uint32Array[number]} w
 * @param {Uint32Array[number]} k
 * @returns {XMSSParams}
 */
export function newXMSSParams(n, h, w, k) {
  return new XMSSParamsClass(n, h, w, k);
}

class QRLDescriptorClass {
  /** @returns {Uint8Array[number]} */
  getHeight() {
    return this.height;
  }

  /** @returns {HashFunction} */
  getHashFunction() {
    return this.hashFunction;
  }

  /** @returns {SignatureType} */
  getSignatureType() {
    return this.signatureType;
  }

  /** @returns {AddrFormatType} */
  getAddrFormatType() {
    return this.addrFormatType;
  }

  /** @returns {Uint8Array} */
  getBytes() {
    const output = new Uint8Array(COMMON.DESCRIPTOR_SIZE);
    output.set([(this.signatureType << 4) | (this.hashFunction & 0x0f)], 0);
    output.set([(this.addrFormatType << 4) | ((this.height >>> 1) & 0x0f)], 1);
    return output;
  }

  constructor(hashFunction, signatureType, height, addrFormatType) {
    this.hashFunction = hashFunction;
    this.signatureType = signatureType;
    this.height = height;
    this.addrFormatType = addrFormatType;
  }
}

/**
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @param {SignatureType} signatureType
 * @param {AddrFormatType} addrFormatType
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptor(height, hashFunction, signatureType, addrFormatType) {
  return new QRLDescriptorClass(hashFunction, signatureType, height, addrFormatType);
}

/**
 * @param {Uint8Array} descriptorBytes
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptorFromBytes(descriptorBytes) {
  if (descriptorBytes.length !== 3) {
    throw new Error('Descriptor size should be 3 bytes');
  }

  return new QRLDescriptorClass(
    descriptorBytes[0] & 0x0f,
    (descriptorBytes[0] >>> 4) & 0x0f,
    (descriptorBytes[1] & 0x0f) << 1,
    (descriptorBytes[1] & 0xf0) >>> 4
  );
}

/**
 * @param {Uint8Array} extendedSeed
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptorFromExtendedSeed(extendedSeed) {
  if (extendedSeed.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error(`extendedSeed should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`);
  }

  return newQRLDescriptorFromBytes(extendedSeed.subarray(0, COMMON.DESCRIPTOR_SIZE));
}

/**
 * @param {Uint8Array} extendedPk
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptorFromExtendedPk(extendedPk) {
  if (extendedPk.length !== CONSTANTS.EXTENDED_PK_SIZE) {
    throw new Error(`extendedPk should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`);
  }

  return newQRLDescriptorFromBytes(extendedPk.subarray(0, COMMON.DESCRIPTOR_SIZE));
}
