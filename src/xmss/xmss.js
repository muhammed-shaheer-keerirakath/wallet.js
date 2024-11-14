/// <reference path="typedefs.js" />

import { randomBytes } from '@noble/hashes/utils';
import {
  newBDSState,
  newQRLDescriptor,
  newQRLDescriptorFromBytes,
  newQRLDescriptorFromExtendedPk,
  newQRLDescriptorFromExtendedSeed,
  newWOTSParams,
  newXMSSParams,
} from './classes.js';
import { COMMON, CONSTANTS, OFFSET_PUB_SEED, OFFSET_ROOT, WOTS_PARAM } from './constants.js';
import { hashH } from './hash.js';
import {
  extendedSeedBinToMnemonic,
  setChainAddr,
  setLTreeAddr,
  setOTSAddr,
  setTreeHeight,
  setTreeIndex,
  setType,
  shake256,
  toByteLittleEndian,
} from './helper.js';
import { XMSSFastGenKeyPair, xmssFastUpdate } from './xmssFast.js';

/**
 * @param {Uint8Array} ePK
 * @returns {Uint8Array}
 */
export function getXMSSAddressFromPK(ePK) {
  const desc = newQRLDescriptorFromExtendedPk(ePK);

  if (desc.getAddrFormatType() !== COMMON.SHA256_2X) {
    throw new Error('Address format type not supported');
  }

  const address = new Uint8Array(COMMON.ADDRESS_SIZE);
  const descBytes = desc.getBytes();

  for (
    let addressIndex = 0, descBytesIndex = 0;
    addressIndex < COMMON.DESCRIPTOR_SIZE && descBytesIndex < descBytes.length;
    addressIndex++, descBytesIndex++
  ) {
    address.set([descBytes[descBytesIndex]], addressIndex);
  }

  const hashedKey = new Uint8Array(32);
  shake256(hashedKey, ePK);

  for (
    let addressIndex = COMMON.DESCRIPTOR_SIZE,
      hashedKeyIndex = hashedKey.length - COMMON.ADDRESS_SIZE + COMMON.DESCRIPTOR_SIZE;
    addressIndex < address.length && hashedKeyIndex < hashedKey.length;
    addressIndex++, hashedKeyIndex++
  ) {
    address.set([hashedKey[hashedKeyIndex]], addressIndex);
  }

  return address;
}

class XMSSClass {
  /**
   * @param {Uint32Array[number]} newIndex
   * @returns {void}
   */
  setIndex(newIndex) {
    xmssFastUpdate(this.hashFunction, this.xmssParams, this.sk, this.bdsState, newIndex);
  }

  /** @returns {Uint8Array[number]} */
  getHeight() {
    return this.height;
  }

  /** @returns {Uint8Array} */
  getPKSeed() {
    return this.sk.subarray(OFFSET_PUB_SEED, OFFSET_PUB_SEED + 32);
  }

  /** @returns {Uint8Array} */
  getSeed() {
    return this.seed;
  }

  /** @returns {Uint8Array} */
  getExtendedSeed() {
    const extendedSeed = new Uint8Array(COMMON.EXTENDED_SEED_SIZE);
    const descBytes = this.desc.getBytes();
    const seed = this.getSeed();
    for (
      let extSeedIndex = 0, bytesIndex = 0;
      extSeedIndex < 3 && bytesIndex < descBytes.length;
      extSeedIndex++, bytesIndex++
    ) {
      extendedSeed.set([descBytes[bytesIndex]], extSeedIndex);
    }
    for (
      let extSeedIndex = 3, seedIndex = 0;
      extSeedIndex < extendedSeed.length && seedIndex < seed.length;
      extSeedIndex++, seedIndex++
    ) {
      extendedSeed.set([seed[seedIndex]], extSeedIndex);
    }

    return extendedSeed;
  }

  /** @returns {string} */
  getHexSeed() {
    const eSeed = this.getExtendedSeed();

    return `0x${Array.from(eSeed)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')}`;
  }

  /** @returns {string} */
  getMnemonic() {
    return extendedSeedBinToMnemonic(this.getExtendedSeed());
  }

  /** @returns {Uint8Array} */
  getRoot() {
    return this.sk.subarray(OFFSET_ROOT, OFFSET_ROOT + 32);
  }

  /** @returns {Uint8Array} */
  getPK() {
    const desc = this.desc.getBytes();
    const root = this.getRoot();
    const pubSeed = this.getPKSeed();

    const output = new Uint8Array(CONSTANTS.EXTENDED_PK_SIZE);
    let offset = 0;
    for (let i = 0; i < desc.length; i++) {
      output.set([desc[i]], i);
    }
    offset += desc.length;
    for (let i = 0; i < root.length; i++) {
      output.set([root[i]], offset + i);
    }
    offset += root.length;
    for (let i = 0; i < pubSeed.length; i++) {
      output.set([pubSeed[i]], offset + i);
    }

    return output;
  }

  /** @returns {Uint8Array} */
  getSK() {
    return this.sk;
  }

  /** @returns {Uint8Array} */
  getAddress() {
    return getXMSSAddressFromPK(this.getPK());
  }

  /** @returns {Uint32Array[number]} */
  getIndex() {
    return (
      (new Uint32Array([this.sk[0]])[0] << 24) +
      (new Uint32Array([this.sk[1]])[0] << 16) +
      (new Uint32Array([this.sk[2]])[0] << 8) +
      new Uint32Array([this.sk[3]])[0]
    );
  }

  /**
   * @param {Uint8Array} message
   * @returns {SignatureReturnType}
   */
  sign(message) {
    const index = this.getIndex();
    this.setIndex(index);

    return xmssFastSignMessage(this.hashFunction, this.xmssParams, this.sk, this.bdsState, message);
  }

  /**
   * @param {XMSSParams} xmssParams
   * @param {HashFunction} hashFunction
   * @param {Uint8Array[number]} height
   * @param {Uint8Array} sk
   * @param {Uint8Array} seed
   * @param {BDSState} bdsState
   * @param {QRLDescriptor} desc
   */
  constructor(xmssParams, hashFunction, height, sk, seed, bdsState, desc) {
    if (seed.length !== COMMON.SEED_SIZE) {
      throw new Error(`seed should be an array of size ${COMMON.SEED_SIZE}`);
    }

    this.xmssParams = xmssParams;
    this.hashFunction = hashFunction;
    this.height = height;
    this.sk = sk;
    this.seed = seed;
    this.bdsState = bdsState;
    this.desc = desc;
  }
}

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
export function newXMSS(xmssParams, hashFunction, height, sk, seed, bdsState, desc) {
  return new XMSSClass(xmssParams, hashFunction, height, sk, seed, bdsState, desc);
}

/**
 * @param {QRLDescriptor} desc
 * @param {Uint8Array} seed
 * @returns {XMSS}
 */
export function initializeTree(desc, seed) {
  if (seed.length !== COMMON.SEED_SIZE) {
    throw new Error(`seed should be an array of size ${COMMON.SEED_SIZE}`);
  }

  const [height] = new Uint32Array([desc.getHeight()]);
  const hashFunction = desc.getHashFunction();
  const sk = new Uint8Array(132);
  const pk = new Uint8Array(64);

  const k = WOTS_PARAM.K;
  const w = WOTS_PARAM.W;
  const n = WOTS_PARAM.N;

  if (k >= height || (height - k) % 2 === 1) {
    throw new Error('For BDS traversal, H - K must be even, with H > K >= 2!');
  }

  const xmssParams = newXMSSParams(n, height, w, k);
  const bdsState = newBDSState(height, n, k);
  XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed);

  return newXMSS(xmssParams, hashFunction, height, sk, seed, bdsState, desc);
}

/**
 * @param {Uint8Array} seed
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @param {AddrFormatType} addrFormatType
 * @returns {XMSS}
 */
export function newXMSSFromSeed(seed, height, hashFunction, addrFormatType) {
  if (seed.length !== COMMON.SEED_SIZE) {
    throw new Error(`seed should be an array of size ${COMMON.SEED_SIZE}`);
  }

  const signatureType = COMMON.XMSS_SIG;
  if (height > CONSTANTS.MAX_HEIGHT) {
    throw new Error('Height should be <= 254');
  }
  const desc = newQRLDescriptor(height, hashFunction, signatureType, addrFormatType);

  return initializeTree(desc, seed);
}

/**
 * @param {Uint8Array} extendedSeed
 * @returns {XMSS}
 */
export function newXMSSFromExtendedSeed(extendedSeed) {
  if (extendedSeed.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error(`extendedSeed should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`);
  }

  const desc = newQRLDescriptorFromExtendedSeed(extendedSeed);
  const seed = new Uint8Array(COMMON.SEED_SIZE);
  seed.set(extendedSeed.subarray(COMMON.DESCRIPTOR_SIZE));

  return initializeTree(desc, seed);
}

/**
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @returns {XMSS}
 */
export function newXMSSFromHeight(height, hashFunction) {
  const seed = randomBytes(COMMON.SEED_SIZE);

  return newXMSSFromSeed(seed, height, hashFunction, COMMON.SHA256_2X);
}

/**
 * @param {Uint32Array[number]} sigSize
 * @param {Uint32Array[number]} wotsParamW
 * @returns {Uint32Array[number]}
 */
export function getHeightFromSigSize(sigSize, wotsParamW) {
  const wotsParam = newWOTSParams(WOTS_PARAM.N, wotsParamW);
  const signatureBaseSize = calculateSignatureBaseSize(wotsParam.keySize);
  if (sigSize < signatureBaseSize) {
    throw new Error('Invalid signature size');
  }

  if ((sigSize - 4) % 32 !== 0) {
    throw new Error('Invalid signature size');
  }

  return new Uint32Array([(sigSize - signatureBaseSize) / 32])[0];
}

/**
 * @param {Uint8Array} address
 * @returns {boolean}
 */
export function isValidXMSSAddress(address) {
  if (address.length !== COMMON.ADDRESS_SIZE) {
    throw new Error(`address should be an array of size ${COMMON.ADDRESS_SIZE}`);
  }

  const d = newQRLDescriptorFromBytes(address.subarray(0, COMMON.DESCRIPTOR_SIZE));
  if (d.getSignatureType() !== COMMON.XMSS_SIG) {
    return false;
  }
  if (d.getAddrFormatType() !== COMMON.SHA256_2X) {
    return false;
  }

  return true;
}

/**
 * @param {HashFunction} hashfunction
 * @param {Uint8Array} pk
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @param {WOTSParams} wotsParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function wotsPKFromSig(hashfunction, pk, sig, msg, wotsParams, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const {
    len: XMSSWOTSLEN,
    len1: XMSSWOTSLEN1,
    len2: XMSSWOTSLEN2,
    logW: XMSSWOTSLOGW,
    w: XMSSWOTSW,
    n: XMSSN,
  } = wotsParams;

  const baseW = new Uint8Array(XMSSWOTSLEN);
  let cSum = new Uint32Array([0])[0];
  const cSumBytes = new Uint8Array((XMSSWOTSLEN2 * XMSSWOTSLOGW + 7) / 8);
  const cSumBaseW = new Uint8Array(XMSSWOTSLEN2);

  calcBaseW(baseW, XMSSWOTSLEN1, msg, wotsParams);

  for (let i = 0; i < XMSSWOTSLEN1; i++) {
    cSum += XMSSWOTSW - 1 - new Uint32Array([baseW[i]])[0];
  }

  cSum <<= 8 - ((XMSSWOTSLEN2 * XMSSWOTSLOGW) % 8);

  toByteLittleEndian(cSumBytes, cSum, (XMSSWOTSLEN2 * XMSSWOTSLOGW + 7) / 8);
  calcBaseW(cSumBaseW, XMSSWOTSLEN2, cSumBytes, wotsParams);

  for (let i = 0; i < XMSSWOTSLEN2; i++) {
    baseW.set([cSumBaseW[i]], XMSSWOTSLEN1 + i);
  }
  for (let i = 0; i < XMSSWOTSLEN; i++) {
    setChainAddr(addr, i);
    const offset = i * XMSSN;
    genChain(
      hashfunction,
      pk.subarray(offset, offset + XMSSN),
      sig.subarray(offset, offset + XMSSN),
      new Uint32Array([baseW[i]])[0],
      XMSSWOTSW - 1 - new Uint32Array([baseW[i]])[0],
      wotsParams,
      pubSeed,
      addr
    );
  }
}

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
export function validateAuthPath(hashFunction, root, leaf, leafIdx, authpath, n, h, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const buffer = new Uint8Array(2 * n);

  let leafIdx1 = leafIdx;
  if (leafIdx1 % 2 !== 0) {
    for (let j = 0; j < n; j++) {
      buffer.set([leaf[j]], n + j);
    }
    for (let j = 0; j < n; j++) {
      buffer.set([authpath[j]], j);
    }
  } else {
    for (let j = 0; j < n; j++) {
      buffer.set([leaf[j]], j);
    }
    for (let j = 0; j < n; j++) {
      buffer.set([authpath[j]], n + j);
    }
  }
  let authPathOffset = n;

  for (let i = 0; i < h - 1; i++) {
    setTreeHeight(addr, i);
    leafIdx1 >>>= 1;
    setTreeIndex(addr, leafIdx1);
    if (leafIdx1 % 2 !== 0) {
      hashH(hashFunction, buffer.subarray(n, n + n), buffer, pubSeed, addr, n);
      for (let j = 0; j < n; j++) {
        buffer.set([authpath[authPathOffset + j]], j);
      }
    } else {
      hashH(hashFunction, buffer.subarray(0, n), buffer, pubSeed, addr, n);
      for (let j = 0; j < n; j++) {
        buffer.set([authpath[authPathOffset + j]], j + n);
      }
    }
    authPathOffset += n;
  }
  setTreeHeight(addr, h - 1);
  leafIdx1 >>>= 1;
  setTreeIndex(addr, leafIdx1);
  hashH(hashFunction, root.subarray(0, n), buffer, pubSeed, addr, n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {WOTSParams} wotsParams
 * @param {Uint8Array} msg
 * @param {Uint8Array} sigMsg
 * @param {Uint8Array} pk
 * @param {Uint32Array[number]} h
 * @returns {boolean}
 */
export function xmssVerifySig(hashFunction, wotsParams, msg, sigMsg, pk, h) {
  let [sigMsgOffset] = new Uint32Array([0]);

  const { n } = wotsParams;

  const wotsPK = new Uint8Array(wotsParams.keySize);
  const pkHash = new Uint8Array(n);
  const root = new Uint8Array(n);
  const hashKey = new Uint8Array(3 * n);

  const pubSeed = new Uint8Array(n);
  for (let pubSeedIndex = 0, pkIndex = n; pubSeedIndex < pubSeed.length && pkIndex < n + n; pubSeedIndex++, pkIndex++) {
    pubSeed.set([pk[pkIndex]], pubSeedIndex);
  }

  // Init addresses
  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  setType(otsAddr, 0);
  setType(lTreeAddr, 1);
  setType(nodeAddr, 2);

  // Extract index
  const idx =
    (new Uint32Array([sigMsg[0]])[0] << 24) |
    (new Uint32Array([sigMsg[1]])[0] << 16) |
    (new Uint32Array([sigMsg[2]])[0] << 8) |
    new Uint32Array([sigMsg[3]])[0];

  // Generate hash key (R || root || idx)
  for (let hashKeyIndex = 0, sigMsgIndex = 4; hashKeyIndex < n && sigMsgIndex < 4 + n; hashKeyIndex++, sigMsgIndex++) {
    hashKey.set([sigMsg[sigMsgIndex]], hashKeyIndex);
  }
  for (let hashKeyIndex = n, pkIndex = 0; hashKeyIndex < n + n && pkIndex < n; hashKeyIndex++, pkIndex++) {
    hashKey.set([pk[pkIndex]], hashKeyIndex);
  }
  toByteLittleEndian(hashKey.subarray(2 * n, 2 * n + n), idx, n);

  sigMsgOffset += n + 4;

  // hash message
  const msgHash = new Uint8Array(n);
  const { error } = hMsg(hashFunction, msgHash, msg, hashKey, n);
  if (error !== null) {
    return false;
  }

  // Prepare Address
  setOTSAddr(otsAddr, idx);
  // Check WOTS signature
  wotsPKFromSig(hashFunction, wotsPK, sigMsg.subarray(sigMsgOffset), msgHash, wotsParams, pubSeed, otsAddr);

  sigMsgOffset += wotsParams.keySize;

  // Compute Ltree
  setLTreeAddr(lTreeAddr, idx);
  lTree(hashFunction, wotsParams, pkHash, wotsPK, pubSeed, lTreeAddr);

  // Compute root
  validateAuthPath(hashFunction, root, pkHash, idx, sigMsg.subarray(sigMsgOffset), n, h, pubSeed, nodeAddr);

  for (let i = 0; i < n; i++) {
    if (root[i] !== pk[i]) {
      return false;
    }
  }

  return true;
}

/**
 * @param {Uint8Array} message
 * @param {Uint8Array} signature
 * @param {Uint8Array} extendedPK
 * @param {Uint32Array[number]} wotsParamW
 * @returns {boolean}
 */
export function verifyWithCustomWOTSParamW(message, signature, extendedPK, wotsParamW) {
  if (extendedPK.length !== CONSTANTS.EXTENDED_PK_SIZE) {
    throw new Error(`extendedPK should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`);
  }

  const wotsParam = newWOTSParams(WOTS_PARAM.N, wotsParamW);

  const signatureBaseSize = calculateSignatureBaseSize(wotsParam.keySize);
  if (new Uint32Array([signature.length])[0] > signatureBaseSize + new Uint32Array([CONSTANTS.MAX_HEIGHT])[0] * 32) {
    throw new Error('Invalid signature size. Height<=254');
  }

  const desc = newQRLDescriptorFromExtendedPk(extendedPK);

  if (desc.getSignatureType() !== COMMON.XMSS_SIG) {
    throw new Error('Invalid signature type');
  }

  const height = getHeightFromSigSize(new Uint32Array([signature.length])[0], wotsParamW);

  if (height === 0 || new Uint32Array([desc.getHeight()])[0] !== height) {
    return false;
  }

  const hashFunction = desc.getHashFunction();

  const k = WOTS_PARAM.K;
  const w = WOTS_PARAM.W;
  const n = WOTS_PARAM.N;

  if (k >= height || (height - k) % 2 === 1) {
    throw new Error('For BDS traversal, H - K must be even, with H > K >= 2!');
  }

  const params = newXMSSParams(n, height, w, k);
  const tmp = signature;
  return xmssVerifySig(
    hashFunction,
    params.wotsParams,
    message,
    tmp,
    extendedPK.subarray(COMMON.DESCRIPTOR_SIZE),
    height
  );
}

/**
 * @param {Uint8Array} message
 * @param {Uint8Array} signature
 * @param {Uint8Array} extendedPK
 * @returns {boolean}
 */
export function verify(message, signature, extendedPK) {
  if (extendedPK.length !== CONSTANTS.EXTENDED_PK_SIZE) {
    throw new Error(`extendedPK should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`);
  }

  return verifyWithCustomWOTSParamW(message, signature, extendedPK, WOTS_PARAM.W);
}
