/// <reference path="typedefs.js" />

import {
  setType,
  setLTreeAddr,
  setOTSAddr,
  genLeafWOTS,
  setTreeHeight,
  setTreeIndex,
  hashH,
  shake256,
  bdsRound,
  bdsTreeHashUpdate,
} from '@theqrl/xmss';

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
export function treeHashSetup(hashFunction, node, index, bdsState, skSeed, xmssParams, pubSeed, addr) {
  const { n, h, k } = xmssParams;

  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  otsAddr.set(addr.subarray(0, 3));
  setType(otsAddr, 0);

  lTreeAddr.set(addr.subarray(0, 3));
  setType(lTreeAddr, 1);

  nodeAddr.set(addr.subarray(0, 3));
  setType(nodeAddr, 2);

  const lastNode = index + (1 << h);

  const bound = h - k;
  const stack = new Uint8Array((h + 1) * n);
  const stackLevels = new Uint32Array(h + 1);
  let stackOffset = new Uint32Array([0])[0];
  let nodeH = new Uint32Array([0])[0];

  const bdsState1 = bdsState;
  for (let i = 0; i < bound; i++) {
    bdsState1.treeHash[i].h = i;
    bdsState1.treeHash[i].completed = 1;
    bdsState1.treeHash[i].stackUsage = 0;
  }

  for (let i = 0, index1 = index; index1 < lastNode; i++, index1++) {
    setLTreeAddr(lTreeAddr, index1);
    setOTSAddr(otsAddr, index1);

    genLeafWOTS(
      hashFunction,
      stack.subarray(stackOffset * n, stackOffset * n + n),
      skSeed,
      xmssParams,
      pubSeed,
      lTreeAddr,
      otsAddr
    );

    stackLevels.set([0], stackOffset);
    stackOffset++;
    if (h - k > 0 && i === 3) {
      bdsState1.treeHash[0].node.set(stack.subarray(stackOffset * n, stackOffset * n + n));
    }
    while (stackOffset > 1 && stackLevels[stackOffset - 1] === stackLevels[stackOffset - 2]) {
      nodeH = stackLevels[stackOffset - 1];
      if (i >>> nodeH === 1) {
        const authStart = nodeH * n;
        const stackStart = (stackOffset - 1) * n;
        for (
          let authIndex = authStart, stackIndex = stackStart;
          authIndex < authStart + n && stackIndex < stackStart + n;
          authIndex++, stackIndex++
        ) {
          bdsState1.auth.set([stack[stackIndex]], authIndex);
        }
      } else if (nodeH < h - k && i >>> nodeH === 3) {
        const stackStart = (stackOffset - 1) * n;
        bdsState1.treeHash[nodeH].node.set(stack.subarray(stackStart, stackStart + n));
      } else if (nodeH >= h - k) {
        const retainStart = ((1 << (h - 1 - nodeH)) + nodeH - h + (((i >>> nodeH) - 3) >>> 1)) * n;
        const stackStart = (stackOffset - 1) * n;
        for (
          let retainIndex = retainStart, stackIndex = stackStart;
          retainIndex < retainStart + n && stackIndex < stackStart + n;
          retainIndex++, stackIndex++
        ) {
          bdsState1.retain.set([stack[stackIndex]], retainIndex);
        }
      }
      setTreeHeight(nodeAddr, stackLevels[stackOffset - 1]);
      setTreeIndex(nodeAddr, index1 >>> (stackLevels[stackOffset - 1] + 1));
      const stackStart = (stackOffset - 2) * n;

      hashH(
        hashFunction,
        stack.subarray(stackStart, stackStart + n),
        stack.subarray(stackStart, stackStart + 2 * n),
        pubSeed,
        nodeAddr,
        n
      );

      stackLevels[stackOffset - 2]++;
      stackOffset--;
    }
  }
  node.set(stack.subarray(0, n));
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} seed
 */
export function XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed) {
  if (xmssParams.h % 2 === 1) {
    throw new Error('Not a valid h, only even numbers supported! Try again with an even number');
  }

  const { n } = xmssParams;

  sk.set([0, 0, 0, 0]);

  const randombits = new Uint8Array(3 * n);

  shake256(randombits, seed);

  const rnd = 96;
  const pks = new Uint32Array([32])[0];
  sk.set(randombits.subarray(0, rnd), 4);
  for (let pkIndex = n, skIndex = 4 + 2 * n; pkIndex < pk.length && skIndex < 4 + 2 * n + pks; pkIndex++, skIndex++) {
    pk.set([sk[skIndex]], pkIndex);
  }

  const addr = new Uint32Array(8);
  treeHashSetup(
    hashFunction,
    pk,
    0,
    bdsState,
    sk.subarray(4, 4 + n),
    xmssParams,
    sk.subarray(4 + 2 * n, 4 + 2 * n + n),
    addr
  );

  for (let skIndex = 4 + 3 * n, pkIndex = 0; skIndex < sk.length && pkIndex < pks; skIndex++, pkIndex++) {
    sk.set([pk[pkIndex]], skIndex);
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} params
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} newIdx
 * @returns {Uint32Array[number]}
 */
export function xmssFastUpdate(hashFunction, params, sk, bdsState, newIdx) {
  const [numElems] = new Uint32Array([1 << params.h]);
  const currentIdx =
    (new Uint32Array([sk[0]])[0] << 24) |
    (new Uint32Array([sk[1]])[0] << 16) |
    (new Uint32Array([sk[2]])[0] << 8) |
    new Uint32Array([sk[3]])[0];

  if (newIdx >= numElems) {
    throw new Error('Index too high');
  }
  if (newIdx < currentIdx) {
    throw new Error('Cannot rewind');
  }

  const skSeed = new Uint8Array(params.n);
  skSeed.set(sk.subarray(4, 4 + params.n));

  const startOffset = 4 + 2 * 32;
  const pubSeed = new Uint8Array(params.n);
  for (
    let pubSeedIndex = 0, skIndex = startOffset;
    pubSeedIndex < 32 && skIndex < startOffset + 32;
    pubSeedIndex++, skIndex++
  ) {
    pubSeed.set([sk[skIndex]], pubSeedIndex);
  }

  const otsAddr = new Uint32Array(8);

  for (let i = currentIdx; i < newIdx; i++) {
    if (i >= numElems) {
      return -1;
    }
    bdsRound(hashFunction, bdsState, i, skSeed, params, pubSeed, otsAddr);
    bdsTreeHashUpdate(hashFunction, bdsState, (params.h - params.k) >>> 1, skSeed, params, pubSeed, otsAddr);
  }

  sk.set(new Uint8Array([(newIdx >>> 24) & 0xff, (newIdx >>> 16) & 0xff, (newIdx >>> 8) & 0xff, newIdx & 0xff]));

  return 0;
}
