const { COMMON } = require('../xmss/constants.js');
const { WORD_LIST } = require('./wordList.js');

/**
 * @param {Uint8Array} input
 * @returns {string}
 */
function binToMnemonic(input) {
  if (input.length % 3 !== 0) {
    throw new Error('byte count needs to be a multiple of 3');
  }

  const buf = [];
  const separator = ' ';
  for (let nibble = 0; nibble < input.length * 2; nibble += 3) {
    const p = nibble >>> 1;
    const [b1] = new Uint32Array([input[p]]);
    let [b2] = new Uint32Array([0]);
    if (p + 1 < input.length) {
      [b2] = new Uint32Array([input[p + 1]]);
    }
    let [idx] = new Uint32Array([0]);
    if (nibble % 2 === 0) {
      idx = (b1 << 4) + (b2 >>> 4);
    } else {
      idx = ((b1 & 0x0f) << 8) + b2;
    }
    try {
      buf.push(WORD_LIST[idx]);
    } catch (error) {
      throw new Error(`ExtendedSeedBinToMnemonic error ${error?.message}`);
    }
  }

  return buf.join(separator);
}

/**
 * @param {Uint8Array} input
 * @returns {string}
 */
function seedBinToMnemonic(input) {
  if (input.length !== COMMON.SEED_SIZE) {
    throw new Error(`input should be an array of size ${COMMON.SEED_SIZE}`);
  }

  return binToMnemonic(input);
}

/**
 * @param {Uint8Array} input
 * @returns {string}
 */
function extendedSeedBinToMnemonic(input) {
  if (input.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error(`input should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`);
  }

  return binToMnemonic(input);
}

/**
 * @param {string} mnemonic
 * @returns {Uint8Array}
 */
function mnemonicToBin(mnemonic) {
  const mnemonicWords = mnemonic.split(' ');
  const wordCount = mnemonicWords.length;
  if (wordCount % 2 !== 0) {
    throw new Error(`Word count = ${wordCount} must be even`);
  }

  const wordLookup = {};

  for (let i = 0; i < WORD_LIST.length; i++) {
    wordLookup[WORD_LIST[i]] = i;
  }

  const result = new Uint8Array((wordCount * 15) / 10);
  let current = 0;
  let buffering = 0;
  let resultIndex = 0;
  for (let i = 0; i < wordCount; i++) {
    const w = mnemonicWords[i];
    const found = w in wordLookup;
    if (!found) {
      throw new Error('Invalid word in mnemonic');
    }
    const value = wordLookup[w];

    buffering += 3;
    current = (current << 12) + value;
    while (buffering > 2) {
      const shift = 4 * (buffering - 2);
      const mask = (1 << shift) - 1;
      const tmp = current >>> shift;
      buffering -= 2;
      current &= mask;
      result.set([tmp], resultIndex);
      resultIndex++;
    }
  }

  if (buffering > 0) {
    result.set([current & 0xff], resultIndex);
    resultIndex++;
  }

  return result;
}

/**
 * @param {string} mnemonic
 * @returns {Uint8Array}
 */
function mnemonicToSeedBin(mnemonic) {
  const output = mnemonicToBin(mnemonic);

  if (output.length !== COMMON.SEED_SIZE) {
    throw new Error('Unexpected MnemonicToSeedBin output size');
  }

  const sizedOutput = new Uint8Array(COMMON.SEED_SIZE);
  for (
    let sizedOutputIndex = 0, outputIndex = 0;
    sizedOutputIndex < sizedOutput.length && outputIndex < output.length;
    sizedOutputIndex++, outputIndex++
  ) {
    sizedOutput.set([output[outputIndex]], sizedOutputIndex);
  }

  return sizedOutput;
}

/**
 * @param {string} mnemonic
 * @returns {Uint8Array}
 */
function mnemonicToExtendedSeedBin(mnemonic) {
  const output = mnemonicToBin(mnemonic);

  if (output.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error('Unexpected MnemonicToExtendedSeedBin output size');
  }

  const sizedOutput = new Uint8Array(COMMON.EXTENDED_SEED_SIZE);
  for (
    let sizedOutputIndex = 0, outputIndex = 0;
    sizedOutputIndex < sizedOutput.length && outputIndex < output.length;
    sizedOutputIndex++, outputIndex++
  ) {
    sizedOutput.set([output[outputIndex]], sizedOutputIndex);
  }

  return sizedOutput;
}

module.exports = {
  binToMnemonic,
  seedBinToMnemonic,
  extendedSeedBinToMnemonic,
  mnemonicToBin,
  mnemonicToSeedBin,
  mnemonicToExtendedSeedBin,
};
