'use strict';

const dilithium = require('./dilithium/dilithium.js');
const helper = require('./utils/helper.js');
const wordlist = require('./utils/wordList.js');
const xmss = require('./xmss/xmss.js');
const xmssFast = require('./xmss/xmssFast.js');

module.exports = {
  Dilithium: dilithium.Dilithium,
  extractMessage: dilithium.extractMessage,
  extractSignature: dilithium.extractSignature,
  getDilithiumAddressFromPK: dilithium.getDilithiumAddressFromPK,
  getDilithiumDescriptor: dilithium.getDilithiumDescriptor,
  isValidDilithiumAddress: dilithium.isValidDilithiumAddress,
  mnemonicToSeedBin: helper.mnemonicToSeedBin,
  seedBinToMnemonic: helper.seedBinToMnemonic,
  xmss,
  xmssFast,
  WORD_LIST: wordlist.WordList,
};
