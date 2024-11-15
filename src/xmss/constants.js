const CONSTANTS = Object.freeze({
  EXTENDED_PK_SIZE: 67,
  MAX_HEIGHT: 254,
});

const HASH_FUNCTION = Object.freeze({
  SHA2_256: 0,
  SHAKE_128: 1,
  SHAKE_256: 2,
});

const COMMON = Object.freeze({
  XMSS_SIG: 1,
  DESCRIPTOR_SIZE: 3,
  ADDRESS_SIZE: 20,
  SEED_SIZE: 48,
  EXTENDED_SEED_SIZE: 51,
  SHA256_2X: 0,
});

const WOTS_PARAM = Object.freeze({
  K: 2,
  W: 16,
  N: 32,
});

const OFFSET_IDX = 0;
const OFFSET_SK_SEED = OFFSET_IDX + 4;
const OFFSET_SK_PRF = OFFSET_SK_SEED + 32;
const OFFSET_PUB_SEED = OFFSET_SK_PRF + 32;
const OFFSET_ROOT = OFFSET_PUB_SEED + 32;

module.exports = {
  CONSTANTS,
  HASH_FUNCTION,
  COMMON,
  WOTS_PARAM,
  OFFSET_ROOT,
};
