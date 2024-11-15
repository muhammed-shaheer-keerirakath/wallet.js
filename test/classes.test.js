const { expect } = require('chai');
const {
  newQRLDescriptor,
  newQRLDescriptorFromBytes,
  newQRLDescriptorFromExtendedPk,
  newQRLDescriptorFromExtendedSeed,
} = require('../src/xmss/classes.js');
const { COMMON, CONSTANTS, HASH_FUNCTION } = require('../src/xmss/constants.js');
const { getUInt32ArrayFromHex, getUInt8ArrayFromHex } = require('./testUtility.js');

describe('Test cases for [classes]', () => {
  describe('newQRLDescriptor', () => {
    it('should create a QRLDescriptor instance', () => {
      const [height] = getUInt8ArrayFromHex('05');
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const [signatureType] = getUInt32ArrayFromHex('00000004');
      const [addrFormatType] = getUInt32ArrayFromHex('00000041');
      const qrlDescriptor = newQRLDescriptor(height, hashFunction, signatureType, addrFormatType);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
      expect(qrlDescriptor.hashFunction).to.equal(1);
      expect(qrlDescriptor.signatureType).to.equal(signatureType);
      expect(qrlDescriptor.height).to.equal(height);
      expect(qrlDescriptor.addrFormatType).to.equal(addrFormatType);
    });
  });

  describe('newQRLDescriptorFromBytes', () => {
    it('should create a QRLDescriptor instance', () => {
      const descriptorBytes = getUInt8ArrayFromHex('030609');
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
    });

    it('should throw an error if the size of descriptionBytes array is not 3', () => {
      const descriptorBytes = getUInt8ArrayFromHex('2d210703064d');

      expect(() => newQRLDescriptorFromBytes(descriptorBytes)).to.throw('Descriptor size should be 3 bytes');
    });

    it('should create a QRLDescriptor instance, with descriptorBytes[310622]', () => {
      const descriptorBytes = getUInt8ArrayFromHex('310622');
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(qrlDescriptor.hashFunction).to.equal(1);
      expect(qrlDescriptor.signatureType).to.equal(3);
      expect(qrlDescriptor.height).to.equal(12);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with descriptorBytes[0001fe]', () => {
      const descriptorBytes = getUInt8ArrayFromHex('0001fe');
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(qrlDescriptor.hashFunction).to.equal(0);
      expect(qrlDescriptor.signatureType).to.equal(0);
      expect(qrlDescriptor.height).to.equal(2);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with descriptorBytes[dc006f]', () => {
      const descriptorBytes = getUInt8ArrayFromHex('dc006f');
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(qrlDescriptor.hashFunction).to.equal(12);
      expect(qrlDescriptor.signatureType).to.equal(13);
      expect(qrlDescriptor.height).to.equal(0);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });
  });

  describe('newQRLDescriptorFromExtendedSeed', () => {
    it('should create a QRLDescriptor instance', () => {
      const extendedSeeds = getUInt8ArrayFromHex(
        '09040609010c02090c04060d03020c060c040205040c080b0d0f0b00070009040202060808030e030806020600090307060e0e'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
    });

    it('should throw an error if the size of extendedSeeds array is not EXTENDED_SEED_SIZE', () => {
      const extendedSeeds = getUInt8ArrayFromHex('04');

      expect(() => newQRLDescriptorFromExtendedSeed(extendedSeeds)).to.throw(
        `extendedSeed should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`
      );
    });

    it('should create a QRLDescriptor instance, with extendedSeeds[0904...]', () => {
      const extendedSeeds = getUInt8ArrayFromHex(
        '09040609010c02090c04060d03020c060c040205040c080b0d0f0b00070009040202060808030e030806020600090307060e0e'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(qrlDescriptor.hashFunction).to.equal(9);
      expect(qrlDescriptor.signatureType).to.equal(0);
      expect(qrlDescriptor.height).to.equal(8);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with extendedSeeds[5ca4...]', () => {
      const extendedSeeds = getUInt8ArrayFromHex(
        '5ca44e1b1494e62e5c71412296cb03641d0260459481f3b68ab5dbdf58d3caaa50929bef44179a8a17bf3f02a41d0e84cd3d03'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(qrlDescriptor.hashFunction).to.equal(12);
      expect(qrlDescriptor.signatureType).to.equal(5);
      expect(qrlDescriptor.height).to.equal(8);
      expect(qrlDescriptor.addrFormatType).to.equal(10);
    });

    it('should create a QRLDescriptor instance, with extendedSeeds[8d09...]', () => {
      const extendedSeeds = getUInt8ArrayFromHex(
        '8d09b9667bb190d5973487600a6a2e74171a973281b777bc7fa3c7abcbcb775961f1430daa629b6ba42892cc04ece0d24300a1'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(qrlDescriptor.hashFunction).to.equal(13);
      expect(qrlDescriptor.signatureType).to.equal(8);
      expect(qrlDescriptor.height).to.equal(18);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });
  });

  describe('newQRLDescriptorFromExtendedPk', () => {
    it('should create a QRLDescriptor instance', () => {
      const extendedPk = getUInt8ArrayFromHex(
        '43053fefbec25a3f74f3f09ad654d94e7da64b591e0ed100908cd343dda572489127510959df03faa33fae8cbca444f3732b5b17c18633b9e3fdb26e56f07059342156'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
    });

    it('should throw an error if the size of extendedPk array is not EXTENDED_PK_SIZE', () => {
      const extendedPk = getUInt8ArrayFromHex('3857');

      expect(() => newQRLDescriptorFromExtendedPk(extendedPk)).to.throw(
        `extendedPk should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`
      );
    });

    it('should create a QRLDescriptor instance, with extendedPk[4305...]', () => {
      const extendedPk = getUInt8ArrayFromHex(
        '43053fefbec25a3f74f3f09ad654d94e7da64b591e0ed100908cd343dda572489127510959df03faa33fae8cbca444f3732b5b17c18633b9e3fdb26e56f07059342156'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(qrlDescriptor.hashFunction).to.equal(3);
      expect(qrlDescriptor.signatureType).to.equal(4);
      expect(qrlDescriptor.height).to.equal(10);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with extendedPk[6d14...]', () => {
      const extendedPk = getUInt8ArrayFromHex(
        '6d14dadec8746dd12d54f2ee01d7127c4dde8eb7dae07b6d6998a480741e9cf6db1496facf78161485b3355782ccb7ea6d5e37bbf22bb3130a51809714f5cfd812eb01'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(qrlDescriptor.hashFunction).to.equal(13);
      expect(qrlDescriptor.signatureType).to.equal(6);
      expect(qrlDescriptor.height).to.equal(8);
      expect(qrlDescriptor.addrFormatType).to.equal(1);
    });

    it('should create a QRLDescriptor instance, with extendedPk[6619...]', () => {
      const extendedPk = getUInt8ArrayFromHex(
        '6619995e50d6f161a2b69063d626e7e377bcb2ca1638ab7d6f00d398816459846938345670935c7de8342488f7848c6120d8d941f7ec686b033917ac8866494e582fd4'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(qrlDescriptor.hashFunction).to.equal(6);
      expect(qrlDescriptor.signatureType).to.equal(6);
      expect(qrlDescriptor.height).to.equal(18);
      expect(qrlDescriptor.addrFormatType).to.equal(1);
    });
  });
});
