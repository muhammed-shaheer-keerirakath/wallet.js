import { newBDSState, newXMSSParams, HASH_FUNCTION } from '@theqrl/xmss';
import { XMSSFastGenKeyPair, treeHashSetup, xmssFastUpdate } from '../src/xmss/xmssFast.js';
import { getUInt32ArrayFromHex, getUInt8ArrayFromHex } from './testUtility.js';

const { expect } = require('chai');

describe('Test cases for [xmssFast]', () => {
  describe('treeHashSetup', () => {
    it('should setup tree hash, with SHA2_256 hashing', () => {
      const index = 5;
      const height = 3;
      const k = 3;
      const w = 7;
      const n = 3;
      const node = getUInt8ArrayFromHex('3807162c5629020608020703050102050302');
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('090734045629020608020703050102050302');
      const xmssParams = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('3807162c5629020608020703050102050336');
      const addr = getUInt32ArrayFromHex(
        '0000005800000007000000160000002c00000056000000290000000200000006000000020000000700000003000000050000000100000002000000050000000300000002'
      );
      const expectedNode = getUInt8ArrayFromHex('021f042c5629020608020703050102050302');
      const expectedSkSeed = getUInt8ArrayFromHex('090734045629020608020703050102050302');
      const expectedPubSeed = getUInt8ArrayFromHex('3807162c5629020608020703050102050336');
      const expectedAddr = getUInt32ArrayFromHex(
        '0000005800000007000000160000002c00000056000000290000000200000006000000020000000700000003000000050000000100000002000000050000000300000002'
      );
      treeHashSetup(HASH_FUNCTION.SHA2_256, node, index, bdsState, skSeed, xmssParams, pubSeed, addr);

      expect(node).to.deep.equal(expectedNode);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should setup tree hash, with SHAKE_128 hashing', () => {
      const index = 7;
      const height = 4;
      const k = 2;
      const w = 5;
      const n = 9;
      const node = getUInt8ArrayFromHex('0d0b0508050d0302060f0b080e0b0f0e');
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('0710120b0c06130f0f060f010d11150108131106120510');
      const xmssParams = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('0903150d0d0b0e141719000011120b09060a0f0e070b0e0f0906');
      const addr = getUInt32ArrayFromHex(
        '0000000e000000070000000f0000000700000004000000070000000f0000000b000000070000000f00000004000000090000000b00000005000000040000000200000006'
      );
      const expectedNode = getUInt8ArrayFromHex('d2da2b4c7c54cb324c0f0b080e0b0f0e');
      const expectedSkSeed = getUInt8ArrayFromHex('0710120b0c06130f0f060f010d11150108131106120510');
      const expectedPubSeed = getUInt8ArrayFromHex('0903150d0d0b0e141719000011120b09060a0f0e070b0e0f0906');
      const expectedAddr = getUInt32ArrayFromHex(
        '0000000e000000070000000f0000000700000004000000070000000f0000000b000000070000000f00000004000000090000000b00000005000000040000000200000006'
      );
      treeHashSetup(HASH_FUNCTION.SHAKE_128, node, index, bdsState, skSeed, xmssParams, pubSeed, addr);

      expect(node).to.deep.equal(expectedNode);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should setup tree hash, with SHAKE_256 hashing', () => {
      const index = 12;
      const height = 7;
      const k = 4;
      const w = 256;
      const n = 3;
      const node = getUInt8ArrayFromHex('000d030a0b0c02090a080b0205050301');
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('0c07100c01100c05030f0e140d071503000d070c031504');
      const xmssParams = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('1004181004061007130e0d09030d0a080010100d0412140108');
      const addr = getUInt32ArrayFromHex(
        '0000000300000006000000000000000c000000040000000000000010000000020000001000000000000000050000000a0000000e0000000d0000000c0000000700000004'
      );
      const expectedNode = getUInt8ArrayFromHex('44b1920a0b0c02090a080b0205050301');
      const expectedSkSeed = getUInt8ArrayFromHex('0c07100c01100c05030f0e140d071503000d070c031504');
      const expectedPubSeed = getUInt8ArrayFromHex('1004181004061007130e0d09030d0a080010100d0412140108');
      const expectedAddr = getUInt32ArrayFromHex(
        '0000000300000006000000000000000c000000040000000000000010000000020000001000000000000000050000000a0000000e0000000d0000000c0000000700000004'
      );
      treeHashSetup(HASH_FUNCTION.SHAKE_256, node, index, bdsState, skSeed, xmssParams, pubSeed, addr);

      expect(node).to.deep.equal(expectedNode);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('XMSSFastGenKeyPair', () => {
    it('should generate secret key and public key, with SHA2_256 hashing', () => {
      const height = 2;
      const k = 2;
      const w = 16;
      const n = 32;
      const xmssParams = newXMSSParams(n, height, w, k);
      const bdsState = newBDSState(height, n, k);
      const pk = getUInt8ArrayFromHex(
        '27121318191e172a0e3c0c1f0d27300f393c071e2a281f36131200010f3802340c190e15383e0f0b130c31292024220f041c1d37002b012d230b17240a091c0f'
      );
      const sk = getUInt8ArrayFromHex(
        '7c48145a1b656c4b10742f042160813d723c7f0d082c1e606d2e30101f1958754711594f53717103010a722418715d36253416245a2b071e4e4c2754747d2a5b1a2e5b3d502e3a616f5149217566431661255f7f562e4e30512b1e367315306e2a102e4d0a6f510d5e4d7a0a5306275a42232d152a1708684302541569137507673f5366'
      );
      const seed = getUInt8ArrayFromHex(
        '102615201829042a1b2423140f0e091e0a202f2429250f1f0206190e1212231c231501201e041e15121f0b2d2d232101'
      );
      const expectedPk = getUInt8ArrayFromHex(
        '88a882c691b377578f2b3486c9bd0dd6393db5d7af7719a5df106c00d79797e28343e3b3cffb0dfc38f3ce6beff4dea6f363ecd3b4842d0bad2d73257b0f7b9e'
      );
      const expectedSk = getUInt8ArrayFromHex(
        '000000000252a9fc1fc1ff75ddd8ca34bc73201eac930121a400762c917ffd22c56054f00fb44853ff79c02f51aabeaa1d629e09ed20c3d59fbf552222d3e93110dbe0978343e3b3cffb0dfc38f3ce6beff4dea6f363ecd3b4842d0bad2d73257b0f7b9e88a882c691b377578f2b3486c9bd0dd6393db5d7af7719a5df106c00d79797e2'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '102615201829042a1b2423140f0e091e0a202f2429250f1f0206190e1212231c231501201e041e15121f0b2d2d232101'
      );
      XMSSFastGenKeyPair(HASH_FUNCTION.SHA2_256, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should generate secret key and public key, with SHAKE_128 hashing', () => {
      const height = 4;
      const k = 3;
      const w = 7;
      const n = 37;
      const xmssParams = newXMSSParams(n, height, w, k);
      const bdsState = newBDSState(height, n, k);
      const pk = getUInt8ArrayFromHex(
        '311410342b1b323b151a1f113e2d07313615232226080a112038143d3e2f050b32101e06061a2209083c3f1c12313d2822391a2a111208061918140022123316'
      );
      const sk = getUInt8ArrayFromHex(
        '7f1f621e630a3f4f2f61231b39232f190d031f3d243e6f6e20100469387c1d654c2a767c4a2a33367055260f36835e1b21272b1e213e3e8331395f0552297a284e27020d5e3d7c804a64366e7a643f653e031724583b3d635c4a314d145f554e426e5c6d3e46052636814b07360e164f72421c2e0e503e5b5f666532735843325424481d'
      );
      const seed = getUInt8ArrayFromHex(
        '2723042729061f24221c2e18182a2f2321060a2e0e20011e072f1a1c09071f260c122b281c112701242d002b21180f11'
      );
      const expectedPk = getUInt8ArrayFromHex(
        'fa872a4f90a9a989e38b5aca522d3f26e8b7cb1f22bb7f376eb061d668ed570216d0d6278edbcdd5f805ce41274d0ca4b523de88b29aeb6296c2fb3e46052636'
      );
      const expectedSk = getUInt8ArrayFromHex(
        '00000000224f2d06b66f41867fab1930e619eb3544a29d806497c2f32a0fc8f1b9e81f557689eeb3b3db12a800320e5dd803ec7a9624e17d2f1a4aa3dac91ac9bc42eea570db23dffe10be09b9f6dbcdd5f805ce41274d0ca4b523de88b29aeb6296c2fb3e46052636814b07360e164f72421cfa872a4f90a9a989e38b5aca522d3f26e8'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '2723042729061f24221c2e18182a2f2321060a2e0e20011e072f1a1c09071f260c122b281c112701242d002b21180f11'
      );
      XMSSFastGenKeyPair(HASH_FUNCTION.SHAKE_128, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should generate secret key and public key, with SHAKE_256 hashing', () => {
      const height = 2;
      const k = 2;
      const w = 16;
      const n = 32;
      const xmssParams = newXMSSParams(n, height, w, k);
      const bdsState = newBDSState(height, n, k);
      const pk = new Uint8Array(64);
      const sk = new Uint8Array(132);
      const seed = getUInt8ArrayFromHex(
        '030501020503020602070305010205030206020703050102050302060207030501020503020602070305010205030206'
      );
      const expectedPk = getUInt8ArrayFromHex(
        '693e356d62a84c53f5162f36801f19b445f5876b70ad3c16a828991ecf9edd8225bfa7c0458254b18322dc4730d2d2028d17536a26c958967fea723371019f13'
      );
      const expectedSk = getUInt8ArrayFromHex(
        '0000000013f324641ae9b1aef4b11890dd7918a2e7fd3d8331e33df9b0a764dfe3b0473d956f4bce2ccb5de9484a7e2cf0687db073f51de3836b86fc2fc8eda92390380f25bfa7c0458254b18322dc4730d2d2028d17536a26c958967fea723371019f13693e356d62a84c53f5162f36801f19b445f5876b70ad3c16a828991ecf9edd82'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '030501020503020602070305010205030206020703050102050302060207030501020503020602070305010205030206'
      );
      XMSSFastGenKeyPair(HASH_FUNCTION.SHAKE_256, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(seed).to.deep.equal(expectedSeed);
    });
  });

  describe('xmssFastUpdate', () => {
    it('should run xmssFastUpdate, with SHA2_256 hashing', () => {
      const height = 3;
      const k = 3;
      const w = 7;
      const n = 32;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        '000000062e714e38484b246b2a6a5c3c27520e0503491a5f5d650236771415305b523c37521b6d3952365247371b385a5e7a1843263d475833382b041968451d6b68771378186a3776627479003e461a78362e38593f6006703d744557293f5464405429'
      );
      const bdsState = newBDSState(height, n, k);
      const newIdx = 7;
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        '000000072e714e38484b246b2a6a5c3c27520e0503491a5f5d650236771415305b523c37521b6d3952365247371b385a5e7a1843263d475833382b041968451d6b68771378186a3776627479003e461a78362e38593f6006703d744557293f5464405429'
      );
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex(
        '31d5eb752ecca048fae65f9dbeb0896e07d901287847138d5cfcd0115aadc2fd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      xmssFastUpdate(HASH_FUNCTION.SHA2_256, params, sk, bdsState, newIdx);

      expect(params).to.be.deep.equal(expectedParams);
      expect(sk).to.be.deep.equal(expectedSk);
      expect(bdsState).to.be.deep.equal(expectedBdsState);
    });

    it('should run xmssFastUpdate, with SHAKE_128 hashing', () => {
      const height = 4;
      const k = 4;
      const w = 256;
      const n = 46;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        '00000003677a721e3a04384e44477a0b436111753672271d74762f50404f1f74174f234a454c640020315f11713d4311407b51094d010c345d27625b3d432742685e703e094b550a5b110626316443746858790f4b130b552f2851630b235e30475d316e4f18046b1f280b3f043c4729321f2e5d5918066a'
      );
      const bdsState = newBDSState(height, n, k);
      const newIdx = 12;
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        '0000000c677a721e3a04384e44477a0b436111753672271d74762f50404f1f74174f234a454c640020315f11713d4311407b51094d010c345d27625b3d432742685e703e094b550a5b110626316443746858790f4b130b552f2851630b235e30475d316e4f18046b1f280b3f043c4729321f2e5d5918066a'
      );
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex(
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034c560df07bcd2dc0992269703659365ac2a70296f579f689868eea30a0d8887f2b06b3334ec168524e98828447ef923fa403e1b21cdc265b1ef8ba76a13372eabfec89ae63dedb0ba21042ba8eac717f436a1e232b97764d4a222c4'
      );
      xmssFastUpdate(HASH_FUNCTION.SHAKE_128, params, sk, bdsState, newIdx);

      expect(params).to.be.deep.equal(expectedParams);
      expect(sk).to.be.deep.equal(expectedSk);
      expect(bdsState).to.be.deep.equal(expectedBdsState);
    });

    it('should run xmssFastUpdate, with SHAKE_256 hashing', () => {
      const height = 5;
      const k = 2;
      const w = 7;
      const n = 43;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        '000000080406090301070b0b0704000304050e040208080d0b0b02080f05060c06030c030e0c0c060e020203010d0a030507010d0401090a0d0e0d0c010b0a00060904040a020c090b060a0701010f0b05020d040e000505070b0c020b0a0b0e00040b0d0208070c'
      );
      const bdsState = newBDSState(height, n, k);
      const newIdx = 11;
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        '0000000b0406090301070b0b0704000304050e040208080d0b0b02080f05060c06030c030e0c0c060e020203010d0a030507010d0401090a0d0e0d0c010b0a00060904040a020c090b060a0701010f0b05020d040e000505070b0c020b0a0b0e00040b0d0208070c'
      );
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex(
        'c8f4327cc03b65d517bd4d0945db33474f79ddfe07b769ae3415fbf488e8aa498940b11e3a77ffa48d418bc4151dbce1b14e56fb48efa9c6a8277a095f43a4ca1c26ace56d1ab88de3107fb95dd51fc4c1d749637492000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      expectedBdsState.treeHash[0].nextIdx = 13;
      expectedBdsState.treeHash[0].completed = 1;
      expectedBdsState.treeHash[0].node = getUInt8ArrayFromHex(
        '8e795933de848defcb66def8d6a3c646eb32e64ccaf4ed0a010d48d30ea35803b255bcd1800f5198e8b3f6'
      );
      expectedBdsState.treeHash[1].completed = 1;
      expectedBdsState.treeHash[1].node = getUInt8ArrayFromHex(
        '843684e0b72a9284721495e5dc6ea2a6664360b0f7bf6f0164b298d63861933a5c68a9c497e9cf87d79d9c'
      );
      xmssFastUpdate(HASH_FUNCTION.SHAKE_256, params, sk, bdsState, newIdx);

      expect(params).to.be.deep.equal(expectedParams);
      expect(sk).to.be.deep.equal(expectedSk);
      expect(bdsState).to.be.deep.equal(expectedBdsState);
    });
  });
});
