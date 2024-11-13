import { COMMON } from '../../packages/xmss/constants';
import {
  binToMnemonic,
  extendedSeedBinToMnemonic,
  mnemonicToBin,
  mnemonicToExtendedSeedBin,
  mnemonicToSeedBin,
  seedBinToMnemonic,
} from '../src/utils/helper.js';
import { getUInt8ArrayFromHex } from './testUtility.js';

const { expect } = require('chai');

describe('Test cases for [helper]', () => {
  describe('binToMnemonic', () => {
    it('should generate mnemonic from binary, with input length [3]', () => {
      const input = getUInt8ArrayFromHex('38ff00');
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic = 'deed utmost';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input length [12]', () => {
      const input = getUInt8ArrayFromHex('8e38cb57812de6b2422270ff');
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic = 'modern mind friar bath tomb carbon calf bad';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input length [30]', () => {
      const input = getUInt8ArrayFromHex('48bd21ff802fa3d43663ee438c54d203b07a5bc82c9bdb3c8311f36555c4');
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'essex spin zero adopt pill early hail throng mile fast afloat amen gene louvre orphan regret lower build harry genus';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input length [300]', () => {
      const input = getUInt8ArrayFromHex(
        '7c53d80b63cd249443ffc0513087b306e58ec84a5b3575faa820c96dcfd7bb80a35d4226ddbe2cae0d39b6f378935f41afea276c1b8d4dd205c757e16af021aa36830ec245899666ced354bd79fba231b90738e667da70b72a9f4c14f89b25dba41ee460cc43e97bc60a8647c06f1bf5a057c876af378f4ed968fc1f8ad173f142bc2b97b062a938e70d69be20da8256ff4695c109ed6ab92dde5823d1ab14f039995bf2ad41cb6e8bd94cb33684e207b461ca309273fb50c3197f44d69e29b368fd5c9323a2bb7215ec3ba863cd53d432779049fa8a3fc554b01df06eac29d760ba1c99cb3391dc26c97e3ebc74e14a9d8b1ef33d865dcc33e557af0cf76dc224dd31be66e74e92c656b328d77da346c81c9c864dee3a95cf41ba67f97183a920df32d24aa08906c151ae6cfa7e5f17d435a18c07da6f2f98ed52ce25bd0df27c44c99f31ab5ab421e7907526de3bcd4a91bc67fa30a315f361898102b023c67853db2acc3986b946d50eac8d1fc0629d27f641dc6acf0d965db82ff24ba90cc534e27c6fe6'
      );
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'ledge dispel arrow dingus carnal eddy zipper airy cosmic layer aloof fully signal plate curse grab pony assist icon wreck rudder arcane glance cakile tace thesis quay square rhine david naples virus raid petty hound rival feat burma shrine lewis hold active price held await career meet havoc sold curl saga paste peru bovine altar module hedge poem rhyme prefer fairly fierce oracle glib pin unkind great shabby treaty rust area hammer scent venom walk alert silken hold david volley stunt mortal bull purely jest beet runway robust range clammy deduce insert hidden than sullen casual zaire hero screen parcel hoard mystic talent lose spend rave vacuum oily genius clasp duel rhexia middle nephew refer helium than layman grit picket mutton draft firm cousin limp fate pair orange herb steel namely demo ruby buyer turf rosa had static stair chart mostly past mental woods follow acre valet trot cider just roll sit sleeve deeply swear human liar tundra joy beige pack real view street glide sent tight lawn ate kernel seed feat cover tokyo topaz trauma shiver holy chilly knack pier hull brave silk fed those nimble virus root linger invade depart bust vienna spinus prefix mean hound flank tonal win tip blast earl pencil school suite victim ocean state socket geneva auntie check eerily omega cove resign relief brush motion flew take sacred exit bowl hefty picket picnic gosh grim nylon adjust actual shoe magnet super punk defy hopple energy first pump spiky scent cider cheer haiti sweep puppy auburn hasty rinse your facial mourn sharp feel left year';

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });

  describe('seedBinToMnemonic', () => {
    it('should generate mnemonic from binary, with input[216, 6...]', () => {
      const input = getUInt8ArrayFromHex(
        'd806cbcdb829b5be1a354311bae3f8cef4adce0f10e47a2268acc80074bc89d972e86badab52cfe5f891e064041548d9'
      );
      const mnemonic = seedBinToMnemonic(input);
      const expectedMnemonic =
        'strap humble snug loudly resin tera curl could rotten dower solely expect social vast thug person hemp smart abode factor melt note toxin rotor proper clutch tip meant tehran dread bend mite';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[68, 138...]', () => {
      const input = getUInt8ArrayFromHex(
        '448a88928517c812db0e629262b3fb610ff9ae933cb6a327e6daa202a94eaf75b61834ece6759d0554c3832f20cf6d05'
      );
      const mnemonic = seedBinToMnemonic(input);
      const expectedMnemonic =
        'edit popery mutual flair sight coffee avail choose guess draft greek zigzag quilt crop revive crater tone pretty adhere nest radar gave blink ferry told gag albeit falcon lowest verbal son soul';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[10, 200...]', () => {
      const input = getUInt8ArrayFromHex(
        '0ac8bbebfc17e6300c4a5024e71ea44b6ac879146a7631314617b8dd02e0bb015ef6656b4e52a885d573f57d6844de54'
      );
      const mnemonic = seedBinToMnemonic(input);
      const expectedMnemonic =
        'arm midas tunic seam toast abra exempt acute tool tried eyed pump lady enamel karate bay embark leaf sword coke rough bestow warp frail fell claim male freer wait stiff effect tiger';

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });

  describe('extendedSeedBinToMnemonic', () => {
    it('should generate mnemonic from binary, with input[51, 195...]', () => {
      const input = getUInt8ArrayFromHex(
        '33c3c2f97a4d96517e3d06c3787a5cdc66ab4db93f3f7b58858b4c1b6b1a36918fe93a69bab1d3bf1b858e5436a8cd546e5ccb'
      );
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'crop diary wholly pivot noisy blaze dire house koran play sweep hoard fauna near dove resent main renal bound react dallas blunt travel plump rosy brew satin ripen modify early port statue ignore smell';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[61, 200...]', () => {
      const input = getUInt8ArrayFromHex(
        '3dc8184fe018bf358c0d5480b54214a2cd5cce59d8f761553e40347948cc57404eb00c0c50a29ad99a220d6603238666f2d38d'
      );
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'divine lone file ache saturn fulfil attach equip repine buy photo steel sodium pack weary bended dole aerial lake mine freeze aim rain scotch finish chrome submit person attain grass cane havoc vicar decree';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[155, 172...]', () => {
      const input = getUInt8ArrayFromHex(
        '9bac999fd10b120f85982ceee0e2bbae1519a609ee1dc9df7da1d0f3b8c6bd590ad7e6eb362092ccf2d9f4ce0f78ae77ca7f95'
      );
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'orient sit pastor ballad barrel what oak sole tenant climb quebec flame plead pardon brink paid let bred viola milk safer mould strait import dad anti smite cocoa voice tend kuwait torch slab who';

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });

  describe('mnemonicToBin', () => {
    it('should throw an error if the word count is not even', () => {
      const mnemonic = 'latch supply taxi';

      expect(() => mnemonicToBin(mnemonic)).to.throw(`Word count = ${mnemonic.split(' ').length} must be even`);
    });

    it('should throw an error if the word is invalid or does not exist in word list', () => {
      const mnemonic = 'quantum design';

      expect(() => mnemonicToBin(mnemonic)).to.throw('Invalid word in mnemonic');
    });

    it('should generate binary from mnemonic, with valid 2 words', () => {
      const mnemonic = 'italy india';
      const binary = mnemonicToBin(mnemonic);
      const expectedBinary = getUInt8ArrayFromHex('72b6f3');

      expect(binary).to.deep.equal(expectedBinary);
    });

    it('should generate binary from mnemonic, with valid 254 words', () => {
      const mnemonic =
        'easel within gallop caught severe pizza stern rear awful shame bend suez chalet ankle shock drool engage jacob guest hardly driver pit iron gong gaucho pile room carbon genius idiom eater utter grab cheat lawful koran rife lid sirius shyly otter naval magic moth proper crypt object swap caesar fabric steak monday warsaw artist group rob sonic binary her mud useful scout vase week debt rule waiter safer figure nurse india did timber viral punish shrub ripple lamp glib world mosque bulb demand friday short hazel draw slater weight twelve knit sudden barber edict cost energy mentor gothic belt dispel rarely scotch real surf let cat fiery above audio panel beat never spirit pedal export poland hour zero olive grid permit recess ever elicit amend stop cyclic denial sword haste akin ploy brink murky join would order sponge age naples cast carpet pine stot pride track sentry torch grin shawl smelly wedge maya expect via noun sudan sweat logic bush help crazy risk item stark malt libel jockey spite chunk audit simian altar spout kick camera buyer mutual flame always stiff mainly envoy stroll branch data trial soften rosy doubt bent rugby worm kiss again throw other war employ adobe andrew expose burnt spinus parish pillow retire franc spill fuzzy aloud canvas gentle tame day wine ivan tax khowar vague sorry greasy geneva before eric goose soothe stamp motive serene teeth locate solo bran obese pink moor ring gravel misty later intend vision whisky mary sinful comedy lunch seize summer plaguy wren danger campus';
      const binary = mnemonicToBin(mnemonic);
      const expectedBinary = getUInt8ArrayFromHex(
        '43afb95a525bc41a4fd64b220f3c4e154da226b08dc6641146e73262c651410a4a7225ee5b2a3cba52425bf6e0441f015fa27b7ae787b7c7e8c97c7c9c193c851905ab5349987dbf21f4b7d598edf670bb623b92cfa16e68d916efdc0df0ff7a385bbcf58bd54fd9806f33c5e5af3eacbc77b867975dbfcb9011f43a0579c6b66c402caff7deca782da011744730a46d8a45f71523d8b0bc0cb1edb97da2574f900b0da9e7139950d26a0f4b0a766c2ff899e615a21b2749645b07bd7535e3a4dd065b052a671dc91c748fd29b8d2c04093525424ca43d7aaa4e88c34e77619c54cccf778894adf2b977d9fdc381520c689329b8872cd4f8607e4746d2729b0dbc8c073d3177322e215928519075d68859479d8f1c5376e9fce8bab3f4157bbafcc77a03fe449c0f6146702e0854b1207d249f1a3fb6456dd2059b06f23d5c1de937afab72edfb772f04d0360b5bd1444845f0cffd48908c37e0580ecf21c4985a448f6b816078d87a6715f43f9387dc902ea83ec26daba53fd836e230'
      );

      expect(binary).to.deep.equal(expectedBinary);
    });
  });

  describe('mnemonicToSeedBin', () => {
    it('should throw an error if the binary output length is not equal to SEED_SIZE', () => {
      const mnemonic = 'latch supply taxi india';

      expect(() => mnemonicToSeedBin(mnemonic)).to.throw('Unexpected MnemonicToSeedBin output size');
    });

    it('should generate seed binary of size SEED_SIZE from mnemonic', () => {
      const mnemonic =
        'reduce upon divert lean bird border smoke audio sydney form helm that amid robust famous crater saber nose shadow falcon sale flash blend candle pale crown injure creole govern brew flux mighty';
      const seedBinary = mnemonicToSeedBin(mnemonic);

      expect(seedBinary).to.have.length(COMMON.SEED_SIZE);
    });

    it('should generate seed binary from mnemonic', () => {
      const mnemonic =
        'decor help decade slate follow tenant june hare unruly malt order spat greed sodium mole sinful phrase tenor obey exist sugar cuff pest hybrid scute survey sail galaxy away eaten borrow aha';
      const seedBinary = mnemonicToSeedBin(mnemonic);
      const expectedSeedBinary = getUInt8ArrayFromHex(
        '38c689387cae54be0e75a652ee78609b8d1260ece58e9c90a2de149864a8da434ea246d7c14dbbbdb5a00f24401ac04a'
      );

      expect(seedBinary).to.deep.equal(expectedSeedBinary);
    });
  });

  describe('mnemonicToExtendedSeedBin', () => {
    it('should throw an error if the binary output length is not equal to SEED_SIZE', () => {
      const mnemonic = 'that amid robust famous';

      expect(() => mnemonicToExtendedSeedBin(mnemonic)).to.throw('Unexpected MnemonicToExtendedSeedBin output size');
    });

    it('should generate extended seed binary of size EXTENDED_SEED_SIZE from mnemonic', () => {
      const mnemonic =
        'soup jolt cook fill sonar orphan orbit taurus gene japan baby sydney cease heard clash alley birth theory caesar pile ledge karl packet cuff locate spill bout dour sample roar cinema leaf role river';
      const extendedSeedBinary = mnemonicToExtendedSeedBin(mnemonic);

      expect(extendedSeedBinary).to.have.length(COMMON.EXTENDED_SEED_SIZE);
    });

    it('should generate extended seed binary from mnemonic', () => {
      const mnemonic =
        'law unfair domino ballot got buck sandy why melt except amiss flee prove cried herd verge fully mosaic popery super opium loan wipe rough clout gate gather cloud import clause lovely slump seed splash';
      const extendedSeedBinary = mnemonicToExtendedSeedBin(mnemonic);
      const expectedSeedBinary = getUInt8ArrayFromHex(
        '7adedd3ea10d5f61ebbedf9a89d4a007e521ab9336690f2158e8fea88db29ae80afb1bb02c95b05b12c76eb2af82ecc6c22d28'
      );

      expect(extendedSeedBinary).to.deep.equal(expectedSeedBinary);
    });
  });
});

describe('Additional test cases for [helper]', () => {
  describe('Tests for binToMnemonic and mnemonicToBin', () => {
    const extendedSeed = {
      '0105005ece2c787198e40d843e9696d0cf67373a0c7e110c475651928ae49e6764368ecce53914f8dbc62fa2571d3bf93aeff6':
        'absorb filled golf thesis koran body thrive streak dome heroic spain warsaw darken peak lewis ballet enter hardly mutual quest panama karl dale twice tier mucky which rust cool cat brew saxon depth zebra',
      '010200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000':
        'absorb bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback',
      '0104005969b326db865bb694a878e95b627e4a79d844891a2e0790d8011ea59ee47a119e1bc0a734593911d35515eeb2c46cc6':
        'absorb drank fusion orange chalky ripple gender hernia pope mole gave cheeky exile pack edit mummy coke laden strap barn plant unkind last bond bowl are crush native barley curlew bestow truly shady slump',
      '020600f429397626f9130f959cda184fa240b263a3699d481ce91141b718c733b53a8ba1a1f5a70972aa09cf5b0d100e27da5c':
        'action grape visa native kansas infant battle who owe pencil fifth cape recent demure heyday stamp break mrs due invade shrill desk deny roll peril game anyway clan appeal walker atlas abrupt cheek play',
      '0006007a0946f171a8b4ca0d44d8d78136286bb1d408923c99f8e58f5a4013852675a76930e00b82e9fc666e1dd30203a96b53':
        'aback grape laser needle velvet booze renal pear effect mist lofty grudge horror brick angle canopy omega modify moon pilot beard flew june keep cotton above lovely pastel havoc test spouse burial pour repent',
    };

    it('TestBinToMnemonic', () => {
      Object.getOwnPropertyNames(extendedSeed).forEach((eSeedStr) => {
        const eSeedArray = [];
        for (let c = 0; c < eSeedStr.length; c += 2) {
          eSeedArray.push(parseInt(eSeedStr.substring(c, c + 2), 16));
        }
        const eSeed = new Uint8Array(eSeedArray);
        const mnemonic = extendedSeedBinToMnemonic(eSeed);
        const expectedMnemonic = extendedSeed[eSeedStr];

        expect(mnemonic).to.equal(expectedMnemonic);
      });
    });

    it('TestMnemonicToBin', () => {
      Object.getOwnPropertyNames(extendedSeed).forEach((expectedESeed) => {
        const mnemonic = extendedSeed[expectedESeed];
        const eSeed = mnemonicToExtendedSeedBin(mnemonic);
        const eSeedStr = Array.from(eSeed, (byte) => byte.toString(16).padStart(2, '0')).join('');

        expect(expectedESeed).to.equal(eSeedStr);
      });
    });
  });

  describe('SeedBinToMnemonic', () => {
    const mnemonic =
      'veto waiter rail aroma aunt chess fiend than sahara unwary punk dawn belong agent sane reefy loyal from judas clean paste rho madam poor pay convoy duty circa hybrid circus exempt splash';
    const HEXSEED = 'f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb7184da84a092f842b2a06d72a24a5d28';

    it('should throw if seed byte count is not a multiple of 3 ', () => {
      expect(() => {
        seedBinToMnemonic(Buffer.from(new Uint8Array(47)));
      }).to.throw();
    });
    it('does not throw if seed byte count is a multiple of 3 ', () => {
      expect(() => {
        seedBinToMnemonic(Buffer.from(new Uint8Array(48)));
      }).to.not.throw();
    });
    it('produces a 32 word list from 48 bytes of passed data', () => {
      expect(seedBinToMnemonic(Buffer.from(new Uint8Array(48))).split(' ').length).to.equal(32);
    });
    it('produces valid mnemonic from hexseed', () => {
      const mnemonicOutput = seedBinToMnemonic(Buffer.from(HEXSEED, 'hex'));
      expect(mnemonicOutput).to.equal(mnemonic);
    });
  });

  describe('MnemonicToSeedBin', () => {
    const mnemonic =
      'veto waiter rail aroma aunt chess fiend than sahara unwary punk dawn belong agent sane reefy loyal from judas clean paste rho madam poor pay convoy duty circa hybrid circus exempt splash';
    const HEXSEED = 'f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb7184da84a092f842b2a06d72a24a5d28';

    it('should produce 48 bytes of hexseed from 32 word mnemonic', () => {
      const output = mnemonicToSeedBin(mnemonic);
      expect(output.length).to.equal(48);
    });
    it('should produce valid hexseed from valid input mnemonic', () => {
      const output = mnemonicToSeedBin(mnemonic);
      expect(Buffer.from(output).toString('hex')).to.equal(HEXSEED);
    });
    it('should throw if word count is odd', () => {
      const invalidMnemonic =
        'veto waiter rail aroma aunt chess fiend than sahara unwary punk dawn belong agent sane reefy loyal from judas clean paste rho madam poor pay convoy duty circa hybrid circus exempt';
      expect(() => {
        mnemonicToSeedBin(invalidMnemonic);
      }).to.throw();
    });
    it('should throw if there is invalid word in mnemonic', () => {
      const invalidMnemonic =
        'veto waiter rail aroma aunt chess fiend than sahara unwary punk dawn belong agent sane reefy loyal from judas clean paste rho madam poor pay convoy duty circa hybrid circus exempt splashed';
      expect(() => {
        mnemonicToSeedBin(invalidMnemonic);
      }).to.throw();
    });
    it('should throw seed output size is invalid', () => {
      const invalidMnemonic = 'veto waiter';
      expect(() => {
        mnemonicToSeedBin(invalidMnemonic);
      }).to.throw();
    });
  });
});
