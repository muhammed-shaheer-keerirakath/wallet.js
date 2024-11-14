import dilithium = require("./dilithium/dilithium.js");
import helper = require("./utils/helper.js");
import xmss = require("./xmss/xmss.js");
import xmssFast = require("./xmss/xmssFast.js");
export declare let Dilithium: typeof dilithium.Dilithium;
export declare let extractMessage: typeof dilithium.extractMessage;
export declare let extractSignature: typeof dilithium.extractSignature;
export declare let getDilithiumAddressFromPK: typeof dilithium.getDilithiumAddressFromPK;
export declare let getDilithiumDescriptor: typeof dilithium.getDilithiumDescriptor;
export declare let isValidDilithiumAddress: typeof dilithium.isValidDilithiumAddress;
export declare let mnemonicToSeedBin: typeof helper.mnemonicToSeedBin;
export declare let seedBinToMnemonic: typeof helper.seedBinToMnemonic;
export declare let WORD_LIST: string[];
export { xmss, xmssFast };
//# sourceMappingURL=index.d.ts.map