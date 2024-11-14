type WOTSParams = {
    len1: Uint32Array[number];
    len2: Uint32Array[number];
    len: Uint32Array[number];
    n: Uint32Array[number];
    w: Uint32Array[number];
    logW: Uint32Array[number];
    keySize: Uint32Array[number];
};
type XMSSParams = {
    wotsParams: WOTSParams;
    n: Uint32Array[number];
    h: Uint32Array[number];
    k: Uint32Array[number];
};
type HashFunction = Uint32Array[number];
type TreeHashInst = {
    h: Uint32Array[number];
    nextIdx: Uint32Array[number];
    stackUsage: Uint32Array[number];
    completed: Uint8Array[number];
    node: Uint8Array;
};
type BDSState = {
    stack: Uint8Array;
    stackOffset: Uint32Array[number];
    stackLevels: Uint8Array;
    auth: Uint8Array;
    keep: Uint8Array;
    treeHash: TreeHashInst[];
    retain: Uint8Array;
    nextLeaf: Uint32Array[number];
};
type SignatureType = Uint32Array[number];
type AddrFormatType = Uint32Array[number];
type QRLDescriptor = {
    hashFunction: HashFunction;
    signatureType: SignatureType;
    height: Uint8Array[number];
    addrFormatType: AddrFormatType;
    getHeight: () => Uint8Array[number];
    getHashFunction: () => HashFunction;
    getSignatureType: () => SignatureType;
    getAddrFormatType: () => AddrFormatType;
    getBytes: () => Uint8Array;
};
type SignatureReturnType = {
    sigMsg: Uint8Array | null;
    error: string | null;
};
type XMSS = {
    xmssParams: XMSSParams;
    hashFunction: HashFunction;
    height: Uint8Array[number];
    sk: Uint8Array;
    seed: Uint8Array;
    bdsState: BDSState;
    desc: QRLDescriptor;
    setIndex: (newIndex: Uint32Array[number]) => void;
    getHeight: () => Uint8Array[number];
    getPKSeed: () => Uint8Array;
    getSeed: () => Uint8Array;
    getExtendedSeed: () => Uint8Array;
    getHexSeed: () => string;
    getMnemonic: () => string;
    getRoot: () => Uint8Array;
    getPK: () => Uint8Array;
    getSK: () => Uint8Array;
    getAddress: () => Uint8Array;
    getIndex: () => Uint32Array[number];
    sign: (message: Uint8Array) => SignatureReturnType;
};
//# sourceMappingURL=typedefs.d.ts.map