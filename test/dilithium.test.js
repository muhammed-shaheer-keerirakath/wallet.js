const { CryptoPublicKeyBytes, CryptoSecretKeyBytes, CryptoBytes } = require('@theqrl/dilithium5');

const { expect } = require('chai');

const {
  Dilithium,
  getDilithiumDescriptor,
  openMessage,
  verifyMessage,
  extractMessage,
  extractSignature,
  getDilithiumAddressFromPK,
  isValidDilithiumAddress,
} = require('../src/dilithium/dilithium.js');

const DilithiumWallet = Dilithium;

// const HASHEDSEED = '8078f74eb51029b5b96cfbe2bd0ab8433252bf4c6c8fbad92789add5e3cca216';
const HEXSEED = 'f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb7184da84a092f842b2a06d72a24a5d28';
const PK =
  'da218daf9d5457bee0e2381250f7ad3159e8a243fbf90e02c2802e1722cee954758875aa00c57adda2736030ea7fd293367c202298d7125f4ca8bd83d0ee8e8805f4a9f2d3915d507a581d59a80491575ed69ed994a6650ecf8902cb056a6d5f8b59a46905ab1c58094c2a5a388de306486dbc23bf268ffa272e010182e8e9e23c07f55a866e59195333a353aeddf3cd51c22f955c21977d3ee9e4ee6557f30edb5d2517c04f834f6825a7a162323cb8b679cb5d2089190aa3e3c486b4b9895987b47e1b475ccc4f25969bc95ac24d2fb3cfcda7330ff9f949ac06a2b7a7293ee8463dc38a9c55d4bb5d8f4904836c29764931b0c3f4d1257871b132b08ae249fb40b61bb75360298f15345d4868b7aa4f06c485b703f6db84d2d5e1e70412928d6c6454a2a019540c518243e18e17404dfd781a576a34e0f297bc4fa69532e717cb9cadc1feafe4c6a99e31cde842dc05fd19d8c7131d530e9ab22b1c621e9d4a2ffd444376f0e0847c0523f56f345669fe88bb28492ed23dc822f83be85eb035695eceb08fb24fab3fb6cd54ee5972d68664af9d3bb4213da1ee11e95070eb45d033777eccf9efe54f2f23bdd0fd64cd0b4bd311d941f108fa13166505944de90e25fe50d4d4be8118d316994b53bacb96c92a4f4048e10fb01d7a8e89d7d0ba37f58ba37e1c399fd1d5c2fd0ba1d30231432a0592d0e06b0a18f0decaa3ef39e88c6d70b42bcc80e28f633c99a89e411d300ff78c7bc93f910906bc9d9202f4ce3b9a1c37432b4df23e053297f81b965ca0b1f447e323a2e66c9ffb75ab1c8daa2a9b239bd87bed1990f4dbf9747005950aa73b6a74da306342a63dfb67d5042f16814f08bd3fda8b572e501ce0a03111f93c0c1d3655634435f1ffc3fc000bf133c926bc336304eea648a7a1c7ebdd65fa593d5c11990878b385499a394584702fe309073aa15420e0d0980165ae7213dae40890babb2bbd3f7abf648c9dc74feba7c0ec8f0525bf5744744b9f5b28f6ac7f234e4f425f4bbafb69714abd911dd0514fd53039c13f72b1074f6c5a229f9172628747079193592bf74ac9049c2aed7823e9522ffeffb7d84887808a5e0814407ebbf514301fb015a3f0fa0c79d3fea883901f3bfc493569a239156f29364a1b43aeb4c3dc6a975ba517e1a6e8ca66b60e4de5326d2d65d95783b050546c73edc37175bf2dac38109c4cc6711c4f6ce4b7af5313e1967161841c11cbbd4f998d5d6b6b1135c9c75616ec88393300c199a2d602f6b048302258c6bf8960434ba6d3d6108a9d8fe17569c1454aedaa7b383975f3ecf1565df1e007744b9474111756a9b4471475dac9e55bb5eb1df67329aa077c14bb8aebac457ad06744e6b67238e1416e14a1c8c84d7981bb42b41562b10b9ba86809f47d19bb2c6a8a9f88559a9a73fecc7f95d781501095fd0f7493ecb020b35b613e2c91db655a9c85ae893e4da69e1ad833fb40c285f09992dbb6b18f154b198af34e3088928102e618722412934ff0bff977d9195d3eb520f8edb7cb08ffc9eeb0f60d02d8272652e456fdd28392acb41ce12fadc83c70dd742abd2015805f2b3713995d1d99050f08f9f88366cf5870b827dadc5bd20fdeacd672df857330be4e1b96838a0d8e97859fd7127d355e51ff9a5e43697b3cedaa1d62dd3aabe28fef97eae5cfec98399bc66f7a34616f95dcebf7eb6563a9115c13c46a80d564e669af08ce600ba0fec9f15a9422b1da6c3995cbff0212626c118ddf77721d84c938200bc9618e7234e3137053eb16620942e9632684e73163f0daad57327999e800c226a09c7083581e3b647cbd61e42a986ecb52f8e64e4d3efdb3fb942ebf2d1638a5c567115e6d33436e2f515e15b903e727d22c1945c968fd1ba1d87093e7768b75cd6033f2826580e85bd7c96477a62b1956a8f7aaba88d7ae095812acc9b9c33a477f3f920e49c7443bba90561b7804f6fe2bba598103507c61365bc11aea34f9f84c0e3a902eb6df4c292aead67699a63c1f5a4b87beb14b2e45537841902764b459b90ba378aadfdcd125deb953413fec2e3e1e3b4f6e435ae84cc7951b996a03db7e49cd1ddeda2041c99eff5dc9c85ffa383852ba9f9dde80cfe8c0353a6faa24a5ae307b8bd863c14f6a9b5b75daf8534118131b3b32b8239f51f6d5123ced24e9bd251d208ca40fa97f9e47fa79f25ede38280a5206c10281a8d4a8459fb0fe9dece2cc61f1ced84e7b5744e59312e32de10c82be7f81264d3a775a04913ce7bb1f28c25037f4b3b2ad5790b3667c9e309234cd161c36f7a71a0145ff0a7c9c1b9bed601b4971696c1979ac3ae2418a842e50c33ed45fddd0e319e48f72583cb90a4b08a57983f63918352cbc6f0a6d345c845f0f2cfbebc25cef454dfcdde04966e63e37d0b2060a12bdedfe3758c5f38a3c7250271ce9dded0e2c37304bbf668add831f76902d42041b9e7a2d77e9e912980be070a0dd84f3523055a86d84b7d92282974ec8f411e26aa88286b6a1314ea9a0b3d3ab100947770238d6a714d0e2ac9a1b7b3cff7e54c33d8bf7a40972418dc7fb205d7c29a8ad0a269eb9f0874e1ae2d37485e9fac92bce8c267d2feaa63f1fe186ae0cd25b626246b2db984941fa6eeb2b2ab14a56aaf15da2458b591b4862173a917a404725b9fee25539b948b2e2c9c5f2a251e9f88cd301715aa221e710228a0e1c691e0ea91414d7ddc6cbe76b572dd904b8107e4472e5e0d694ec8e4cf29c79ca83206c9a8fcb8e77a1157b4f7c9a68ab41520b5e2c0c9af6d11109c259ab5dc8d1f87bc83ebeb4a8845519833e42883ad7b16752b2ffbdc53ececca688b97b431a33d4223dcc32be985ea66f255ae44df027713ae10120e3bcc2eac966d974cc6e69449e959d7eb783855f975d36a8a5d5889db3137b338cabba16284d87965493bb07cc5639bb017499d5a59049a65fd5a0a58568c8c93677491b45b3099dd3ab9527dcb9455d42e7c22278dd800187a8fa016ad0ae3a5737f5ac6fbec043576cf5298150daba87066fb20ee074dfbfb330f4d9321834b35b43e9448997b254e78e1f2c5a4d757e4dc5bfee53dedcc863c539273d7135b063b724bc0edf153fd1f2828866801673c068442b38bcf45ea3bc006b84aaef5e8cc1de1d00e10484b3a59546c4b729595bde6a7facb5e1f6a041dd52307ec9ca2d1ca891eca2e2f0803ddac1698d6cc07d4ee381c06e9d232676c1acfa03287000c44afdf6c1613fa3ae499acd852f8a43dee5f2f790ab6b56a3010d6f35b6d0d3d185540f21593b8d8e75c4938192706ae087555ebc1e48882f1ee46af8256964d7fd4fb9bb6ffa60f79036b17e46d7f210c25fb1690a748dcf33ae74b1f44290fe1a46b87333def13630cc17e7e1290593775b043f817e603675dd16ceb159b4ee6d43799c2ae23984465e0942a64e30da1271d5e6194585d3ecdfe2302d4cae4ca388a516184e333f0d87103ab6585a955be8c7708c338fe1775b04486721b008cf99fd1f6d1a0d1027d975b21086fd42d4037f7979eac9e22108432401aff3443c5aec62e5a7c44bcda3d0ccc0e1b56c611f69b84500d2649f852190eedd1eb9a121d476dd26f81c6a52859c1de36066e8ce44a9f2edf94717b0fe445caddb';
const SK =
  'da218daf9d5457bee0e2381250f7ad3159e8a243fbf90e02c2802e1722cee9540b5e62cb0091be3c87a916e8f74d930b2e2d855068b043512edb1227b8727e035741cda59a36b5b2a7f520f05f99d76d9a34cdd2694c4dc703930a6fbbc1d402821440e3804d918065543042a0084ed8146e03895181266c0907092434509230899110908a2620092226a2185003809001002800294c5a9884120589dc0288d40269423460c3a0801ac9444bc60c5b14514bc400ca804523842de326851ab02d4408698b0601a2b68122c98c09b604609865102310e1060650b42d0c174e1c970d63008158402ae0484e03a86dcc18729b2621e0a408d2a630dc20251ab80518c1689002929c46061c808c5c4444a3842418b60104c0094122129992008084252085610215041c8870dc32061cb460e11829cca60001012652226acc1640d0221014a74d1246881c30201b4520143552c31412cc88459340100b0082448288dc042d4c380820173024a07183a6851a435009926082a40882a6858930012220069ab6705c44421401891c3565008244c922100cb52c88040294384a14238e5c929119867140888422054ed332680320421b4826d3280123468da31669e41206c2027104078cc9b2298ac62408364854a4600a470ae0c0000a058e0c43409136645c189108b77040c248d8886148a860130110d440484a3402c1a608d9001100838418254e90940103383062a8290a074019932521171013446048806c0104014bb490e4806004434e14896c913231cb146123478298b88c2406510c952908a881133428a00848224029e0440058b690082588220024923228e308520846101b84050a1745903422e0821119384ae2265259182244280ea3968492448e21116d21168512906c091025d010921ca491122932002844191311cc342450308894142098468c1036524820811b224e0035480bc98583b80d230224cb922c61346a628884e4b49008890019b02960b02d1a32111ba0514496900291094b96299b9670d40480d1122ae0a8040a220243a88484426a001990a49049211129c8885109232c94040d20b62dc0b811cba0490840520033851239489340454216701b1811042380d33089dbc82401380984386621488dc38001e30844091401540672c3863123214cd8c62c9b2642042340933864c1446a0c22241aa824cc007204a969e0902ddb060ec286911204850a131284c00c649851592845db28820c982120c429602002da240e62288e600284648848e41086cb929009448d88126d4904285a24264a3665db309019110250181183824183b03063a669c3a084d80884e39870491200099745e2c02182202a63c400e018851828915b288408c189922472a1202883126589c464cb962d113072e1308ed816420883441882889c104954124a09042404142da49021481044c24604a0c86401a54d82486503c8851c95454c34916026514394891a136c0b06895ac44121398590a48d834609230425d3149142088002b62004324d00a34889162e903068c0345224c0684b1252e108214c422cda386a22134600008cd1386cca90919aa88820450a94a24121268918354e88929120004412866d8118661144668aa891098864093051192288483066114271e1220018b77020876cda4832c926621c1770928451a1408d64048d103880000282c8c4688ca268a2c82821a36911c3095cc0500a99600a08620c36101b47319a3266e1c00d029889c9246c08c6300c108c2208040b37811b27015a02215bb0010a36314c8885c9a48d11a08c8a862124b5042221010c872904094851a60509106acc448a21c391e2b46414c3115ab60862c0641a28824ab081d82262a316082424461c8328198428c2066e03432c20196e0bb765c8a031a316029b14058a228ec34252c2b00561a2491c144441161294242089b49100a86d480262591061d4c044a1a265c4344e11038190322a59a2842240618c4440a09849d1964d44266062088920920c0a1812520866c22470049230242886cc98205b26444b202c18b2619c086a98428c8ac020a49410e292290a09322080701c2522a22632122892d3342e14828903068d1ca45083344880322908336a1ca941c11065c800518928105c042a0b856991e93f35659d3f7b11bbfc3443dd48cb0e3cdc35be09f092124908b0344c0fd5d1595ff2bd9473f854280d2bcd9377d6129f3f105f16d80899dd16d5c452bc002b14cc5304b98099f4f189dc344f3d77bff6e0aa03511969012ec0e857a3d8ab31cf08ed1a48be59bb0f9b2bf9a8a4d4c6a35d45fefd45b7c7f792db793d236f52605ed7a80dd4e8e9696a44c7d5232bbad92c80b54afc61ded07a01645ba70e8f6181d6ad479d2e0db5fc59a46b251243422d03d2048fd1c1cb55c70b03dd55eacb3d96a91ea2941d1aa01ab1552b8b22caa17a83e4bd740b1e998526eabf5bacaf31a0d088c1d0419bd666f4b468c408ef8bad59e61d47d235f1ff7369701a849c59ba9cb79699a66d03c67d650552f5d4bab6e09ad17a4dc5190eeba879ce2d104c34f183119802154b146057e44942af4a107017d9fc057bab642e920a3596cc500fe2e71009a1b6b51c0e55eab2c08ed2c1e05a28046b0024a7e64f7307c1927960fe6dc275db066f617b6c33d6dd295c300e8421563b040921306db9eec5d92a8f426d9d02a9afc4ca4b6b81f28a70af6a06ac275218235395d40310b9b1190171ae17ebfe24127d3761874e5c49817e763b251a07d1dfa3d15d7ec26b52f695cc8023a74cd418c579952a9e0a59cd4712a2171e63027c43def6a3627b154d43177ee2a9f9e63886764c98c0b0705156daf132e41a458cfdf836cfcaf5ed0c6bda497eaffca3b50e83791811d10985e89bf0bafb9b24a94dbdc65a895791eae3a72a6e6ced4799dcedde9e136060fc6a2da86f4d91106847003e621d3f51fdfbda193e44162c3369cf6bc4a0db9cffe70d1fc4b4735fb975c0c1dd200128d9942a03d946570036f2513b9d4745c2a0a0a76b66485528be114a77c146c69f8ae352557ea80518a00e49a153a12bbed470d921dbaf89748f23f9b84ae2e91c705a3a47f70a11420e7d68cbb412fa046f9021ab7f34cab78bc4ab6ce1f88f1791185cd74803ccaec6098406fb3e6b9b4ef390d1e2523cca02c6fe5e71adcd52f65e0e384fff1a404ad09b9b9d9b74e669000440ef5a54dded018fa838ebf075cd3201d225c178a56a2efa5f6438f0a9c0e8e9adca7980943e8824e191f862ec5c3bd7659b3a13978d6ca6ee41440797d451cf6c2c25ff7a6f52bddc35da446b0fc05cc6f664361a5f3feb4509aeb500f6811c6582fc428c4741bde88ae91ccab1eab7e1a18ea7a10b393ea9d84b26621e8b23dd86aa899b408cf3a3dee902d697b91314d8c1ec14319cf9fff43a63b4e832feaaba33363dce8c8a3534b843f4c47a42f29bf275f152a9c0400fa0efa666bc4edee127c0684958b3e050428cd8d4397be14540267916b36ec1325b352a7657693f16219eaf7d0ec05d925c8e5c563f935c16aea2e843ac24c395ecd6e35ce8a8ea61f866d1f2562254a1d782a27ed46ca258b0f7de78a2ed0d5391c5cc35954da52ca7bb85d4dc0bb5d894a7aeda4dc8a0683e49d80fe9831b975871fc19d1fe0394ade47f7d2982a316d08c29cee8a3add11367503ab528fac173987ec411553359f83b61e9659133c7f27471934556ea5d3574b814d811907f9dd25d9b2c3f1ad2aba5ab2cbf7417cd7a41cf249a5205063c52fcc20badfacb9e3202a78edb047709d56448058cd6515f8c0f08e5073a62eca1961f1bdcbb335ab6c333df3ca765f45c5ee5e8717e32626bde1c2bdc40633832efc2eb3ee52bd552a3a1c242da37f55f171766a2f36caa6a8a8c227677bc159a40207bea82f03bbf4a8b9563e94d5506f1a25346c2de761451cbaa2527ad4fa182f11baf7ff9bf5096498dd25587a245e097dd837593a7a2636ac878d136781c265983bbf0740320e98edfb312448bea66b38e087edf2ae13a8bca6798fb94abbdb36360567ab84332ab6ff2b77d9383f6c117d525ba7f3d31a79e101e15fb5a24f243ba7ebebfdcbc27ccb567a3125506f9f6e3254218068d892bbc11d1dc8c23bd5995329f829d02bc1bcff3f934e2104f91eb98b7d0830bfc8399f0992f7aafd0ad2ad1fb472d946406381320412260f90fd6dbb851022330d86cc3c8caa27f70f46e2335cc8775cd028c8d08a3956b44211be8cab10447f7dc7a981370e9d623a03f892ebd7f82a6562facd3a535197f92174328148d5cad8e2ce990167c22e4099b1843a0efeeddc47a190cf991d9d1a8f46a9b9d442a7bfb6c95ce5628626495dda99f1ca937e74f8dd504e6274ee0351157c64ebfb6e072338402aae2cac125cc6938bf1d1b43a04845c64fe8bba7ea16c3273616f0a1666254abfa1c6a47cab4fa53230369d92e301e80e32ef528e9e707202ee034de448a74592834f76ff0429d7bd600f3eea2dcce06e4d10d09eaffa1ed21ec0d2504308d12fa025761794675bd5d75dd7838bbebf974bee0424e968a8b25cf84770660107a0e217e0ecfb97312a04852f68029be7148b3fd42039deb52af700d737df731140832eafdfdc219a4193f804cb2d282807b52d8b2ce05ffeb81861b7433ea643413b4c50ca7858824e00b0ab87d22e9f1e8ee84948fb4443f85d7376859cc20ff2e5a6e9acf11002b868acd3e6464199950ba254093c83983a5aeebd1490a375785a2abb0372f7c9f27b7f66d28cc0c8fc3019f87106f7ff9ddf6d66e3e4ffa872ad4c59837b5837f13e13fdbe1d99612c6a0e016a8567777611a28f694906a0f4c01615fb3ce99788fb529fbf7dc7bd0afefb4c6281ca9af635e7271d9a2c0a77c108b292a05d805ab7b557c77329937a7794eaeb5fd23164decfe33d2a7edd1c00998f168e3a33c8d59dc1bf311ce3a7874e9a1177639dcabd8c98591402fe14e0d29a4b74018b5d7e1498262d6877913df8990e88ada6352a3671d94d54298bdde3ca8992a76113c321812c2526de321c55ae2bb6f7c42868a106a9266dacb4aae9ea925500e876b6f061ea76161d464f88d208c4843aaed1934539c593e0e7318f92f34a9b4d6636e79086f13c5b298004f9077e71b8e159592867d0cd474bdefc595806e6715be347ceaf4a05b8213fae23677f46f697f076a07080f066c6efd5cbd381d5c414fa0225785e50157ffbe93f404458738d33b29f8f798444ba95d0f23e5533bf9097beea2fa4da6fcee69c1b7047327533b46dbdc2622d008f02cf46a2c7368d0ecb1efddfd31e8d3e4f06a420afbe309675c27a8a9d3c47c4ec7827909f770d257b80bcd65db5476282bc1cf555cd0c03905f6f7d6fef2c300d465f20601e96db6b21fc11cec51786a5d0540cad5f94fe6770a4858abd7522effcd0ad1578a9289dfb51427b404eaad1dba801fb3f9da7a5fe86d1f4bb586b8a07ec89b1995d74275dcafca5cfba11492fd1843fa46661645c76fefed8b804981931619c82bef217c70713cc3e21ef97ead5fafe951bbd15d0d91ba81b49bb82cf0acef3b3d6c9a9b00c01d8fccbd253e71baec8d272193846e4be0520bba660582dde0954847e97d8f747d24ef50551c1b4346826f0739be9cb1547600b09e170149ff67536bc55f96abdcd8ec2491d0f8d9154e8431cf6c06855e09ce311582eb78271e4854e0c5b98c9faaded452d7a55b94803cb6a8d5b571f7e6e118312f6d9cdd2bb09d1930e0a1b608a06c7ad5a0bda41c6ddbeac54421c8a4383b7f684bb0c74faedddb6100c1a9b3b19a5645d46e6570da70135c383f19acb7f56b25c2bbfc23a0f00739598d0c00b1edb912275fab346e1ef99ed61201851a5cbb062f3836b26852612ad38dd855911835b73f79ca991727e2589935c98f24d14ca59f1317de7938e4eade460e9bbf51bf5bf26d148bc4b6ad709aff2f63adf93acf77e84b1eca57b748ad0f2952eb99efec9a9536539b880f8140103a1b360a95767652a27787e9e8f9cf8c3e2b7912c7ff9dc772b3e3b3919bf30cf8d626e7fa3d1986bf364fccfac98b337437dcdd6841339a71a6b1ddfd5c5cd59e6ed3848bcdcce7a63cf4df936aa39be758b7c98b36724a012010ef2d3b71a34007494b83eefa94bd26e7d21e6b6378a56dd0dfb6837f20acee1965723db0490a3ac55375d45fcfe119d9ec4a55a507f145189ec3ba2b4181dfcda83d7bef3100dd826f1d89df0391a65f4a79f18fa6c75de83502de768499473e8ba908239e17e31da44fa5679b7a82305c0d5de676cb1242029575613358ce7c723feea343c8888275c018819dd10411243e9f8dd271fd3a9772a3ce1b2fd4c39e4522c8f692a25aaa7da5b05c5fd790ba6a2fa1d154d7bee699d57663990cddfc950c4b713f50a6ac8e7849678caffbf5c90be00d984097358e68d2e32838f7e8e66ab2257616777f080abd5db88a4ecc945a5ab3e5e4c28a49dfa4a8a0e771d15b3551d6fc41ea0e0536d2f590010fecfb25be4110054037073a3efffc749c7af845d85ccab8babd4a0b539907e1624ed69e7cf1fb9456d3b1c4a4be57727e02206cca30ad7cb62801912c147d600e9b48954d9cd2402fbccc4719da7ae98cccfc0b8e2e31bdc7a0fb5b43e63572835bf0f9d1d2da954e4716a70d147dfdcf61241e6831c5b99854e970bf692a2429b9c977c6f5247bd0ee175a2b53d6ce2aa0320291353ee3092507f1f4757c37489d845ad922562f4111dcd680c58ed4a6eb77957daa96dfdc95077815e4ad40ee130768222c9ba6df0c9f5ea3693994061040e9';
const ADDRESS = '2099d76d9a34cdd2694c4dc703930a6fbbc1d402';
const MESSAGE = '00010204060901';
const SIGNATURE =
  '22926804b665610e37e35b0b4a1099599fa0bcbe9b0793333e5394114bab5ab5d5abb376aa20bfdc26d6079e3e2794cba1045f5f8160123dc08ebe3c9172d748ebc2101d3507eb955ca08debf13b826a2a912c48d59f320a985581777370bba3cd0987b1bf4e5d96374f91044f89e01857259b3369ca023a03a4f07e26968b6b4d245e97547bbfe93346791117c39a66b6ede8bf12ac3f2f340f38068b204b5cca5635af61760e4dce59e4bb3c6096872d5305bfcc68aeb8d520df7847965c4da2859d625e66af1988147601f1c983ccd5c08825a7ec81bd1198a42c97837f2d3c52c7c43aa0a0c628c5265bad30a68adfb0469e2b8ec3109ed1a79d392200afd81bf054f5f5e356b2623fa132ad133df4748afb1237b3f768577783f24c9c597c50adcbac6418f947260b1d0bf22d731d5af8e7c2a0ae85eb1bce6e844106f00db40054e591ee58305b5aa4542baf781cac18e581778ba87b4e2e9dba19f09636f65d27f56c70e5c9279d6bc0a566cef04f5f76f5ba0f1ca8f4ed2030c690d0ec15326797144e9d9be7eac6a152b35c5b869dad619e6297e6b4ed3f32db0bbf6dff673d30abd288f47180bf71d46cd2796706768159cad86cb07cc233c8c959dfa2444924b1403c9563e88cd2b9a65612d961e4b15bcb02aca11411250e6aa5f51b579a491fc85545d313bdd4ab8d69b56fb636cad63dfa59f490155b1d1a7eda64924acb461e1ced05c14d288a06e230d0d299998f868b686d9363b6c210477cf61b08eefb9b3c28718776a4b87ef7d9c3a8faee53f6b9ac92b9f96e8b1a496ab702e6d3325a08e488eb4ee253200b9295bb1591e64ade15051ce739d7bf5996c5e2ee22d820e2ab5d3907a26bb2e414fbc98a636b501e694e7ea57b9d2d5ac6d0cb095909dfb3ad7066d4b7dd0223acbaa03b79c3b70c9ae984a23853c9a1bab87d9a28d83dbcf75c1df0169047122ea281d212cb928b8d38fa4e9c797bf8ad278a6df2f9b2b837883ab26d1f5c6892c0a3c579067e1ae1b1c6e15e74d4dbb889e9f3d1b88fe63d3eea14a4ca5953b9060cdde5a6fab6450d0ebee5b912c34405b7047fcf609abdc443f16121a1b34f2fad73dde0edc200ecf8248dd9ee2d9361e2fdc4d951db95e01c437b55c719ab46b72ce0e0119a0587aea0658222f46842148b76d00ad5a9455c6cccd5805f176e06a5c91ef818e010392e4f4965d86cd372480662f1cdd51991513f4d5d6039c8431f8141685617454999fb31a786c40b888162af003a7a439e10c8590f6ecc0d12db383add44ecafe6cc02da52b38d110e1132e26e72f2e0d3117a135b6c0e568b24ccb14defd730ef97ea54fcd79570d4644f17dcd8d466a43073731d3a8e180b87ddd48e9af214cc714d945089cf3274df5b61f875b7803bc0073d51165530214c6526107e8b2b67a2b23f9489b09044f47425dda237d4220c643fb9c39ebc05b03df84ba1b85e520a732c9e9791de3ded94440cec6472da95f5879e379ef7cac5245fb98250b0bd2011d5592c3deee6318eb3ae67820373a2739840062c1d1757a94aa78a9f20bb8833ce74b93e21c4ad1931bcbad13e63b784188d836a068918cb95b81751dec18461d52bdecc9df991a8e2f3f5ed7a2d88ac770d4504de470418aa6f4e06b66173e38c90b12ad8a4cb3fa7cda71943d924e9076c5b9e5dd4843bc00697faf8d624d230216083b09e9a8af55ab642de17bf25fe8c187b0a534e28b71a1d56ca973ea092f655d90163d1204d017053fa82be4c5254607b3441d28d155a2487d40dcd5f7d6418828e7537e4cbedbccd9ff162c1dd568b8661ae48ad908007809bcb4e6b2426993fddc747dd29608ce971ea2de21ff060f8bc37bac698adf09671c4d1057225c421376f91a7716b4073f858c59d29fd5f67c878bc1691cb1912ae89890ed04a9446d0fa779bfe39be759ef5ae4eedb5b942c0a4e91b4fbc114b9be31829c8accafaf4962f9d30952deec46ac5cfe2e4bf29c66cc48113e85162b1d094c290b82aee8b8acba5f2f2cbeb5d9f2a0df1890d948fbb8bb22924fa8bd03d6fa356c69033c9367e55e94977d6b30bfd0a0a35045c7c5d6b3564f63542df673e685eed89c808fc1ecf966db7306ee16f6a1c90b1ad059698bce04894dfa4a37e30abfefd5a30fab451ed54af76a8b12618cb21f77faca8bd4d1f44410f6492e5376dcf0f92c6c929f803c9d04ea77ed333652256fc4d8659104045aada9431ad9694204e8944328037c31d2f93d2d4d2ad192e5116b56e09b071815733aecc62dba3f40cb5ce012df589f09576737c3464b7c5316525e69c321d78199c3097999d409cbef18ca119a48c8aac8e0275350d5876fcc4f3b01686766b3bac23ff0d1e57a2ef51ffc3cfd634f11709154e3edfb1f3df895dfbf3a6e80da68ec3e6fd81de89f9ee7950917622753e24fb53ac3bccda3246f884e0beafc2992714881577f4db19f113f5047d37a4cf89fa3069476ee2402080dbcb1e07b9c5d19ee143cd34e700fc3ef5cb294999a8f0047a9b3b7b0e41ee3dac6df0a1cbaea6390d8baf4baf16c415fbd32b47af90abfb8095617dfa4a1d7cbb54032967394407d6d1ca1ceb330b3556ceb6fd7327ece055011fc3a50293f123d67d27d5bb588b75a8de53a8ee8433b73d7438bc3b84d23d0bd5802d30384fa8366c553841bea4a4dae9620b0a978b5258b36d9cab4c0c6e93b14928f3abaf31b65aecb526dbc56da6faadd9f6b42bc816bdbc09ec6bbc0e9b6dd445221abcf1170c4b62cfd68b9574645091f5bc17b1ccf934f6217fc91661ddc8a8851e98433b0229beaa34296bdc08c7b1b27996423c9220e5dd9a863dfed4f9ee0ed72e04f10b3612ca33429e9c95b3f69a6adb20010aa9b3490a76df8685073003dbadff94ca6d1d6bf49f7989fdccf4f89ac671f934ca3f5916e46d8e80f4651ecca7ef3101de28c1fbc2c38b366438b75fc39b20cbec36a71fa442a564b47dc57f37aab17160d5037bc97e87a0cf2d1330a6633750c880b71eff80992b2679bbd67994ecebe44c725c8d7176c8930b6cbe635a7398a0671e3091edec559d211db17b30c8f67387290ecf9b7a1a2aea4928cd0e400acce8cf27533ab1be3062eab1c234067eda7a763b5a3dad75a36254eb73dc09eb59ba9068ad2c916b6856491ffeb5e4968cb0a989fa666019c67eb067fb4782ae73526d0fef19f8544ea7b6be22492863a38b8e80cb4b32c20a98153d62da3d987f261098da5b2e70ebc5a9a47498bf495d56dd9b32b547861ddf7f75f0c290ddb05dc8ca0fe7467a21e5ad1d173513c73d26b74d02c7144e67f8be612b82b636f00bb21e385ca8e51e540736d475db81a1ca55304306fd8270f43d85063e72ac0eda28f823ad474e54068d4299c80b0c62072920ca9372b21d00bffde70edb3e40834c9611c5ddab32578562cec2c7aed608092fa54508442bbc88a09d2372300374bf4d9affa7499e0889cca969d0a209cf0147b690b871c360466824b4d284d6cd2e4883e87cf7a77834e32719310c9298059747bd3c4ada7fab718c055a53514cbe81dd8a2d181f76b8cbd924b6f4b10065c1c1f672dd6d15ef1368d4c05a1565399be256774d2ad9ad3692286e4f0ed0a5cec45fc8d21fee10302191bbdb750742d305c29c4ec8ec08c916d4eca7f4d3d5d95a6d27617116a5209ce35862814a14d3dd4b12d6171fcc8c21038b45fcb74a04db8617897c9bd66bcaf858bf5d76b266f539d5de1a1afd4485ebfbb5d3e9202a6f16abbfe72d1b3863f3491f0212df86fc7fb7d1936e3d1b8ea28baf2064c88d7576d1197cba67eef8480a00301bbbabd8cc8c3e5b6c3d8887fcdb280f4506873909e6421cf0473c1388098215ee3fd8794d2aac910bf4731f8a983b32f65a8e424a2654a054b0a50b676a46ec7afa8961af0dfff14b74df9aaba78a5b585e03e1306d09550a7814b2478d4c1d6fcbb97490925864bd032f93a8a23b7eebaa6bcb5e693ec4f99ce94ebd20f86133424950ef216d257fb5292c046f336a99f79d4f7e75482baedbcd1170070ebd9974eb16b659b8330b6e8f036207e7285119b95a1050a66fbf656177e7ebcb6dd8841b921b1a435cce72bfa41a0464b79801285665e111a227b8f5986ef196792397d5fa0829d332857bff9c25325b8e9be3e25393d43f8e67a146eddd8075107e91a9b31db68c0e5ed11bdf8f1f542eed5d880fc108f137444f6966cbecfc8f91c64474e3b7fa0f5330bdd3150d0c8848e26bb7bcffe972a7bdc98646abecebe375324a9e18e1136d813c2e28ec7181e0c8c7a1a0ded7278355aa84f4bfe702150808b7a2a82fe569c0e28b4e20117710a111e17beba20e622877553c53de005d1ce2db5bf5ff1c5c4497c0576e8c64020e2a66b9524c56fda5d558327467ceec428a1d2309c4b19e42729c38808cbbb3a979f56cab80be90f9dff0f0fa726f012031dd9fc09b578b256b0c861487180894ee0caef99d2781dbba81e993118a1107db287ed04771a0381b8b059157c99904f0d0b8ac859ace7cce6ef3c755178198fc7378a63b107acb60084ffd6f2204e6f45eb44c4634b41b882391e951ace3c8a7e43d3f421ce4e3203393077050c5511bfadc8ea4c00bdd261366f950f906fce26c05e559f900e95a42d791db7111b00c7fd6ad9cf63ec5005414e1bb7399a8674b30a46a61c4e9162d17b1f50cb9009fbd6c73e238a3ff4fede4a6c2fd0cf65d8844efcb215243a77d5ef6334a5da1a21f4369568827ada5151ccc0604208382b28cc4feb54f2b62d06f433bb3813cb822429b9214c7309b34c1ecc94b8e6f14e2044cb475bcf8aea4d64673517cb7a30f493465facb6184486d7a517aec4bbcc754417b1e56688f3dec0ff4c1295d255caaa9116cb32a8de11d59e2f291ed5f0a86214ad3999d21da10744295539225dc6b8c0df9422aef56ed8e98a40cbfaa998b937a956abfb222791f1b9cb8864967f4d4e4b92d6cac46bfed11c98d26c10d35ecfb15f75412d48ac532fa22ff39016adf8123329e1827952425effd68aff4ca0488503ead67c02b5d9fed51803c34a1a3e2f3e141b35b9565eab3569e8bf5336ced4d9239ab3a6f6f8de8f2a153dd0d018c048866ec859a8134bcfd42a4b343609044f4c4e02695d7392b5dc9baead19f8b8af0eaa036a1df5094187f4494fb05c3977e8dd9e41b81e91003e97adb684331f21e0046c61a84c39baa4a67e9a7934779c9529af9e1fb56324eef34a51c3ca5adc6bd5964638ae883ee09f9bb1979db163d0fa08cfcc9d1106acdc36cf5dcf99aed2ce221158d3daeaa6c081d95e2fb36d6855d0e1f1b1fadde3edc69de55b5267c4ee6461c44182285dc82289e7305af504294430ef422e8bfb068b53a80de589a4b877ffa8ce8cd1473423680c48da31defb534dc21072e424b6aae07682ef7847a1762e00add667b32cd1cc7db62b2c5f87a8d32be5b44f8be5ce5aef6d18a1196001ad73070262f713fb9d3c067d0341a990312a340fb75926e45a73889c1d4f02300f2573d09db2800904af36e2f5c3c9647d21e87fb8993437e5f824d057df5e446ce643d47076848fb36c9dbf8206944ec8ce5c21bb05ea633504ef1ac9cecf07df44d27d98dfe6efd290416651047d6568ef7f0cbb668957646f30d88099fdb5b3c27e0d13a290c7ab6debac7328ea2ede119df34f19860ab032194495f05e00e15b610d381f3ae97388be71e1cdb71fdceb5d3f5ab212b0cc964a86aaa86fa690dfe1e1674f1d7861f4836d4e83f0293437b358b048aebab595bb8fe96b110e9d7304bc417eaacd99d57cecb505f5551085e59ca854a1248f18c8b64fb08d87467adff7da2e7bbed2d457a6ad902157d958d27b3c6e460f33376a837f14fd1026a66fa77d2721ce084118717bf55d56930f934f3a3fb1b3d57509cfb993014a9c3354b78e9ae3b96a48d7bd5025143a058a737fd04dd4b634ea093fe7db92606c24dfc0009213438e4c7f4541a9d24596ddfcabaf913fd0c77279d3db977ce7a8a9b05e2acf1d0282a43d34939164a1adb748fa176b01a1fd03a89d44efafb2fd245b2552a80bdca6de4ecec677ec368111c1db7aa5a900ce00aab56c583ade5d88e41d633af75662f08f10ba58c54297fbdccf9acb752cd0682d6d8e35e3f039ee9d6578a44367b0f684fbf7cd07472ab9382d7c7725cdd1522b91331e2d84bc4f6381077d3109509aea0ba674a342c4dd327bf05b37b5f5fa3051da0fe1596d527057a6ddfd415c9774200bbd3d2c4b777f561b5acc3908434f9a2037f4a6a813cb5918f5021a93f21cec455c9d64cdf4db6b9da183a20457863f7ef3a0f2e383db5e9052e397fa6c0c2cc424a7e9ca6bef63d6088a9abb80f141922374d63858fa3c1c80f28638da7d90a0b1a3852545f7d7e81badef95489cdd700000000000000000000000000060e151b272d3a3e';

describe('Dilithium constructor without seed', () => {
  it('constructor without a seed creates random wallet', () => {
    const wallet = new DilithiumWallet();
    const secondWallet = new DilithiumWallet();
    expect(wallet.pk.length).to.equal(CryptoPublicKeyBytes);
    expect(Buffer.from(wallet.pk).toString('hex')).to.not.equal(Buffer.from(secondWallet.pk).toString('hex'));
  });

  it('should return public key from GetPK method', () => {
    const dilithium = new DilithiumWallet();
    dilithium.create();
    const pk = dilithium.getPK();
    expect(pk.length).to.equal(CryptoPublicKeyBytes);
  });

  it('should return secret key from GetSK method', () => {
    const dilithium = new DilithiumWallet();
    dilithium.create();
    const sk = dilithium.getSK();
    expect(sk.length).to.equal(CryptoSecretKeyBytes);
  });

  it('should return seed from GetSeed method', () => {
    const dilithium = new DilithiumWallet();
    dilithium.create();
    const seed = dilithium.getSeed();
    expect(seed.length).to.equal(48);
  });

  it('should return hexSeed from GetHexSeed method', () => {
    const dilithium = new DilithiumWallet();
    dilithium.create();
    const hexSeed = dilithium.getHexSeed();
    expect(hexSeed.length).to.equal(HEXSEED.length + 2);
    expect(hexSeed.slice(0, 2)).to.equal('0x');
  });

  it('should return mnemonic from GetMnemonic method', () => {
    const dilithium = new DilithiumWallet();
    dilithium.create();
    const mnemonic = dilithium.getMnemonic();
    expect(mnemonic.split(' ').length).to.equal(32);
  });

  it('should return address from GetAddress method', () => {
    const dilithium = new DilithiumWallet();
    dilithium.create();
    const address = dilithium.getAddress();
    const d = getDilithiumDescriptor(address);
    expect(address.length).to.equal(20);
    expect(address[0]).to.equal(d);
  });

  it('should be able to sign message with Seal method', () => {
    const dilithium = new DilithiumWallet();
    dilithium.create();
    const msg = Buffer.from(MESSAGE, 'hex');
    const signatureMessage = dilithium.seal(msg);
    expect(signatureMessage.length).to.equal(CryptoBytes + msg.length);
  });

  it('should be able to sign message with Sign method', () => {
    const dilithium = new DilithiumWallet();
    dilithium.create();
    const signature = dilithium.sign(Buffer.from(MESSAGE, 'hex'));
    expect(signature.length).to.equal(CryptoBytes);
  });
});

describe('Dilithium constructor with seed', () => {
  it('should generate dilithium keys from seed', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    expect(Buffer.from(dilithium.pk, 'binary').toString('hex')).to.equal(PK);
    expect(Buffer.from(dilithium.sk, 'binary').toString('hex')).to.equal(SK);
  });

  it('should return public key from GetPK method', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const pk = dilithium.getPK();
    expect(Buffer.from(pk, 'binary').toString('hex')).to.equal(PK);
  });

  it('should return secret key from GetSK method', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const sk = dilithium.getSK();
    expect(Buffer.from(sk, 'binary').toString('hex')).to.equal(SK);
  });

  it('should return seed from GetSeed method', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const seed = dilithium.getSeed();
    expect(seed.length).to.equal(48);
  });

  it('should return hexSeed from GetHexSeed method', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const hexSeed = dilithium.getHexSeed();
    expect(hexSeed).to.equal(`0x${HEXSEED}`);
  });

  it('should return mnemonic from GetMnemonic method', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const mnemonic = dilithium.getMnemonic();
    expect(mnemonic.split(' ').length).to.equal(32);
  });

  it('should return address from GetAddress method', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const address = dilithium.getAddress();
    const d = getDilithiumDescriptor(address);
    expect(address.length).to.equal(20);
    expect(address[0]).to.equal(d);
    expect(Buffer.from(address, 'binary').toString('hex')).to.equal(ADDRESS);
  });

  it('should be able to sign message with Seal method', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const msg = Buffer.from(MESSAGE, 'hex');
    const signatureMessage = dilithium.seal(msg);
    expect(signatureMessage.length).to.equal(CryptoBytes + msg.length);
    expect(Buffer.from(signatureMessage, 'binary').toString('hex')).to.equal(SIGNATURE + MESSAGE);
  });

  it('should be able to sign message with Sign method', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const signature = dilithium.sign(Buffer.from(MESSAGE, 'hex'));
    expect(signature.length).to.equal(CryptoBytes);
    expect(Buffer.from(signature, 'binary').toString('hex')).to.equal(SIGNATURE);
  });
});

describe('Open', () => {
  it('should open sealed message and return original message with signature', () => {
    const sigMessage = Buffer.from(SIGNATURE + MESSAGE, 'hex');
    const pk = Buffer.from(PK, 'hex');
    const openedMessage = openMessage(sigMessage, pk);
    expect(Buffer.from(openedMessage, 'binary').toString('hex')).to.equal(MESSAGE);
  });
});

describe('Verify', () => {
  it('should return true on signature verification', () => {
    const sig = Buffer.from(SIGNATURE, 'hex');
    const msg = Buffer.from(MESSAGE, 'hex');
    const pk = Buffer.from(PK, 'hex');
    const bool = verifyMessage(msg, sig, pk);
    expect(bool).to.equal(true);
  });
});

describe('ExtractMessage', () => {
  it('should extract message from signature', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const signatureMessage = dilithium.seal(Buffer.from(MESSAGE, 'hex'));
    const messageBuf = extractMessage(signatureMessage);
    expect(Buffer.from(messageBuf, 'binary').toString('hex')).to.equal(MESSAGE.toString(16));
  });
});

describe('ExtractSignature', () => {
  it('should extract signature from Signature attached with message', () => {
    const dilithium = new DilithiumWallet(Buffer.from(HEXSEED, 'hex'));
    const signatureMessage = dilithium.seal(Buffer.from(MESSAGE, 'hex'));
    const sigBuf = extractSignature(signatureMessage);
    expect(Buffer.from(sigBuf, 'binary').toString('hex')).to.equal(SIGNATURE.toString(16));
  });
});

describe('GetDilithiumAddressFromPK', () => {
  it('should fetch dilithium address from public key', () => {
    const pk = new Uint8Array(Buffer.from(PK, 'hex'));
    const address = getDilithiumAddressFromPK(pk);
    const d = getDilithiumDescriptor(address);
    expect(address.length).to.equal(20);
    expect(address[0]).to.equal(d);
    expect(Buffer.from(address, 'binary').toString('hex')).to.equal(ADDRESS);
  });
});

describe('isValidDilithiumAddress', () => {
  it('should return true for a valid dilithium address', () => {
    const pk = Buffer.from(PK, 'hex');
    const address = getDilithiumAddressFromPK(pk);
    const bool = isValidDilithiumAddress(address);
    expect(bool).to.equal(true);
  });
  it('should return false for an invalid dilithium address', () => {
    const pk = Buffer.from(PK, 'hex');
    const address = getDilithiumAddressFromPK(pk);
    // flip first bit to make invalid
    address[0] = 0x00;
    const bool = isValidDilithiumAddress(address);
    expect(bool).to.equal(false);
  });
});

describe('getDilithiumDescriptor', () => {
  it('getDilithiumDescriptor will throw if passed without an address', () => {
    expect(() => {
      getDilithiumDescriptor();
    }).to.throw();
  });
});
