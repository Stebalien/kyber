package p256

// Data from: http://point-at-infinity.org/ecc/nisttv
var basePointScalarMult = []struct {
	K string
	X string
	Y string
}{
	{
		K: "1",
		X: "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
		Y: "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
	},
	{
		K: "2",
		X: "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978",
		Y: "07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1",
	},
	{
		K: "3",
		X: "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C",
		Y: "8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032",
	}, {
		K: "4",
		X: "E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852",
		Y: "E0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6",
	}, {
		K: "5",
		X: "51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED",
		Y: "E0C17DA8904A727D8AE1BF36BF8A79260D012F00D4D80888D1D0BB44FDA16DA4",
	}, {
		K: "6",
		X: "B01A172A76A4602C92D3242CB897DDE3024C740DEBB215B4C6B0AAE93C2291A9",
		Y: "E85C10743237DAD56FEC0E2DFBA703791C00F7701C7E16BDFD7C48538FC77FE2",
	}, {
		K: "7",
		X: "8E533B6FA0BF7B4625BB30667C01FB607EF9F8B8A80FEF5B300628703187B2A3",
		Y: "73EB1DBDE03318366D069F83A6F5900053C73633CB041B21C55E1A86C1F400B4",
	}, {
		K: "8",
		X: "62D9779DBEE9B0534042742D3AB54CADC1D238980FCE97DBB4DD9DC1DB6FB393",
		Y: "AD5ACCBD91E9D8244FF15D771167CEE0A2ED51F6BBE76A78DA540A6A0F09957E",
	}, {
		K: "9",
		X: "EA68D7B6FEDF0B71878938D51D71F8729E0ACB8C2C6DF8B3D79E8A4B90949EE0",
		Y: "2A2744C972C9FCE787014A964A8EA0C84D714FEAA4DE823FE85A224A4DD048FA",
	}, {
		K: "10",
		X: "CEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F",
		Y: "878662A229AAAE906E123CDD9D3B4C10590DED29FE751EEECA34BBAA44AF0773",
	}, {
		K: "11",
		X: "3ED113B7883B4C590638379DB0C21CDA16742ED0255048BF433391D374BC21D1",
		Y: "9099209ACCC4C8A224C843AFA4F4C68A090D04DA5E9889DAE2F8EEFCE82A3740",
	}, {
		K: "12",
		X: "741DD5BDA817D95E4626537320E5D55179983028B2F82C99D500C5EE8624E3C4",
		Y: "0770B46A9C385FDC567383554887B1548EEB912C35BA5CA71995FF22CD4481D3",
	}, {
		K: "13",
		X: "177C837AE0AC495A61805DF2D85EE2FC792E284B65EAD58A98E15D9D46072C01",
		Y: "63BB58CD4EBEA558A24091ADB40F4E7226EE14C3A1FB4DF39C43BBE2EFC7BFD8",
	}, {
		K: "14",
		X: "54E77A001C3862B97A76647F4336DF3CF126ACBE7A069C5E5709277324D2920B",
		Y: "F599F1BB29F4317542121F8C05A2E7C37171EA77735090081BA7C82F60D0B375",
	}, {
		K: "15",
		X: "F0454DC6971ABAE7ADFB378999888265AE03AF92DE3A0EF163668C63E59B9D5F",
		Y: "B5B93EE3592E2D1F4E6594E51F9643E62A3B21CE75B5FA3F47E59CDE0D034F36",
	}, {
		K: "16",
		X: "76A94D138A6B41858B821C629836315FCD28392EFF6CA038A5EB4787E1277C6E",
		Y: "A985FE61341F260E6CB0A1B5E11E87208599A0040FC78BAA0E9DDD724B8C5110",
	}, {
		K: "17",
		X: "47776904C0F1CC3A9C0984B66F75301A5FA68678F0D64AF8BA1ABCE34738A73E",
		Y: "AA005EE6B5B957286231856577648E8381B2804428D5733F32F787FF71F1FCDC",
	}, {
		K: "18",
		X: "1057E0AB5780F470DEFC9378D1C7C87437BB4C6F9EA55C63D936266DBD781FDA",
		Y: "F6F1645A15CBE5DC9FA9B7DFD96EE5A7DCC11B5C5EF4F1F78D83B3393C6A45A2",
	}, {
		K: "19",
		X: "CB6D2861102C0C25CE39B7C17108C507782C452257884895C1FC7B74AB03ED83",
		Y: "58D7614B24D9EF515C35E7100D6D6CE4A496716E30FA3E03E39150752BCECDAA",
	}, {
		K: "20",
		X: "83A01A9378395BAB9BCD6A0AD03CC56D56E6B19250465A94A234DC4C6B28DA9A",
		Y: "76E49B6DE2F73234AE6A5EB9D612B75C9F2202BB6923F54FF8240AAA86F640B8",
	}, {
		K: "112233445566778899",
		X: "339150844EC15234807FE862A86BE77977DBFB3AE3D96F4C22795513AEAAB82F",
		Y: "B1C14DDFDC8EC1B2583F51E85A5EB3A155840F2034730E9B5ADA38B674336A21",
	}, {
		K: "112233445566778899112233445566778899",
		X: "1B7E046A076CC25E6D7FA5003F6729F665CC3241B5ADAB12B498CD32F2803264",
		Y: "BFEA79BE2B666B073DB69A2A241ADAB0738FE9D2DD28B5604EB8C8CF097C457B",
	}, {
		K: "29852220098221261079183923314599206100666902414330245206392788703677545185283",
		X: "9EACE8F4B071E677C5350B02F2BB2B384AAE89D58AA72CA97A170572E0FB222F",
		Y: "1BBDAEC2430B09B93F7CB08678636CE12EAAFD58390699B5FD2F6E1188FC2A78",
	}, {
		K: "57896042899961394862005778464643882389978449576758748073725983489954366354431",
		X: "878F22CC6DB6048D2B767268F22FFAD8E56AB8E2DC615F7BD89F1E350500DD8D",
		Y: "714A5D7BB901C9C5853400D12341A892EF45D87FC553786756C4F0C9391D763E",
	}, {
		K: "1766845392945710151501889105729049882997660004824848915955419660366636031",
		X: "659A379625AB122F2512B8DADA02C6348D53B54452DFF67AC7ACE4E8856295CA",
		Y: "49D81AB97B648464D0B4A288BD7818FAB41A16426E943527C4FED8736C53D0F6",
	}, {
		K: "28948025760307534517734791687894775804466072615242963443097661355606862201087",
		X: "CBCEAAA8A4DD44BBCE58E8DB7740A5510EC2CB7EA8DA8D8F036B3FB04CDA4DE4",
		Y: "4BD7AA301A80D7F59FD983FEDBE59BB7B2863FE46494935E3745B360E32332FA",
	}, {
		K: "113078210460870548944811695960290644973229224625838436424477095834645696384",
		X: "F0C4A0576154FF3A33A3460D42EAED806E854DFA37125221D37935124BA462A4",
		Y: "5B392FA964434D29EEC6C9DBC261CF116796864AA2FAADB984A2DF38D1AEF7A3",
	}, {
		K: "12078056106883488161242983286051341125085761470677906721917479268909056",
		X: "5E6C8524B6369530B12C62D31EC53E0288173BD662BDF680B53A41ECBCAD00CC",
		Y: "447FE742C2BFEF4D0DB14B5B83A2682309B5618E0064A94804E9282179FE089F",
	}, {
		K: "57782969857385448082319957860328652998540760998293976083718804450708503920639",
		X: "03792E541BC209076A3D7920A915021ECD396A6EB5C3960024BE5575F3223484",
		Y: "FC774AE092403101563B712F68170312304F20C80B40C06282063DB25F268DE4",
	}, {
		K: "57896017119460046759583662757090100341435943767777707906455551163257755533312",
		X: "2379FF85AB693CDF901D6CE6F2473F39C04A2FE3DCD842CE7AAB0E002095BCF8",
		Y: "F8B476530A634589D5129E46F322B02FBC610A703D80875EE70D7CE1877436A1",
	}, {
		K: "452312848374287284681282171017647412726433684238464212999305864837160993279",
		X: "C1E4072C529BF2F44DA769EFC934472848003B3AF2C0F5AA8F8DDBD53E12ED7C",
		Y: "39A6EE77812BB37E8079CD01ED649D3830FCA46F718C1D3993E4A591824ABCDB",
	}, {
		K: "904571339174065134293634407946054000774746055866917729876676367558469746684",
		X: "34DFBC09404C21E250A9B40FA8772897AC63A094877DB65862B61BD1507B34F3",
		Y: "CF6F8A876C6F99CEAEC87148F18C7E1E0DA6E165FFC8ED82ABB65955215F77D3",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044349",
		X: "83A01A9378395BAB9BCD6A0AD03CC56D56E6B19250465A94A234DC4C6B28DA9A",
		Y: "891B64911D08CDCC5195A14629ED48A360DDFD4596DC0AB007DBF5557909BF47",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044350",
		X: "CB6D2861102C0C25CE39B7C17108C507782C452257884895C1FC7B74AB03ED83",
		Y: "A7289EB3DB2610AFA3CA18EFF292931B5B698E92CF05C1FC1C6EAF8AD4313255",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044351",
		X: "1057E0AB5780F470DEFC9378D1C7C87437BB4C6F9EA55C63D936266DBD781FDA",
		Y: "090E9BA4EA341A246056482026911A58233EE4A4A10B0E08727C4CC6C395BA5D",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044352",
		X: "47776904C0F1CC3A9C0984B66F75301A5FA68678F0D64AF8BA1ABCE34738A73E",
		Y: "55FFA1184A46A8D89DCE7A9A889B717C7E4D7FBCD72A8CC0CD0878008E0E0323",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044353",
		X: "76A94D138A6B41858B821C629836315FCD28392EFF6CA038A5EB4787E1277C6E",
		Y: "567A019DCBE0D9F2934F5E4A1EE178DF7A665FFCF0387455F162228DB473AEEF",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044354",
		X: "F0454DC6971ABAE7ADFB378999888265AE03AF92DE3A0EF163668C63E59B9D5F",
		Y: "4A46C11BA6D1D2E1B19A6B1AE069BC19D5C4DE328A4A05C0B81A6321F2FCB0C9",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044355",
		X: "54E77A001C3862B97A76647F4336DF3CF126ACBE7A069C5E5709277324D2920B",
		Y: "0A660E43D60BCE8BBDEDE073FA5D183C8E8E15898CAF6FF7E45837D09F2F4C8A",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044356",
		X: "177C837AE0AC495A61805DF2D85EE2FC792E284B65EAD58A98E15D9D46072C01",
		Y: "9C44A731B1415AA85DBF6E524BF0B18DD911EB3D5E04B20C63BC441D10384027",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044357",
		X: "741DD5BDA817D95E4626537320E5D55179983028B2F82C99D500C5EE8624E3C4",
		Y: "F88F4B9463C7A024A98C7CAAB7784EAB71146ED4CA45A358E66A00DD32BB7E2C",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044358",
		X: "3ED113B7883B4C590638379DB0C21CDA16742ED0255048BF433391D374BC21D1",
		Y: "6F66DF64333B375EDB37BC505B0B3975F6F2FB26A16776251D07110317D5C8BF",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044359",
		X: "CEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F",
		Y: "78799D5CD655517091EDC32262C4B3EFA6F212D7018AE11135CB4455BB50F88C",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044360",
		X: "EA68D7B6FEDF0B71878938D51D71F8729E0ACB8C2C6DF8B3D79E8A4B90949EE0",
		Y: "D5D8BB358D36031978FEB569B5715F37B28EB0165B217DC017A5DDB5B22FB705",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044361",
		X: "62D9779DBEE9B0534042742D3AB54CADC1D238980FCE97DBB4DD9DC1DB6FB393",
		Y: "52A533416E1627DCB00EA288EE98311F5D12AE0A4418958725ABF595F0F66A81",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044362",
		X: "8E533B6FA0BF7B4625BB30667C01FB607EF9F8B8A80FEF5B300628703187B2A3",
		Y: "8C14E2411FCCE7CA92F9607C590A6FFFAC38C9CD34FBE4DE3AA1E5793E0BFF4B",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044363",
		X: "B01A172A76A4602C92D3242CB897DDE3024C740DEBB215B4C6B0AAE93C2291A9",
		Y: "17A3EF8ACDC8252B9013F1D20458FC86E3FF0890E381E9420283B7AC7038801D",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044364",
		X: "51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED",
		Y: "1F3E82566FB58D83751E40C9407586D9F2FED1002B27F7772E2F44BB025E925B",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044365",
		X: "E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852",
		Y: "1F0EA8A4B39CC339E62011A02579D289B103693D0CF11FFAA3BD3DC0E7B12739",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044366",
		X: "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C",
		Y: "78CB9BF2B6670082C8B4F931E59B5D1327D54FCAC7B047C265864ED85D82AFCD",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044367",
		X: "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978",
		Y: "F888AAEE24712FC0D6C26539608BCF244582521AC3167DD661FB4862DD878C2E",
	}, {
		K: "115792089210356248762697446949407573529996955224135760342422259061068512044368",
		X: "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
		Y: "B01CBD1C01E58065711814B583F061E9D431CCA994CEA1313449BF97C840AE0A",
	},
}
