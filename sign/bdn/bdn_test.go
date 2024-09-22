package bdn

import (
	"encoding"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/pairing/bls12381/circl"
	"go.dedis.ch/kyber/v4/pairing/bls12381/gnark"
	"go.dedis.ch/kyber/v4/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/sign/bls"
	"go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/kyber/v4/util/random"
)

var suite = bn256.NewSuiteBn256()
var two = suite.Scalar().Add(suite.Scalar().One(), suite.Scalar().One())
var three = suite.Scalar().Add(two, suite.Scalar().One())

// Reference test for other languages
func TestBDN_HashPointToR_BN256(t *testing.T) {
	p1 := suite.Point().Base()
	p2 := suite.Point().Mul(two, suite.Point().Base())
	p3 := suite.Point().Mul(three, suite.Point().Base())

	coefs, err := hashPointToR(suite, []kyber.Point{p1, p2, p3})

	require.NoError(t, err)
	require.Equal(t, "35b5b395f58aba3b192fb7e1e5f2abd3", coefs[0].String())
	require.Equal(t, "14dcc79d46b09b93075266e47cd4b19e", coefs[1].String())
	require.Equal(t, "933f6013eb3f654f9489d6d45ad04eaf", coefs[2].String())
	//require.Equal(t, 16, coefs[0].MarshalSize())

	mask, _ := NewMask(suite, []kyber.Point{p1, p2, p3}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	mask.SetBit(2, true)

	agg, err := AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	buf, err := agg.MarshalBinary()
	require.NoError(t, err)
	ref := "1432ef60379c6549f7e0dbaf289cb45487c9d7da91fc20648f319a9fbebb23164abea76cdf7b1a3d20d539d9fe096b1d6fb3ee31bf1d426cd4a0d09d603b09f55f473fde972aa27aa991c249e890c1e4a678d470592dd09782d0fb3774834f0b2e20074a49870f039848a6b1aff95e1a1f8170163c77098e1f3530744d1826ce"
	require.Equal(t, ref, fmt.Sprintf("%x", buf))
}

func TestBDN_AggregateSignatures(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)

	_, err = AggregateSignatures(suite, [][]byte{sig1}, mask)
	require.Error(t, err)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)

	mask.SetBit(1, false)
	aggregatedKey, err = AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.Error(t, err)
}

func TestBDN_SubsetSignature(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	_, public3 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := NewMask(suite, []kyber.Point{public1, public3, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(2, true)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)
}

func TestBDN_RogueAttack(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	scheme := bls.NewSchemeOnG1(suite)
	// honest
	_, public1 := scheme.NewKeyPair(random.New())
	// attacker
	private2, public2 := scheme.NewKeyPair(random.New())

	// create a forged public-key for public1
	rogue := public1.Clone().Sub(public2, public1)

	pubs := []kyber.Point{public1, rogue}

	sig, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	// Old scheme not resistant to the attack
	agg := scheme.AggregatePublicKeys(pubs...)
	require.NoError(t, scheme.Verify(agg, msg, sig))

	// New scheme that should detect
	mask, _ := NewMask(suite, pubs, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	agg, err = AggregatePublicKeys(suite, mask)
	require.NoError(t, err)
	require.Error(t, Verify(suite, agg, msg, sig))
}

func Benchmark_BDN_AggregateSigs(b *testing.B) {
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)

	mask, _ := NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	}
}

func Benchmark_BDN_BLS12381_AggregateVerify(b *testing.B) {
	suite := kilic.NewBLS12381Suite()
	schemeOnG2 := NewSchemeOnG2(suite)

	rng := random.New()
	pubKeys := make([]kyber.Point, 3000)
	privKeys := make([]kyber.Scalar, 3000)
	for i := range pubKeys {
		privKeys[i], pubKeys[i] = schemeOnG2.NewKeyPair(rng)
	}

	mask, err := NewMask(suite.G1(), pubKeys, nil)
	require.NoError(b, err)
	for i := range pubKeys {
		require.NoError(b, mask.SetBit(i, true))
	}

	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sigs := make([][]byte, len(privKeys))
	for i, k := range privKeys {
		s, err := schemeOnG2.Sign(k, msg)
		require.NoError(b, err)
		sigs[i] = s
	}

	sig, err := schemeOnG2.AggregateSignatures(sigs, mask)
	require.NoError(b, err)
	sigb, err := sig.MarshalBinary()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk, err := schemeOnG2.AggregatePublicKeys(mask)
		require.NoError(b, err)
		require.NoError(b, schemeOnG2.Verify(pk, msg, sigb))
	}
}

func unmarshalHex[T encoding.BinaryUnmarshaler](t *testing.T, into T, s string) T {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.NoError(t, into.UnmarshalBinary(b))
	return into
}

func marshalHex[T encoding.BinaryMarshaler](t *testing.T, val T) string {
	t.Helper()
	data, err := val.MarshalBinary()
	require.NoError(t, err)
	return hex.EncodeToString(data)
}

func TestBDNFixtures(t *testing.T) {
	suites := []interface {
		suites.Suite
		pairing.Suite
	}{
		kilic.NewSuiteBLS12381(),
		circl.NewSuiteBLS12381(),
		gnark.NewSuiteBLS12381(),
	}
	for _, suite := range suites {
		t.Run(fmt.Sprintf("%s", suite), func(t *testing.T) {
			testBDNFixtures(t, suite)
		})
	}
}

// This tests exists to make sure we don't accidentally make breaking changes to signature
// aggregation by using checking against known aggregated signatures and keys.
func testBDNFixtures(t *testing.T, suite pairing.Suite) {
	schemeOnG1 := NewSchemeOnG1(suite)

	//private1, public1 := schemeOnG1.NewKeyPair(random.New())
	//private2, public2 := schemeOnG1.NewKeyPair(random.New())
	//private3, public3 := schemeOnG1.NewKeyPair(random.New())

	//t.Log(marshalHex(t, public1))
	//t.Log(marshalHex(t, private1))
	//t.Log(marshalHex(t, public2))
	//t.Log(marshalHex(t, private2))
	//t.Log(marshalHex(t, public3))
	//t.Log(marshalHex(t, private3))

	public1 := unmarshalHex(t, suite.G2().Point(), "89a3c3ff4ad97196430c52778b304b4f733b1e583ca531da8f7196b75132ae123ea3623558caaa27dc442e2003fc73c018acb67b63f029a2f805c393a5999825a52dcfbfe9925b251e564d7126236dde1719c8fb17a43c6d9539bc52ce819df3")
	private1 := unmarshalHex(t, suite.G2().Scalar(), "2fc4f01295ac7b694141053d646716f984bef2c62dca06da44d65293543fa1cf")
	public2 := unmarshalHex(t, suite.G2().Point(), "8d4597a0a330939accdf7979c4669e992bfb300541248e25be205ce0f96503b1c66eff0f7c5471dc47cf3d0a6d92e9d20594946589fd8e0e0c0d9823bbaa515b950eacb6a3e758906cfe3350c70739ced779e47bfeba3f87fcbdf941524292fd")
	private2 := unmarshalHex(t, suite.G2().Scalar(), "612765290696a5aef46f2a9b30f6c4f9d8934385511eeb69b0852b1418c804e2")
	public3 := unmarshalHex(t, suite.G2().Point(), "b987b7b2e81dfe3b620b40561b4cd027febab563454b02a02fa25083f305aef08922f752e52c7f784a738a12b12dd1bd053a2baaba7c34274f3946e0c56fbeb7166a2f0c0ef2ac2ce189431c13ca0967b9ff3749c4337b52773e0016ef99eb11")
	private3 := unmarshalHex(t, suite.G2().Scalar(), "3f78125ca531fdb699d5499cef86449757b33f4fa4158595931573cba734bf70")

	const sig1Exp = "b3a21c2bf8e99f16be63c56cafc8b9753ac448283dc053e142329b78938437ef14d61b790235cb59bfe852a755c65c83"
	const sig2Exp = "9507d535c9c1c21e522d06790e487eb2a8213481f2dcee9e50e6e64b70e8e44942c791596b849061702814bd5eac9da5"
	const sig3Exp = "87bcba051ca24b96d7ccb94a490bbc01cef1fe19f8a23b4f76b52d4eca74d651f6b04f5d3e6f230f7dbf65897c00937b"

	const aggSigExp = "920bea3be12844d36beb28ea88a1cb84030144710ca201c64f2a5bf320572dd8e70275612fb3e1f06239c78e7a8de404"
	const aggKeyExp = "94294bebcbe2ad9671790f505bb7ef52a1aa2fe025fcd1650055345c0ca7f7fa345157cb7aa56c4a3eb91e88f51ff43d18bc4e084e61a27ac3f7524cd2d514c9dfa9846ddcbaa2ba9d1782949250fda6018c57dab9f86fd1dc7e997c42184ce5"

	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := schemeOnG1.Sign(private1, msg)
	require.Nil(t, err)
	assert.Equal(t, sig1Exp, hex.EncodeToString(sig1), "sig1 doesn't match")

	sig2, err := schemeOnG1.Sign(private2, msg)
	require.Nil(t, err)
	assert.Equal(t, sig2Exp, hex.EncodeToString(sig2), "sig2 doesn't match")

	sig3, err := schemeOnG1.Sign(private3, msg)
	require.Nil(t, err)
	assert.Equal(t, sig3Exp, hex.EncodeToString(sig3), "sig3 doesn't match")

	mask, _ := NewMask(suite.G1(), []kyber.Point{public1, public2, public3}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)
	mask.SetBit(2, true)

	aggSig, err := schemeOnG1.AggregateSignatures([][]byte{sig1, sig3}, mask)
	require.NoError(t, err)
	aggSigBin, err := aggSig.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, aggSigExp, hex.EncodeToString(aggSigBin))

	aggKey, err := schemeOnG1.AggregatePublicKeys(mask)
	require.NoError(t, err)
	aggKeyBin, err := aggKey.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, aggKeyExp, hex.EncodeToString(aggKeyBin))
}
