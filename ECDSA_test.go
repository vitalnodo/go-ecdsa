package goecdsa

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"log"
	"math/big"
	"testing"

	naiveelliptic "github.com/vitalnodo/naive-elliptic"
)

type ECDSATest struct {
	curve naiveelliptic.ShortWeierstrassCurve
	hash  hash.Hash
	msg   string
	k     string
	r     string
	s     string
}

var tests = []ECDSATest{
	ECDSATest{
		curve: naiveelliptic.P256(),
		hash:  sha256.New(),
		msg:   "sample",
		k:     "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
		r:     "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
		s:     "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
	},
	ECDSATest{
		curve: naiveelliptic.P256(),
		hash:  sha512.New(),
		msg:   "sample",
		k:     "5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5",
		r:     "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
		s:     "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE",
	},
}

func TestECDSAValid(t *testing.T) {
	curve := naiveelliptic.P256()
	priv, _ := new(big.Int).SetString("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
	public := curve.ScalarMult(*priv, curve.BasePointGGet())
	for i := range tests {
		k, _ := new(big.Int).SetString(tests[i].k, 16)
		expected_r, _ := new(big.Int).SetString(tests[i].r, 16)
		expected_s, _ := new(big.Int).SetString(tests[i].s, 16)
		r, s := Sign(curve, tests[i].hash, tests[i].msg, priv, k)
		if r.Cmp(expected_r) != 0 || s.Cmp(expected_s) != 0 {
			fmt.Println(tests[i])
			log.Panic("TestECDSAValid invalid signature")
		}
		res := Verify(curve, tests[i].hash, public, tests[i].msg, r, s)
		if !res {
			log.Panic("TestECDSAValid invalid verify")
		}
	}
}
