package goecdsa

import (
	"fmt"
	"hash"
	"log"
	"math/big"

	naiveelliptic "github.com/vitalnodo/naive-elliptic"
)

func hashToInt(hash []byte, c naiveelliptic.Curve) *big.Int {
	orderBits := c.N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}
	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func Sign(curve naiveelliptic.ShortWeierstrassCurve, hash hash.Hash,
	msg string, priv *big.Int, k *big.Int) (r *big.Int, s *big.Int) {
	hash.Reset()
	hash.Write([]byte(msg))
	e := hash.Sum(nil)
	z := hashToInt(e, curve.Curve)
	for {
		P := curve.ScalarMult(*k, curve.BasePointGGet())
		r := new(big.Int).Mod(P.X, curve.N)
		if r.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		k_inv := new(big.Int).ModInverse(k, curve.N)
		s := new(big.Int).Mul(r, priv)
		s.Add(s, z)
		s.Mul(s, k_inv)
		s.Mod(s, curve.N)
		if s.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		return r, s
	}
}

func Verify(curve naiveelliptic.ShortWeierstrassCurve, hash hash.Hash,
	public naiveelliptic.ECPoint, msg string, r, s *big.Int) bool {
	if r.Cmp(big.NewInt(1)) == 1 && r.Cmp(curve.N) != -1 {
		log.Panic("not in range")
	}
	hash.Reset()
	hash.Write([]byte(msg))
	e := hash.Sum(nil)
	z := hashToInt(e, curve.Curve)
	s_inv := new(big.Int).ModInverse(s, curve.N)
	u1 := new(big.Int).Mul(z, s_inv)
	u1.Mod(u1, curve.N)
	u2 := new(big.Int).Mul(r, s_inv)
	u2.Mod(u2, curve.N)
	p1 := curve.ScalarMult(*u1, curve.BasePointGGet())
	p2 := curve.ScalarMult(*u2, public)
	P := curve.AddECPoints(p1, p2)
	x1 := new(big.Int).Mod(P.X, curve.N)
	r_mod_n := new(big.Int).Mod(r, curve.N)
	if x1.Cmp(r_mod_n) == 0 {
		return true
	} else {
		fmt.Println(x1, r_mod_n)
		return false
	}
}
