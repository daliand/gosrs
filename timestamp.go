package gosrs

import (
	"strings"
	"time"
)

const tsPrecision = (60 * 60 * 24)
const tsBasebits = 5
const tsSize = 2
const tsSlots = (1 << tsBasebits << (tsSize - 1))

// 5-bit / base 32 alphabet for timestamp encoding as described in the spec.
// Note that this is NOT the same as RFC4648 or RFC3548 Base32 encoding, which are both 8-bit / base 256 encodings.
var tsBaseChars = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

// GenerateTS generates timestamp string TT for use in an SRS0 address from current date.
// TT is a 10 bit number, stored as two base32 characters, computed as UNIX_TIME/(60 * 60 * 24)mod2^10
func generateTS() string {

	t := time.Now().Unix() / tsPrecision
	r := []rune("==")
	r[1] = tsBaseChars[t&((1<<tsBasebits)-1)]
	t = t >> tsBasebits
	r[0] = tsBaseChars[t&((1<<tsBasebits)-1)]
	return string(r)

}

// CheckTS checks that the supplied 'ts' string is a valid SRS timestamp for the duration of Now() - 'validity' days
func checkTS(ts string, validity int64) error {

	then := int64(0)

	for _, char := range ts {
		dex := int64(strings.Index(string(tsBaseChars), strings.ToUpper(string(char))))
		if dex == -1 {
			return ErrInvalidTimestampCharacter
		}
		then = (then << tsBasebits) | dex
	}

	now := (time.Now().Unix() / tsPrecision) % tsSlots

	for now < then {
		now = now + tsSlots
	}

	if now <= (then + validity) {
		return nil
	}

	return ErrTimestampExpired
}
