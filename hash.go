package gosrs

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"strings"
)

// Produces a hash string for use in an SRS address.
// As recommended in the specification, this function yields a base64-encoded
// hash of the provided string in lower case using the HMAC-SHA1 algorithm, and
// truncates it to len characters.
func generateHash(s string, key string, len int) string {
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(s))
	return string(base64.StdEncoding.EncodeToString(h.Sum(nil))[0:len])
}

// Checks a hash 'h' against an input string 's'
// As per canonical implementation (libsrs2), hashes are compared case-insensively.
func checkHash(h string, s string, key string, len int) error {
	if strings.ToUpper(h) == strings.ToUpper(generateHash(s, key, len)) {
		return nil
	}
	return errors.New("gosrs: Invalid hash")
}
