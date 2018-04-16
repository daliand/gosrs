package gosrs

import (
	"errors"
	"fmt"
	"strings"
)

// GS -  Guarded Scheme Config struct
type GS struct {
	key       string
	hashLen   int
	validity  int64
	separator string
}

// GuardedScheme initializes the library
func GuardedScheme(secret string) (*GS, error) {
	s := GS{
		key:       secret,
		hashLen:   4,
		separator: "=",
		validity:  7}

	return &s, nil
}

// SetSeparator Sets the GS address separator to 'separator'. Must be one of '=', '+', or '-'
func (GS *GS) SetSeparator(separator string) error {
	if separator == "=" || separator == "+" || separator == "-" {
		GS.separator = separator
		return nil
	}
	return errors.New("goGS: Invalid separator. Must be one of '=', '+', '-'. Default '='")
}

// SetValidity sets the number of days GS timstamp is valid for
func (GS *GS) SetValidity(validity int64) error {
	GS.validity = validity
	return nil
}

// SetHashlen sets the length of the GS hash part
func (GS *GS) SetHashlen(len int) error {
	GS.hashLen = len
	return nil
}

// Forward - Rewrites sender 'from' address to 'alias' domain.
// As described in the SRS specification, the algorithm is:
// 	- If 'from' is an SRS1 address rewritten by 1stHop.com to SRS0 and later by nthHop.com to SRS1, rewrite to a new SRS1 address such that bounces will go to us then 1stHop.com.
// 	- If 'from' is an SRS0 address rewritten by 1stHop.com, rewrite to an SRS1 address such that bounces will go to us then back to 1stHop.com.
// 	- If 'from' is neither an SRS0 address nor an SRS1 address, rewrite to an SRS0 address such that bounces will go to us then back to 'from'.
func (GS *GS) Forward(from string, alias string) (string, error) {

	fromLocal, fromDomain, isSRS, err := validateAddress(from)
	if err != nil {
		return "", err
	}

	if isSRS {
		// We are hop > 2. Replace SRS1 hash with our own. Bounces will go back to first hop.
		if strings.Contains(fromLocal, "SRS1") {
			_, firsthopDomain, opaque, errAddr := splitSRS1Address(fromLocal)
			if errAddr != nil {
				return "", errAddr
			}

			// hash 1st hop host + 1st hop local part
			hash := generateHash(fmt.Sprintf("%s%s", firsthopDomain, opaque), GS.key, GS.hashLen)
			return fmt.Sprintf("SRS1%s%s%s%s%s%s@%s", GS.separator, hash, GS.separator, firsthopDomain, GS.separator, opaque, alias), nil
		}

		// We are second hop. Generate SRS1 address that bounces to first hop
		if strings.Contains(fromLocal, "SRS0") {
			opaque := strings.TrimLeft(fromLocal, "SRS0")

			// hash envelope domain and SRS opaque part
			hash := generateHash(fmt.Sprintf("%s%s", fromDomain, opaque), GS.key, GS.hashLen)
			return fmt.Sprintf("SRS1%s%s%s%s%s%s@%s", GS.separator, hash, GS.separator, fromDomain, GS.separator, opaque, alias), nil
		}
	}
	// We are the first hop. Generate SRS0 address that bounces to original envelope sender
	ts := generateTS()
	hash := generateHash(fmt.Sprintf("%s%s%s", ts, fromDomain, fromLocal), GS.key, GS.hashLen)
	return fmt.Sprintf("SRS0%s%s%s%s%s%s%s%s@%s", GS.separator, hash, GS.separator, ts, GS.separator, fromDomain, GS.separator, fromLocal, alias), nil
}

// Reverse reverses a rewritten address.
// As described in the SRS specification, the algorithm is:
// 	- If 'addr' is an SRS0 address rewritten by us, bounce to the original envelope sender address.
// 	- If 'addr' is an SRS1 address rewritten by 1stHop.com and then us, bounce to the SRS0 address rewritten by 1stHop.com.
func (GS *GS) Reverse(addr string) (string, error) {
	fromLocal, _, isSRS, err := validateAddress(addr)
	if err != nil {
		return "", err
	}

	if isSRS {
		// Bounce back to the original envelope sender
		if strings.Contains(fromLocal, "SRS0") {
			hash, ts, domain, sender, _ := splitSRS0Address(fromLocal)
			// check timestamp
			tsErr := checkTS(ts, GS.validity)
			if tsErr != nil {
				return "", tsErr
			}
			// check hash
			hashErr := checkHash(hash, fmt.Sprintf("%s%s%s", ts, domain, sender), GS.key, GS.hashLen)
			if hashErr != nil {
				return "", hashErr
			}
			return fmt.Sprintf("%s@%s", sender, domain), nil
		}

		// Bounce back to 1st hop
		if strings.Contains(fromLocal, "SRS1") {
			hash, firsthopDomain, opaque, _ := splitSRS1Address(fromLocal)

			// check hash
			hashErr := checkHash(hash, fmt.Sprintf("%s%s", firsthopDomain, opaque), GS.key, GS.hashLen)
			if hashErr != nil {
				return "", hashErr
			}

			return fmt.Sprintf("SRS0%s@%s", opaque, firsthopDomain), nil
		}
	}
	return "", errors.New("gosrs: Not an SRS address")
}
