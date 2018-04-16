package gosrs

import (
	"errors"
	"net/mail"
	"regexp"
	"strings"
)

func validateAddress(address string) (string, string, bool, error) {

	// Check for valid RFC address
	a, err := mail.ParseAddress(address)
	if err != nil {
		return "", "", false, errors.New("gosrs: Invalid email address")
	}
	ret := strings.Split(a.Address, "@")

	r := regexp.MustCompile(`(?i)^SRS[01][=+-]`)

	if r.MatchString(ret[0]) {
		return ret[0], ret[1], true, nil
	}

	return ret[0], ret[1], false, nil
}

// splitSRS1Address splits 'address' and returns hash, 1st hop host, and opaque part
func splitSRS1Address(address string) (string, string, string, error) {
	sep, err := detectSeparator(address)
	r := strings.SplitN(address, sep, 4)
	if err != nil {
		return "", "", "", err
	}
	return r[1], r[2], r[3], nil
}

// splitSRS0Address splits 'address' and returns hash, timestamp, original domain, and original sender
func splitSRS0Address(address string) (string, string, string, string, error) {
	sep, err := detectSeparator(address)
	if err != nil {
		return "", "", "", "", err
	}
	r := strings.Split(address, sep)
	return r[1], r[2], r[3], r[4], nil
}

func detectSeparator(address string) (string, error) {
	// We have an SRS address
	separator := string(address[4])
	if separator == "=" || separator == "-" || separator == "+" {
		return separator, nil
	}
	return "", errors.New("gosrs: Invalid SRS separator")

}
