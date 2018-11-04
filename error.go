package gosrs

import "errors"

var (
	ErrInvalidSeparator          = errors.New("gosrs: Invalid SRS separator. Must be one of '=', '+', '-'. Default '='")
	ErrInvalidSRSAddress         = errors.New("gosrs: Not an SRS address")
	ErrInvalidHash               = errors.New("gosrs: Invalid hash")
	ErrInvalidTimestampCharacter = errors.New("gosrs: Invalid timestamp character")
	ErrTimestampExpired          = errors.New("gosrs: Timestamp expired")
	ErrInvalidAddress            = errors.New("gosrs: Invalid email address")
)
