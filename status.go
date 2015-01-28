package smtpd

var statusString = map[int]string{
	StatusPasswordNeeded:     "4.7.12  A password transition is needed",
	StatusTempAuthFailure:    "4.7.0  Temporary authentication failure",
	StatusAuthInvalid:        "5.7.8  Authentication credentials invalid",
	StatusAuthRequired:       "5.7.0  Authentication required",
	StatusEncryptionRequired: "5.7.11  Encryption required for requested authentication mechanism",
}

func StatusString(status int) string {
	s, found := statusString[status]
	if !found {
		return "unknown"
	}
	return s
}

const (
	StatusPasswordNeeded     = 432
	StatusTempAuthFailure    = 454
	StatusAuthInvalid        = 535
	StatusAuthRequired       = 530
	StatusEncryptionRequired = 538
)

var ErrPasswordNeeded = Error{Code: StatusPasswordNeeded, Message: StatusString(StatusPasswordNeeded)}
var ErrTempAuthFailure = Error{Code: StatusTempAuthFailure, Message: StatusString(StatusTempAuthFailure)}
var ErrAuthInvalid = Error{Code: StatusAuthInvalid, Message: StatusString(StatusAuthInvalid)}
var ErrAuthRequired = Error{Code: StatusAuthRequired, Message: StatusString(StatusAuthRequired)}
var ErrEncryptionRequired = Error{Code: StatusEncryptionRequired, Message: StatusString(StatusEncryptionRequired)}
