package github.com/vompressor/mkpw

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/tredoe/osutil/user/crypt"
	"github.com/tredoe/osutil/user/crypt/apr1_crypt"
	"github.com/tredoe/osutil/user/crypt/common"
	"github.com/tredoe/osutil/user/crypt/md5_crypt"
	"github.com/tredoe/osutil/user/crypt/sha256_crypt"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

func PasswordPrompt() (string, error) {
	var p1, p2 []byte // passwords
	var err error     // error holder

	// loop until match
	for {
		// prompt user and read password
		fmt.Print("Password: ")
		if p1, err = gopass.GetPasswd(); err != nil {
			return "", err
		}

		// prompt user and read confirmation
		fmt.Print("Confirm:  ")
		if p2, err = gopass.GetPasswd(); err != nil {
			return "", err
		}

		// compare passwords and ensure non-nil
		if bytes.Equal(p1, p2) && p1 != nil {
			// return password string - no error
			return string(p1), nil
		}

		// not equal - try again
		fmt.Print("Password confirmation failed.  Please try again.\n")
	}
}

func MkPasswd(cryptoHash string, pw string, salt string, rounds int) (string, error) {
	var c crypt.Crypter
	var s common.Salt

	var saltString string
	var retPW string

	switch strings.ToLower(cryptoHash) {
	case "apr1":
		c = crypt.New(crypt.APR1)
		s = apr1_crypt.GetSalt()
	case "md5":
		c = crypt.New(crypt.MD5)
		s = md5_crypt.GetSalt()
	case "sha256":
		c = crypt.New(crypt.SHA256)
		s = sha256_crypt.GetSalt()
	case "sha512":
		c = crypt.New(crypt.SHA512)
		s = sha512_crypt.GetSalt()
	default:
		var eret CryptoHashMethodError
		eret.InputedVal = cryptoHash
		return "", eret
	}

	// TODO:: Rounds var check

	if salt != "" {
		if len(salt) > s.SaltLenMax || len(salt) < s.SaltLenMin {
			var eret CryptoSaltLengthError
			eret.InputedSaltLen = len(salt)
			eret.MaxLen = s.SaltLenMax
			eret.MinLen = s.SaltLenMin
			return "", eret
		}

		if rounds != 0 && rounds == s.RoundsDefault {
			saltString = fmt.Sprintf("%srounds=%d$%s", s.MagicPrefix, rounds, saltString)
		} else {
			saltString = fmt.Sprintf("%s%s", s.MagicPrefix, saltString)
		}
	} else if rounds > 0 {
		saltString = string(s.GenerateWRounds(s.SaltLenMax, rounds))
	}

	retPW, err := c.Generate([]byte(pw), []byte(saltString))

	if err != nil {
		return "", err
	}

	return retPW, nil
}

// Error Types...

type CryptoHashMethodError struct {
	InputedVal string
}

func (e CryptoHashMethodError) Error() string {
	return "Invalid input hash method: " + e.InputedVal
}

type CryptoSaltLengthError struct {
	InputedSaltLen int
	MaxLen         int
	MinLen         int
}

func (e CryptoSaltLengthError) Error() string {
	return fmt.Sprintf("Invailid Salt Inputed len: %d  Max len : %d  Min len: %d", e.InputedSaltLen, e.MaxLen, e.MinLen)
}

type CryptoRoundsValueError struct {
	InputedRounds int
	Max           int
	Min           int
}

func (e CryptoRoundsValueError) Error() string {
	return fmt.Sprintf("Invailid Rounds Inputed: %d  Max : %d  Min: %d", e.InputedRounds, e.Max, e.Min)
}
