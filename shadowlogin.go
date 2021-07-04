package github.com/vompressor/mkpw

import (
	"github.com/tredoe/osutil/user/crypt"
	_ "github.com/tredoe/osutil/user/crypt/apr1_crypt"
	_ "github.com/tredoe/osutil/user/crypt/common"
	_ "github.com/tredoe/osutil/user/crypt/md5_crypt"
	_ "github.com/tredoe/osutil/user/crypt/sha256_crypt"
	_ "github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

func ShadowLogin(shadow string, pw string) (bool, error) {

	// TODO:: This function contains "panic" risk
	c := crypt.NewFromHash(shadow)

	err := c.Verify(shadow, []byte(pw))
	if err != nil {
		return false, err
	}
	return true, nil
}

type InvailidShadowHashError struct {
	InputedShadow string
}

type PasswordMissMatchError struct {
}
