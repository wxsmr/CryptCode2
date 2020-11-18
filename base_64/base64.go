package base_64

import "encoding/base64"

const (
	base64Table = "123QRSTUabcdVWXYZHijKLAWDCABDstEFGuvwxyzGHIJklmnopqr234560178912"
)

func Base64Encode(src []byte) []byte {
	coder := base64.NewEncoding(base64Table)
	return []byte(coder.EncodeToString(src))
}


func Base64Decode(src []byte) ([]byte, error) {
	coder := base64.NewEncoding(base64Table)
	return coder.DecodeString(string(src))
}
