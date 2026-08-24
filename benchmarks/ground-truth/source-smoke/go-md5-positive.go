package fixture

import "crypto/md5"

func checksum(data []byte) [16]byte {
	return md5.Sum(data)
}
