package fixture

import "crypto/sha256"

func checksum(data []byte) [32]byte {
	return sha256.Sum256(data)
}
