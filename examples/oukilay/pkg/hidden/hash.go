package hidden

import (
	"fmt"
	"hash/fnv"
)

func FNVHashByte(b []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(b)
	return hash.Sum64()
}

func FNVHashStr(s string) uint64 {
	return FNVHashByte([]byte(s))
}

func FNVHashInt(i int) uint64 {
	return FNVHashStr(fmt.Sprintf("%d", i))
}
