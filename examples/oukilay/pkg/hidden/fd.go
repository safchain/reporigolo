package hidden

type RkFdContentKey struct {
	ID    uint64
	Chunk uint32
}

// Write write binary representation
func (p *RkFdContentKey) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.ID)
	ByteOrder.PutUint32(buffer[8:12], p.Chunk)
}

// Bytes returns array of byte representation
func (p *RkFdContentKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

type RkFdContent struct {
	Size    uint64
	Content [64]byte
}

// Write write binary representation
func (p *RkFdContent) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Size)
	copy(buffer[8:], p.Content[:])
}

// Bytes returns array of byte representation
func (p *RkFdContent) Bytes() []byte {
	b := make([]byte, len(p.Content)+8)
	p.Write(b)
	return b
}

type RkFdKey struct {
	Fd  uint64
	Pid uint32
}

// Write write binary representation
func (p *RkFdKey) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Fd)
	ByteOrder.PutUint32(buffer[8:12], p.Pid)
}

// Bytes returns array of byte representation
func (p *RkFdKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

// RkFdAttr represents a file
type RkFdAttr struct {
	Action      uint64
	ReturnValue int64
}

// Write write binary representation
func (p *RkFdAttr) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Action)
	ByteOrder.PutUint64(buffer[8:16], uint64(p.ReturnValue))
}

// Bytes returns array of byte representation
func (p *RkFdAttr) Bytes() []byte {
	b := make([]byte, 56)
	p.Write(b)
	return b
}
