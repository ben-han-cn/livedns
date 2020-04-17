package util

import (
	"unsafe"

	"github.com/ben-han-cn/g53"
	"github.com/cespare/xxhash"
)

func HashQuery(name *g53.Name, typ g53.RRType) (uint64, uint64) {
	l := len(name.Bytes()) + 1 + 2
	raw := make([]byte, l)
	copy(raw, name.Bytes())
	raw[l-3] = '+'
	raw[l-1] = byte(uint16(typ) & 0xff)
	raw[l-2] = byte(uint16(typ) >> 8)
	return MemHash(raw), xxhash.Sum64(raw)
}

type stringStruct struct {
	str unsafe.Pointer
	len int
}

//go:noescape
//go:linkname memhash runtime.memhash
func memhash(p unsafe.Pointer, h, s uintptr) uintptr

func MemHash(data []byte) uint64 {
	ss := (*stringStruct)(unsafe.Pointer(&data))
	return uint64(memhash(ss.str, 0, uintptr(ss.len)))
}
