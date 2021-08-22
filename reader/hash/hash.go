package hash

import (
	"fmt"
	"strconv"
	"strings"
)

type FileId struct {
	PH uint32
	SH uint32
}

type HashData struct {
	PH       uint
	SH       uint
	Filename string
	CRC      string
}

func Gen() map[string]HashData {
	hash := map[string]HashData{}

	for i := 0; i < 500; i++ {
		fileName := "/resources/systemgenerated/buckets/" + strconv.Itoa(i) + ".bkt"
		hashes := FromFilePath(fileName, 0)
		fmt.Println(hashes)
		hash[strconv.Itoa(int(hashes.PH))+"|"+strconv.Itoa(int(hashes.SH))] = HashData{uint(hashes.PH), uint(hashes.SH), fileName, ""}
	}

	return hash
}

func FromFilePath(filePath string, seed uint32) FileId {
	var eax, ecx, edx, ebx, esi, edi uint32
	if seed == 0 {
		seed = 0xDEADBEEF
	}

	s := strings.ToLower(filePath)

	eax = 0 //ecx = edx = ebx = esi = edi = 0;
	ebx, edi, esi = uint32(len(s))+seed, uint32(len(s))+seed, uint32(len(s))+seed

	var i int

	for i = 0; i+12 < len(s); i += 12 {
		edi = uint32(int32(s[i+7])<<24|int32(s[i+6])<<16|int32(s[i+5])<<8|int32(s[i+4])) + edi
		esi = uint32(int32(s[i+11])<<24|int32(s[i+10])<<16|int32(s[i+9])<<8|int32(s[i+8])) + esi
		edx = uint32(int32(s[i+3])<<24|int32(s[i+2])<<16|int32(s[i+1])<<8|int32(s[i])) - esi

		edx = (edx + ebx) ^ (esi >> 28) ^ (esi << 4)
		esi += edi
		edi = (edi - edx) ^ (edx >> 26) ^ (edx << 6)
		edx += esi
		esi = (esi - edi) ^ (edi >> 24) ^ (edi << 8)
		edi += edx
		ebx = (edx - esi) ^ (esi >> 16) ^ (esi << 16)
		esi += edi
		edi = (edi - ebx) ^ (ebx >> 13) ^ (ebx << 19)
		ebx += esi
		esi = (esi - edi) ^ (edi >> 28) ^ (edi << 4)
		edi += ebx
	}

	if len(s)-i > 0 {
		switch len(s) - i {
		case 12:
			esi += uint32(int32(s[i+11]) << 24)
			fallthrough
		case 11:
			esi += uint32(int32(s[i+10]) << 16)
			fallthrough
		case 10:
			esi += uint32(int32(s[i+9]) << 8)
			fallthrough
		case 9:
			esi += uint32(s[i+8]) //I added this, not sure if it works
			fallthrough
		case 8:
			edi += uint32(int32(s[i+7]) << 24)
			fallthrough
		case 7:
			edi += uint32(int32(s[i+6]) << 16)
			fallthrough
		case 6:
			edi += uint32(int32(s[i+5]) << 8)
			fallthrough
		case 5:
			edi += uint32(s[i+4]) //I added this, not sure if it works
			fallthrough
		case 4:
			ebx += uint32(int32(s[i+3]) << 24)
			fallthrough
		case 3:
			ebx += uint32(int32(s[i+2]) << 16)
			fallthrough
		case 2:
			ebx += uint32(int32(s[i+1]) << 8)
			fallthrough
		case 1:
			ebx += uint32(s[i]) //I added this, not sure if it works
		}

		esi = (esi ^ edi) - ((edi >> 18) ^ (edi << 14))
		ecx = (esi ^ ebx) - ((esi >> 21) ^ (esi << 11))
		edi = (edi ^ ecx) - ((ecx >> 7) ^ (ecx << 25))
		esi = (esi ^ edi) - ((edi >> 16) ^ (edi << 16))
		edx = (esi ^ ecx) - ((esi >> 28) ^ (esi << 4))
		edi = (edi ^ edx) - ((edx >> 18) ^ (edx << 14))
		eax = (esi ^ edi) - ((edi >> 8) ^ (edi << 24))

		return FileId{edi, eax}
	}
	return FileId{esi, eax}
}

func ToString(fId FileId) string {
	return string(rune(AsUInt64(fId)))
}

func AsUInt64(fId FileId) int64 {
	result := fId.PH //may need to cast here
	result = (result << 32) | fId.SH

	return int64(result)
}
