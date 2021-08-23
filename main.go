package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Tormak9970/node-reader/reader"
	"github.com/Tormak9970/node-reader/reader/hash"
	"github.com/Tormak9970/node-reader/reader/tor"
)

//* build command: go build -o nodeReader.exe main.go

type Node struct {
	Id            string `json:"id"`
	Fqn           string `json:"fqn"`
	BaseClass     string `json:"baseClass"`
	BktIdx        int    `json:"bktIdx"`
	DataOffset    uint16 `json:"dataOffset"`
	DataLength    uint32 `json:"dataLength"`
	ContentOffset uint16 `json:"contentOffset"`
	UncomprLength uint16 `json:"uncomprLength"`
	StreamStyle   uint8  `json:"streamStyle"`
}

func readGOMString(reader reader.SWTORReader, offset uint64) string {
	var strBuff []byte
	oldOffset, _ := reader.Seek(0, 1)
	reader.Seek(int64(offset), 0)
	for true {
		tempBuff := make([]byte, 1)
		_, err := reader.File.Read(tempBuff)
		if err != nil {
			log.Panicln(err)
		}
		curChar := tempBuff[0]

		if curChar == 0 {
			break
		} else {
			strBuff = append(strBuff, curChar)
		}
	}
	reader.Seek(oldOffset, 0)
	return string(strBuff)
}

func byteJoin(bytes []byte) string {
	res := ""
	for i := 0; i < len(bytes); i++ {
		res = fmt.Sprintf("%s%d", res, bytes[i])
	}
	return res
}

func uInt64(idLo uint32, idHi uint32) string {
	tableLo := [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 6}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 8}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 5, 6}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 1, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 4, 8}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 9, 6}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1, 9, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 6, 3, 8, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2, 7, 6, 8}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 5, 5, 3, 6}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 1, 0, 7, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 6, 2, 1, 4, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 2, 4, 2, 8, 8}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4, 8, 5, 7, 6}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 9, 7, 1, 5, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 9, 4, 3, 0, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 3, 8, 8, 6, 0, 8}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 6, 7, 7, 7, 2, 1, 6}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 5, 5, 4, 4, 3, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 7, 1, 0, 8, 8, 6, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 4, 2, 1, 7, 7, 2, 8}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 6, 8, 4, 3, 5, 4, 5, 6}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 3, 6, 8, 7, 0, 9, 1, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 7, 3, 7, 4, 1, 8, 2, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 4, 7, 4, 8, 3, 6, 4, 8}}
	tableHi := [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 2, 9, 4, 9, 6, 7, 2, 9, 6}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 5, 8, 9, 9, 3, 4, 5, 9, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7, 1, 7, 9, 8, 6, 9, 1, 8, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4, 3, 5, 9, 7, 3, 8, 3, 6, 8}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 8, 7, 1, 9, 4, 7, 6, 7, 3, 6}, {0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 7, 4, 3, 8, 9, 5, 3, 4, 7, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 2, 7, 4, 8, 7, 7, 9, 0, 6, 9, 4, 4}, {0, 0, 0, 0, 0, 0, 0, 0, 5, 4, 9, 7, 5, 5, 8, 1, 3, 8, 8, 8}, {0, 0, 0, 0, 0, 0, 0, 1, 0, 9, 9, 5, 1, 1, 6, 2, 7, 7, 7, 6}, {0, 0, 0, 0, 0, 0, 0, 2, 1, 9, 9, 0, 2, 3, 2, 5, 5, 5, 5, 2}, {0, 0, 0, 0, 0, 0, 0, 4, 3, 9, 8, 0, 4, 6, 5, 1, 1, 1, 0, 4}, {0, 0, 0, 0, 0, 0, 0, 8, 7, 9, 6, 0, 9, 3, 0, 2, 2, 2, 0, 8}, {0, 0, 0, 0, 0, 0, 1, 7, 5, 9, 2, 1, 8, 6, 0, 4, 4, 4, 1, 6}, {0, 0, 0, 0, 0, 0, 3, 5, 1, 8, 4, 3, 7, 2, 0, 8, 8, 8, 3, 2}, {0, 0, 0, 0, 0, 0, 7, 0, 3, 6, 8, 7, 4, 4, 1, 7, 7, 6, 6, 4}, {0, 0, 0, 0, 0, 1, 4, 0, 7, 3, 7, 4, 8, 8, 3, 5, 5, 3, 2, 8}, {0, 0, 0, 0, 0, 2, 8, 1, 4, 7, 4, 9, 7, 6, 7, 1, 0, 6, 5, 6}, {0, 0, 0, 0, 0, 5, 6, 2, 9, 4, 9, 9, 5, 3, 4, 2, 1, 3, 1, 2}, {0, 0, 0, 0, 1, 1, 2, 5, 8, 9, 9, 9, 0, 6, 8, 4, 2, 6, 2, 4}, {0, 0, 0, 0, 2, 2, 5, 1, 7, 9, 9, 8, 1, 3, 6, 8, 5, 2, 4, 8}, {0, 0, 0, 0, 4, 5, 0, 3, 5, 9, 9, 6, 2, 7, 3, 7, 0, 4, 9, 6}, {0, 0, 0, 0, 9, 0, 0, 7, 1, 9, 9, 2, 5, 4, 7, 4, 0, 9, 9, 2}, {0, 0, 0, 1, 8, 0, 1, 4, 3, 9, 8, 5, 0, 9, 4, 8, 1, 9, 8, 4}, {0, 0, 0, 3, 6, 0, 2, 8, 7, 9, 7, 0, 1, 8, 9, 6, 3, 9, 6, 8}, {0, 0, 0, 7, 2, 0, 5, 7, 5, 9, 4, 0, 3, 7, 9, 2, 7, 9, 3, 6}, {0, 0, 1, 4, 4, 1, 1, 5, 1, 8, 8, 0, 7, 5, 8, 5, 5, 8, 7, 2}, {0, 0, 2, 8, 8, 2, 3, 0, 3, 7, 6, 1, 5, 1, 7, 1, 1, 7, 4, 4}, {0, 0, 5, 7, 6, 4, 6, 0, 7, 5, 2, 3, 0, 3, 4, 2, 3, 4, 8, 8}, {0, 1, 1, 5, 2, 9, 2, 1, 5, 0, 4, 6, 0, 6, 8, 4, 6, 9, 7, 6}, {0, 2, 3, 0, 5, 8, 4, 3, 0, 0, 9, 2, 1, 3, 6, 9, 3, 9, 5, 2}, {0, 4, 6, 1, 1, 6, 8, 6, 0, 1, 8, 4, 2, 7, 3, 8, 7, 9, 0, 4}, {0, 9, 2, 2, 3, 3, 7, 2, 0, 3, 6, 8, 5, 4, 7, 7, 5, 8, 0, 8}}
	out := make([]byte, 20)
	out32 := make([]uint32, 20)
	if idHi == 0 {
		if idLo == 0 {
			return "0"
		} else {
			return strconv.Itoa(int(idLo))
		}
	}

	out32[0] = 0
	out32[1] = 0
	out32[2] = 0
	out32[3] = 0
	out32[4] = 0

	{
		for i := 0; i < 32; i++ {
			if (idLo & 1) != 0 {
				summand := tableLo[i]
				for j := 19; j >= 10; j-- {
					out[j] += summand[j]
				}
			}
			idLo = idLo >> 1
		}
		for j := 19; j >= 10; j-- {
			if out[j] > 9 {
				remainder := (out[j] % 10) | 0
				out[j-1] += ((out[j] - remainder) / 10) | 0
				out[j] = remainder
			}
		}
	}
	for i := 0; i < 32; i++ {
		if (idHi & 1) != 0 {
			summand := tableHi[i]
			for j := 19; j >= 0; j-- {
				out[j] += summand[j]
			}
		}
		idHi = idHi >> 1
	}
	for j := 19; j >= 1; j-- {
		if out[j] > 9 {
			remainder := (out[j] % 10) | 0
			out[j-1] += ((out[j] - remainder) / 10) | 0
			out[j] = remainder
		}
	}
	stringedBytes := byteJoin(out)
	regEx := regexp.MustCompile(`/^0+/`)
	found := regEx.FindString(stringedBytes)
	return strings.Replace(stringedBytes, found, "", 1)
}

func main() {
	torFile := ""
	if len(os.Args) >= 1 {
		torFile = os.Args[1]
	}
	if torFile == "" {
		return
	}

	filesAttempted := 0

	data := tor.Read(torFile)

	start := time.Now()

	for i := 0; i < 500; i++ { //500
		fileName := "/resources/systemgenerated/buckets/" + strconv.Itoa(i) + ".bkt"
		litHashes := hash.FromFilePath(fileName, 0)
		key := strconv.Itoa(int(litHashes.PH)) + "|" + strconv.Itoa(int(litHashes.SH))

		if data, ok := data[key]; ok {
			data := data
			filesAttempted++
			f, err := os.Open(torFile)
			if err != nil {
				log.Panicln(err)
			}
			defer f.Close()
			reader := reader.SWTORReader{File: f}

			oldPos, _ := reader.Seek(int64(data.Offset), 0)
			dblbOffset := data.Offset + uint64(data.HeaderSize) + 24

			reader.Seek(int64(dblbOffset), 0)
			dblbSize := reader.ReadUInt32()
			reader.ReadUInt32() //dblb header
			reader.ReadUInt32() //dblb version

			endOffset := data.Offset + uint64(data.HeaderSize) + 28 + uint64(dblbSize)

			var j int
			for pos, _ := reader.Seek(0, 1); pos < int64(endOffset); j++ {
				nodeOffset, _ := reader.Seek(0, 1)
				nodeSize := reader.ReadUInt32()
				if nodeSize == 0 {
					break
				}
				reader.ReadUInt32()
				idLo := reader.ReadUInt32() //idLo
				idHi := reader.ReadUInt32() //idHi

				reader.ReadUInt16() //type
				dataOffset := reader.ReadUInt16()

				nameOffset := reader.ReadUInt16()
				reader.ReadUInt16()

				baseClassLo := reader.ReadUInt32()
				baseClassHi := reader.ReadUInt32()

				reader.ReadUInt32()
				reader.ReadUInt32()

				uncomprLength := reader.ReadUInt16()
				reader.ReadUInt16()

				uncomprOffset := reader.ReadUInt16()
				reader.ReadUInt16()

				currOff, _ := reader.Seek(0, 1)
				reader.Seek(currOff+1, 0)
				streamStyle := reader.ReadUInt8()

				gomName := readGOMString(reader, uint64(nodeOffset)+uint64(nameOffset))

				nodeEntr := Node{Id: uInt64(idLo, idHi), Fqn: gomName, BaseClass: uInt64(baseClassLo, baseClassHi), BktIdx: i, DataOffset: nameOffset + dataOffset, DataLength: nodeSize - uint32(dataOffset), ContentOffset: uncomprOffset - dataOffset, UncomprLength: uncomprLength, StreamStyle: streamStyle}

				out, err := json.Marshal(nodeEntr)
				if err != nil {
					panic(err)
				}
				fmt.Println(string(out))

				reader.Seek(nodeOffset+((int64(nodeSize)+7)&-8), 0)
			}

			reader.Seek(oldPos, 0)
			fmt.Println(filesAttempted, 500)
		}
	}

	diff := time.Now().Sub(start)
	log.Println("duration", fmt.Sprintf("%s", diff))
}
