package rsync

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestAnalyse(t *testing.T) {
	dst := "dst.txt"
	df := NewFileHashInfo(dst, 6)
	if err := df.Open(); err != nil {
		panic(err)
	}
	defer df.Close()
	if err := df.FillHashInfo(); err != nil {
		panic(err)
	}
	df.Close()

	hi := df.GetHashInfo()

	mp := NewFileMerger(dst, hi)
	defer mp.Close()

	src := "src.txt"
	sf := NewFileHashInfo(src, hi)
	if err := sf.Open(); err != nil {
		panic(err)
	}
	defer sf.Close()
	if err := sf.Analyse(func(info *AnalyseInfo) error {
		log.Println("idx = ", info.Index, "data = ", string(info.Data), "hash= ", hex.EncodeToString(info.Hash), "off = ", info.Off, " type = ", info.Type)
		return mp.Write(info)
	}); err != nil {
		panic(err)
	}
}
