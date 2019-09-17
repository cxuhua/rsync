package rsync

import (
	"log"
	"testing"
)

func TestAnalyse(t *testing.T) {
	dst := "dst.txt"
	df := NewFileHashInfo(dst)
	if err := df.Open(nil); err != nil {
		panic(err)
	}
	defer df.Close()
	if err := df.Full(); err != nil {
		panic(err)
	}

	hi := df.GetHashInfo()
	log.Println(hi)

	src := "src.txt"
	sf := NewFileHashInfo(src, hi.BlockSize)
	if err := sf.Open(hi); err != nil {
		panic(err)
	}
	defer sf.Close()
	if err := sf.Analyse(func(info *AnalyseInfo) error {
		log.Println("idx = ", info.Index, "data = ", len(info.Data), "hash= ", info.Hash, "off = ", info.Off, " type = ", info.Type)
		return nil
	}); err != nil {
		panic(err)
	}
}
