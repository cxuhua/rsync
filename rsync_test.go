package rsync

import (
	"log"
	"testing"
)

func TestBuffer(t *testing.T) {

	b := HashBlock{}
	b.H3[0] = 1
	b.H3[1] = 2
	b.H3[2] = 3
	b.H3[3] = 4

	c := b

	log.Println(c)

	b.H3[0] = 0

	log.Println(c)
}

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
		log.Println("idx = ", info.Index, "date = ", len(info.Data), "hash= ", info.Hash, "off = ", info.Off, " type = ", info.Type)
		return nil
	}); err != nil {
		panic(err)
	}
}
