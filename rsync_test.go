package rsync

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"log"
	"testing"
)

func TestHashBlockRW(t *testing.T) {
	mv := [md5.Size]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}
	b1 := HashBlock{}
	b1.Idx = 1
	b1.H1 = 140
	b1.H2 = 277
	b1.H3 = mv
	buf := &bytes.Buffer{}
	if err := b1.Write(buf); err != nil {
		t.Error(err)
		t.SkipNow()
	}
	b2 := &HashBlock{}
	if err := b2.Read(1, buf); err != nil {
		t.Error(err)
		t.SkipNow()
	}
	if !HashBlockEqual(b1, *b2) {
		t.Error("test failed")
		t.SkipNow()
	}
}

func TestAnalyse(t *testing.T) {
	dst := "dst.txt"

	hi, err := GetFileHashInfo(dst, func(b *HashBlock) {
		log.Println("HashBlock idx = ", b.Idx)
	}, DefaultBlockSize)
	if err != nil {
		panic(err)
	}

	//test read write
	buf := &bytes.Buffer{}
	if err := hi.Write(buf); err != nil {
		panic(err)
	}

	hh := NewHashInfo()
	if err := hh.Read(buf); err != nil {
		panic(err)
	}

	if !HashInfoEqual(hi, hh) {
		t.Error("HashInfoEqual error")
	}

	//
	mp := NewFileMerger(dst, hi)
	defer mp.Close()

	src := "src.txt"
	sf := NewFileHashInfo(src, hi)
	if err := sf.Open(); err != nil {
		panic(err)
	}
	defer sf.Close()
	if err := sf.Analyse(func(info *AnalyseInfo) error {
		log.Println("idx = ", info.Index, "data = ", len(info.Data), "hash= ", hex.EncodeToString(info.Hash), "off = ", info.Off, " type = ", info.Type)
		return mp.Write(info)
	}); err != nil {
		panic(err)
	}
}
