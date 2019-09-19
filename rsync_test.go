package rsync

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"log"
	"testing"

	"github.com/gofrs/flock"
)

func TestR(t *testing.T) {
	f := flock.New("aa.lck")
	defer f.Close()
	locked, err := f.TryLock()
	locked, err = f.TryLock()
	log.Println(err, locked)
	f.Unlock()
}

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
	}, 4)
	if err != nil {
		panic(err)
	}

	//test read write
	buf, err := hi.ToBuffer()
	if err != nil {
		panic(err)
	}

	hh, err := NewHashInfoWithBuf(buf)
	if err != nil {
		panic(err)
	}

	if !HashInfoEqual(hi, hh) {
		t.Error("HashInfoEqual error")
	}
	//
	mp := NewFileMerger(dst, hh)
	if err = mp.Open(); err != nil {
		panic(err)
	}
	defer mp.Close()

	src := "src.txt"
	sf := NewFileHashInfo(src, hh)
	if err := sf.Open(); err != nil {
		panic(err)
	}
	defer sf.Close()

	abuf := &bytes.Buffer{}

	if err := sf.Analyse(func(ai *AnalyseInfo) error {
		abuf.Reset()
		if err := ai.Write(abuf); err != nil {
			return err
		}
		info := &AnalyseInfo{}
		if err := info.Read(abuf); err != nil {
			return err
		}
		log.Println("idx = ", info.Index, "data = ", len(info.Data), "hash= ", hex.EncodeToString(info.Hash), "off = ", info.Off, " type = ", info.Type)
		return mp.Write(info)
	}); err != nil {
		panic(err)
	}
}
