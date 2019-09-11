package rsync

import (
	"bytes"
	"log"
	"testing"
)

func TestBuffer(t *testing.T) {

	b := bytes.NewBuffer(nil)
	b.Write([]byte{1, 2, 3})
	b.Read([]byte{0})
	log.Println(b.Bytes())
	b.Write([]byte{4})
	log.Println(b.Bytes())

}

func TestGetFileHashBlock(t *testing.T) {
	dst := "dst.txt"
	df := NewFileHashInfo(DefaultBlockSize, dst)
	if err := df.Open(nil); err != nil {
		panic(err)
	}
	defer df.Close()
	if err := df.Full(); err != nil {
		panic(err)
	}
	b, err := df.ReadBlock(0)
	if err != nil {
		panic(err)
	}
	log.Println(b, df)
	hi := df.GetHashInfo()

	log.Println(hi)

	src := "src.txt"
	sf := NewFileHashInfo(hi.BlockSize, src)
	if err := sf.Open(hi); err != nil {
		panic(err)
	}
	defer sf.Close()
	if err := sf.ComputeHash(func(info *ComputerInfo) error {
		log.Println("idx = ", info.BlockIdx, "off = ", info.Off)
		return nil
	}); err != nil {
		panic(err)
	}
}
