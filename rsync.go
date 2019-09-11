package rsync

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	DefaultBlockSize = 1024
)

type HashBlock struct {
	H1  uint16         //adler32 low  = (hash & 0xFFFF)
	H2  uint16         //adler32 high = ((hash > 16) & 0xFFFF)
	H3  [md5.Size]byte //md5 sum
	Len int64          //block data len
	Off int64          //block offset
}

func (this HashBlock) String() string {
	return fmt.Sprintf("H1=%.4X H2=%.4X H3=%s Len=%d Off=%d", this.H1, this.H2, hex.EncodeToString(this.H3[:]), this.Len, this.Off)
}

func HashBlockEqual(b1 HashBlock, b2 HashBlock) bool {
	if b1.H1 != b2.H1 {
		return false
	}
	if b2.H2 != b2.H2 {
		return false
	}
	return bytes.Equal(b1.H3[:], b2.H3[:])
}

type HashInfo struct {
	Blocks    []HashBlock //block info
	MD5       []byte      //file md5
	BlockSize int         //block size
}

func (this *HashInfo) PassH1(o int, h uint32) (int, bool) {
	h1 := uint16(h & 0xFFFF)
	l := len(this.Blocks)
	for i := o; i < l; i++ {
		v := this.Blocks[i]
		if v.H1 == h1 {
			return i, true
		}
	}
	return 0, false
}

func (this *HashInfo) PassH2(o int, h uint32) (int, bool) {
	h2 := uint16((h >> 16) & 0xFFFF)
	l := len(this.Blocks)
	for i := o; i < l; i++ {
		v := this.Blocks[i]
		if v.H2 == h2 {
			return i, true
		}
	}
	return 0, false
}

func (this *HashInfo) PassH3(o int, h [md5.Size]byte) (int, bool) {
	l := len(this.Blocks)
	for i := o; i < l; i++ {
		v := this.Blocks[i]
		if bytes.Equal(v.H3[:], h[:]) {
			return i, true
		}
	}
	return 0, false
}

type FileHashInfo struct {
	Info      *HashInfo   //hash info from computer
	Path      string      //file path
	File      *os.File    //if file opened
	Blocks    []HashBlock //block info
	Count     int64       //block count
	MD5       []byte      //file md5
	BlockSize int         //block size
	FileSize  int64       //file size
}

func (this *FileHashInfo) GetHashInfo() *HashInfo {
	ret := &HashInfo{
		Blocks:    this.Blocks,
		MD5:       this.MD5,
		BlockSize: this.BlockSize,
	}
	sort.SliceIsSorted(ret.Blocks, func(i, j int) bool {
		if ret.Blocks[i].H1 == ret.Blocks[j].H1 {
			return ret.Blocks[i].H2 < ret.Blocks[j].H2
		}
		return ret.Blocks[i].H1 < ret.Blocks[j].H1
	})
	return ret
}

const (
	ComputerTypeData  = 1
	ComputerTypeIndex = 2
)

type ComputerInfo struct {
	HashFile *FileHashInfo //file info
	BlockIdx int           // >= 0 map to blocks
	Off      int64
	Data     []byte // len > 0 has new data
	Type     int    // &1  idx start, = &2 computer stop &4 = data
}

func (this *FileHashInfo) ComputeHash(fn func(info *ComputerInfo) error) error {
	if this.Info == nil {
		return errors.New("info nil")
	}
	if this.File == nil {
		return errors.New("file not open")
	}
	checkPass := func(buf []byte) int {
		h12 := adler32.Checksum(buf)
		o, b := this.Info.PassH1(0, h12)
		if !b {
			return -1
		}
		o, b = this.Info.PassH2(o, h12)
		if !b {
			return -2
		}
		h3 := md5.Sum(buf)
		o, b = this.Info.PassH3(o, h3)
		if !b {
			return -3
		}
		return o
	}
	var err error = nil
	rbuf := bytes.NewBuffer(nil)
	fbuf := make([]byte, this.BlockSize)
	wbuf := bytes.NewBuffer(nil)
	one := []byte{0}
	rsiz := this.BlockSize
	if this.FileSize < int64(rsiz) {
		rsiz = int(this.FileSize)
	}
	for foff := int64(0); foff < this.FileSize; foff++ {
		if (this.FileSize - foff) < int64(rsiz) {
			rsiz = int(this.FileSize - foff)
		}
		if err := this.read(foff, rsiz, fbuf); err != nil {
			return err
		}
		foff += int64(rsiz - 1)
		if _, err := rbuf.Write(fbuf[:rsiz]); err != nil {
			return err
		}
		idx := checkPass(rbuf.Bytes())
		if idx >= 0 && wbuf.Len() > 0 {
			info := &ComputerInfo{HashFile: this}
			info.BlockIdx = -1
			info.Type = ComputerTypeData
			info.Data = wbuf.Bytes()
			info.Off = foff - int64(this.BlockSize+wbuf.Len()) + 1
			err = fn(info)
			if err != nil {
				return err
			}
			wbuf.Reset()
		}
		if idx >= 0 {
			info := &ComputerInfo{HashFile: this}
			info.BlockIdx = idx
			info.Type = ComputerTypeIndex
			info.Off = foff - int64(this.BlockSize) + 1
			err = fn(info)
			if err != nil {
				return err
			}
			rbuf.Reset()
			rsiz = this.BlockSize
		} else {
			if _, err := rbuf.Read(one); err != nil {
				return err
			}
			if _, err := wbuf.Write(one); err != nil {
				return err
			}
			rsiz = 1
		}
	}
	return nil
}

func (this *FileHashInfo) Open(hi *HashInfo) error {
	this.Info = hi
	if this.Info != nil {
		this.BlockSize = hi.BlockSize
	}
	if this.BlockSize == 0 {
		return errors.New("block size error")
	}
	fs, err := os.Stat(this.Path)
	if err != nil {
		return fmt.Errorf("file stat error: %v", err)
	}
	this.FileSize = fs.Size()
	if this.FileSize == 0 {
		return errors.New("file size == 0")
	}
	if this.FileSize%int64(this.BlockSize) == 0 {
		this.Count = (this.FileSize / int64(this.BlockSize))
	} else {
		this.Count = (this.FileSize / int64(this.BlockSize)) + 1
	}
	fd, err := os.OpenFile(this.Path, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open file error: %v", err)
	}
	this.File = fd
	return nil
}

func (this *FileHashInfo) read(off int64, size int, buf []byte) error {
	if _, err := this.File.Seek(off, io.SeekStart); err != nil {
		return err
	}
	l := size
	p := 0
	for l-p > 0 {
		rl, err := this.File.Read(buf[p : p+l])
		if err != nil {
			return err
		}
		p += rl
		l -= rl
	}
	return nil
}

func (this *FileHashInfo) Full() error {
	if this.File == nil {
		return errors.New("file not open")
	}
	fmd5 := md5.New()
	buf := make([]byte, this.BlockSize)
	pos := int64(0)
	for i := int64(0); i < this.Count; i++ {
		hb := HashBlock{}
		rsiz := this.BlockSize
		if this.FileSize-pos < int64(rsiz) {
			rsiz = int(this.FileSize - pos)
		}
		if err := this.read(pos, int(rsiz), buf); err != nil {
			return fmt.Errorf("read file error: %v", err)
		}
		fmd5.Write(buf[:rsiz])
		acs := adler32.Checksum(buf[:rsiz])
		hb.Len = int64(rsiz)
		hb.Off = pos
		hb.H1 = uint16((acs & 0xFFFF))
		hb.H2 = uint16(((acs >> 16) & 0xFFFF))
		hb.H3 = md5.Sum(buf[:rsiz])
		this.Blocks = append(this.Blocks, hb)
		pos += int64(rsiz)
	}
	this.MD5 = fmd5.Sum(nil)
	return nil
}

func (this *FileHashInfo) Close() {
	if this.File != nil {
		this.File.Close()
		this.File = nil
	}
}

func (this *FileHashInfo) ReadBlock(idx int) ([]byte, error) {
	if idx < 0 || idx >= len(this.Blocks) {
		return nil, errors.New("idx bound out")
	}
	b := this.Blocks[idx]
	if b.Len == 0 {
		return nil, errors.New("block len zero")
	}
	buf := make([]byte, b.Len)
	if err := this.read(b.Off, int(b.Len), buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (this *FileHashInfo) String() string {
	s := []string{"\n", this.Path}
	for i, v := range this.Blocks {
		s = append(s, fmt.Sprintf("%.5d: %s", i, v.String()))
	}
	s = append(s, fmt.Sprintf("File MD5=%s SIZE=%d COUNT=%d", hex.EncodeToString(this.MD5), this.FileSize, this.Count))
	return strings.Join(s, "\n")
}

func NewFileHashInfo(bsiz int, file string) *FileHashInfo {
	if bsiz == 0 {
		bsiz = DefaultBlockSize
	}
	return &FileHashInfo{
		Blocks:    []HashBlock{},
		BlockSize: bsiz,
		Path:      file,
	}
}
