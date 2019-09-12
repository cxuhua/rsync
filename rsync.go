package rsync

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
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
	Idx int            //last block size
	H1  uint16         //adler32 low  = (hash & 0xFFFF)
	H2  uint16         //adler32 high = ((hash > 16) & 0xFFFF)
	H3  [md5.Size]byte //md5 sum
	Len int64          //block data len
	Off int64          //block offset
}

func (this HashBlock) Clone() HashBlock {
	ret := HashBlock{}
	ret.Idx = this.Idx
	ret.H1 = this.H1
	ret.H2 = this.H2
	copy(ret.H3[:], this.H3[:])
	ret.Len = this.Len
	ret.Off = this.Off
	return ret
}

func (this HashBlock) String() string {
	return fmt.Sprintf("IDX=%d H1=%.4X H2=%.4X H3=%s Len=%d Off=%d", this.Idx, this.H1, this.H2, hex.EncodeToString(this.H3[:]), this.Len, this.Off)
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
	h1 := uint16(h & 0xFFFF)
	h2 := uint16((h >> 16) & 0xFFFF)
	l := len(this.Blocks)
	for i := o; i < l; i++ {
		v := this.Blocks[i]
		if v.H1 == h1 && v.H2 == h2 {
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

type FileReader struct {
	File *os.File
	Size int
	Buf  *bytes.Buffer
	Hash hash.Hash
}

func (this *FileReader) Read(offset int64) ([]byte, error) {
	one := []byte{0}
	n, err := this.Buf.Read(one)
	if err == nil && n == 1 {
		return one, nil
	}
	if _, err := this.File.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, this.Size)
	if num, err := this.File.Read(buf); err != nil {
		return nil, err
	} else if _, err := this.Buf.Write(buf[:num]); err != nil {
		return nil, err
	} else if _, err := this.Hash.Write(buf[:num]); err != nil {
		return nil, err
	}
	n, err = this.Buf.Read(one)
	if err == nil && n == 1 {
		return one, nil
	}
	return nil, io.EOF
}

func NewFileReader(f *os.File, siz int) *FileReader {
	if f == nil {
		panic(errors.New("f nil"))
	}
	c := &FileReader{}
	c.Hash = md5.New()
	c.File = f
	c.Buf = &bytes.Buffer{}
	c.Size = siz
	return c
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
		Blocks:    []HashBlock{},
		MD5:       this.MD5,
		BlockSize: this.BlockSize,
	}
	for _, v := range this.Blocks {
		ret.Blocks = append(ret.Blocks, v.Clone())
	}
	sort.Slice(ret.Blocks, func(i, j int) bool {
		if ret.Blocks[i].H1 == ret.Blocks[j].H1 {
			return ret.Blocks[i].H2 < ret.Blocks[j].H2
		}
		return ret.Blocks[i].H1 < ret.Blocks[j].H1
	})
	return ret
}

const (
	ComputerTypeData  = 1 //data
	ComputerTypeIndex = 2 //index
	ComputerTypeClose = 4 //hash
	ComputerTypeOpen  = 8 //off=filesize
)

type AnalyseInfo struct {
	HashFile *FileHashInfo //file info
	Index    int           // >= 0 map to blocks
	Off      int64
	Data     []byte // len > 0 has new data
	Type     int    // &1  idx start, = &2 computer stop &4 = data
	Hash     []byte
}

func (this *FileHashInfo) CheckPass(buf []byte, h12 uint32) int {
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
	return this.Info.Blocks[o].Idx
}

func (this *FileHashInfo) Analyse(fn func(info *AnalyseInfo) error) error {
	if this.Info == nil {
		return errors.New("info nil")
	}
	if this.File == nil {
		return errors.New("file not open")
	}
	info := &AnalyseInfo{HashFile: this}
	info.Type = ComputerTypeOpen
	info.Off = this.FileSize
	if err := fn(info); err != nil {
		return err
	}
	rbuf := bytes.NewBuffer(nil)
	wbuf := bytes.NewBuffer(nil)
	adler := adler32.New()
	file := NewFileReader(this.File, this.BlockSize)
	for foff := int64(0); foff < this.FileSize; foff++ {
		if one, err := file.Read(foff); err != nil {
			return err
		} else if _, err := rbuf.Write(one); err != nil {
			return err
		} else if _, err := adler.Write(one); err != nil {
			return err
		} else if idx := this.CheckPass(rbuf.Bytes(), adler.Sum32()); idx >= 0 {
			adler.Reset()
			info := &AnalyseInfo{HashFile: this}
			info.Type = ComputerTypeIndex
			info.Index = idx
			if wbuf.Len() > 0 {
				info.Data = wbuf.Bytes()
				info.Type |= ComputerTypeData
			}
			info.Off = foff - int64(wbuf.Len()+rbuf.Len()-1)
			if err := fn(info); err != nil {
				return err
			}
			wbuf.Reset()
			rbuf.Reset()
			continue
		}
		if rbuf.Len() >= this.BlockSize {
			one := []byte{0}
			adler.Reset()
			if num, err := rbuf.Read(one); err != nil {
				return err
			} else if _, err := wbuf.Write(one[:num]); err != nil {
				return err
			}
			foff -= int64(this.BlockSize - 1)
			rbuf.Reset()
		}
		if wbuf.Len() >= this.BlockSize {
			info := &AnalyseInfo{HashFile: this}
			info.Type = ComputerTypeData
			info.Data = wbuf.Bytes()
			info.Off = foff - int64(wbuf.Len()-1)
			if err := fn(info); err != nil {
				return err
			}
			wbuf.Reset()
		}
	}
	if _, err := wbuf.Write(rbuf.Bytes()); err != nil {
		return err
	}
	info = &AnalyseInfo{HashFile: this}
	info.Type = ComputerTypeClose
	info.Hash = file.Hash.Sum(nil)
	if wbuf.Len() > 0 {
		info.Type |= ComputerTypeData
		info.Data = wbuf.Bytes()
		info.Off = this.FileSize - int64(wbuf.Len())
	}
	return fn(info)
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
		hb.Idx = int(i)
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
