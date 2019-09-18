package rsync

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"io"
	"os"
)

const (
	DefaultBlockSize = 1024
)

type HashBlock struct {
	Idx int            //last block size
	H1  uint16         //adler32 low  = (hash & 0xFFFF)
	H2  uint16         //adler32 high = ((hash > 16) & 0xFFFF)
	H3  [md5.Size]byte //md5 sum
	Len int            //block data len
	Off int64          //block offset
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

type HashMap map[uint16][]HashBlock

func (this HashMap) PassH1(h uint32) (int, bool) {
	h1 := uint16(h & 0xFFFF)
	hs, ok := this[h1]
	if !ok {
		return 0, false
	}
	for _, v := range hs {
		if v.H1 == h1 {
			return v.Idx, true
		}
	}
	return 0, false
}

func (this HashMap) PassH2(h uint32) (int, bool) {
	h1 := uint16(h & 0xFFFF)
	h2 := uint16((h >> 16) & 0xFFFF)
	hs, ok := this[h1]
	if !ok {
		return 0, false
	}
	for _, v := range hs {
		if v.H1 == h1 && v.H2 == h2 {
			return v.Idx, true
		}
	}
	return 0, false
}

func (this HashMap) PassH3(h uint32, mv [md5.Size]byte) (int, bool) {
	h1 := uint16(h & 0xFFFF)
	h2 := uint16((h >> 16) & 0xFFFF)
	hs, ok := this[h1]
	if !ok {
		return 0, false
	}
	for _, v := range hs {
		if v.H1 == h1 && v.H2 == h2 && bytes.Equal(v.H3[:], mv[:]) {
			return v.Idx, true
		}
	}
	return 0, false
}

func (this *HashInfo) GetMap() HashMap {
	m := HashMap{}
	for _, v := range this.Blocks {
		m[v.H1] = append(m[v.H1], v)
	}
	return m
}

func (this *HashInfo) IsEmpty() bool {
	l := len(this.Blocks)
	if l == 0 {
		return true
	}
	if l == 1 && this.Blocks[0].Len < this.BlockSize {
		return true
	}
	return false
}

type FileMerger struct {
	WFile *os.File
	RFile *os.File
	Size  int64
	Path  string
	Hash  hash.Hash
	Info  *HashInfo
}

func (this *FileMerger) doOpen(hi *AnalyseInfo) error {
	return this.open(hi.Off)
}

func (this *FileMerger) doClose(hi *AnalyseInfo) error {
	mv := this.Hash.Sum(nil)
	if !bytes.Equal(mv[:], hi.Hash) {
		return errors.New("hash error")
	}
	if err := this.attach(); err != nil {
		return err
	}
	this.Close()
	return nil
}

func (this *FileMerger) doData(hi *AnalyseInfo) error {
	if num, err := this.Hash.Write(hi.Data); err != nil {
		return err
	} else if num != len(hi.Data) {
		return fmt.Errorf("write hash data num error: index = %d", hi.Index)
	}
	if num, err := this.WFile.Write(hi.Data); err != nil {
		return err
	} else if num != len(hi.Data) {
		return fmt.Errorf("write file data num error: index = %d", hi.Index)
	}
	return nil
}

func (this *FileMerger) ReadBlock(b *HashBlock) ([]byte, error) {
	if this.RFile == nil {
		return nil, errors.New("not found file : " + this.Path)
	}
	data := make([]byte, b.Len)
	if _, err := this.RFile.Seek(b.Off, io.SeekStart); err != nil {
		return nil, err
	}
	if num, err := this.RFile.Read(data); err != nil {
		return nil, err
	} else if num != len(data) {
		return nil, fmt.Errorf("read file data num error: index = %d", b.Idx)
	}
	return data, nil
}

func (this *FileMerger) doIndex(hi *AnalyseInfo) error {
	if hi.Index < 0 || hi.Index >= len(this.Info.Blocks) {
		return errors.New("block index out bound")
	}
	b := this.Info.Blocks[hi.Index]
	data, err := this.ReadBlock(&b)
	if err != nil {
		return err
	}
	if num, err := this.Hash.Write(data); err != nil {
		return err
	} else if num != len(data) {
		return fmt.Errorf("write hash data num error: index = %d", hi.Index)
	}
	if num, err := this.WFile.Write(data); err != nil {
		return err
	} else if num != len(data) {
		return fmt.Errorf("write file data num error: index = %d", hi.Index)
	}
	return nil
}

func (this *FileMerger) Write(hi *AnalyseInfo) error {
	var err error = nil
	if hi.IsOpen() {
		err = this.doOpen(hi)
	}
	if err != nil {
		return err
	}
	if hi.IsData() {
		err = this.doData(hi)
	}
	if err != nil {
		return err
	}
	if hi.IsIndex() {
		err = this.doIndex(hi)
	}
	if err != nil {
		return err
	}
	if hi.IsClose() {
		err = this.doClose(hi)
	}
	return err
}

func (this *FileMerger) open(siz int64) error {
	this.Size = siz
	tmp := this.Path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_APPEND|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	this.WFile = file
	file, err = os.OpenFile(this.Path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		this.RFile = nil
	} else {
		this.RFile = file
	}
	return nil
}

func (this *FileMerger) attach() error {
	if this.RFile != nil {
		this.RFile.Close()
		this.RFile = nil
		if err := os.Remove(this.Path); err != nil {
			return err
		}
	}
	if this.WFile != nil {
		this.WFile.Close()
		this.WFile = nil
	}
	tmp := this.Path + ".tmp"
	return os.Rename(tmp, this.Path)
}

func (this *FileMerger) Close() {
	if this.RFile != nil {
		this.RFile.Close()
		this.RFile = nil
	}
	if this.WFile != nil {
		this.WFile.Close()
		this.WFile = nil
	}
}

func NewFileMerger(file string, hi *HashInfo) *FileMerger {
	return &FileMerger{
		Path: file,
		Hash: md5.New(),
		Info: hi,
	}
}

type FileReader struct {
	File *os.File
	Size int
	Off  int64
	Buf  *bytes.Buffer
	Hash hash.Hash
}

func (this *FileReader) Truncate(size int) error {
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	num, err := this.Buf.Read(buf)
	if err != nil {
		return err
	}
	this.Off += int64(num)
	return nil
}

func (this *FileReader) Read(offset int64) ([]byte, error) {
	one := []byte{0}
	ds := this.Buf.Bytes()
	idx := int(offset - this.Off)
	if idx >= 0 && idx < len(ds) {
		one[0] = ds[idx]
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
	ds = this.Buf.Bytes()
	if len(ds) > 0 {
		one[0] = ds[idx]
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
	return &HashInfo{
		Blocks:    this.Blocks,
		MD5:       this.MD5,
		BlockSize: this.BlockSize,
	}
}

const (
	AnalyseTypeOpen  = 1 << 0 //off=filesize
	AnalyseTypeData  = 1 << 1 //data
	AnalyseTypeIndex = 1 << 2 //index
	AnalyseTypeClose = 1 << 3 //hash
)

type AnalyseInfo struct {
	HashFile *FileHashInfo //file info
	Index    int           // >= 0 map to blocks
	Off      int64         //
	Data     []byte        // len > 0 has new data
	Type     int           // AnalyseType*
	Hash     []byte        //
}

func (this *AnalyseInfo) IsOpen() bool {
	return this.Type&AnalyseTypeOpen != 0
}
func (this *AnalyseInfo) IsData() bool {
	return this.Type&AnalyseTypeData != 0
}
func (this *AnalyseInfo) IsClose() bool {
	return this.Type&AnalyseTypeClose != 0
}
func (this *AnalyseInfo) IsIndex() bool {
	return this.Type&AnalyseTypeIndex != 0
}

func (this *FileHashInfo) CheckPass(mp HashMap, buf []byte, hh hash.Hash32) int {
	if len(buf) < this.BlockSize {
		return -4
	}
	h12 := hh.Sum32()
	o, b := mp.PassH1(h12)
	if !b {
		return -1
	}
	o, b = mp.PassH2(h12)
	if !b {
		return -2
	}
	h3 := md5.Sum(buf)
	o, b = mp.PassH3(h12, h3)
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
	info.Type = AnalyseTypeOpen
	info.Off = this.FileSize
	if err := fn(info); err != nil {
		return err
	}
	mp := this.Info.GetMap()
	rbuf := bytes.NewBuffer(nil)
	wbuf := bytes.NewBuffer(nil)
	adler := adler32.New()
	file := NewFileReader(this.File, this.BlockSize)
	for foff := int64(0); foff < this.FileSize; foff++ {
		if this.Info.IsEmpty() {
			buf := make([]byte, this.BlockSize)
			num, err := this.File.Read(buf)
			if err != nil {
				return err
			}
			if _, err := file.Hash.Write(buf[:num]); err != nil {
				return err
			}
			info := &AnalyseInfo{HashFile: this}
			info.Type = AnalyseTypeData
			info.Data = buf[:num]
			foff += int64(num)
			if err := fn(info); err != nil {
				return err
			}
			continue
		}
		if one, err := file.Read(foff); err != nil {
			return err
		} else if _, err := rbuf.Write(one); err != nil {
			return err
		} else if _, err := adler.Write(one); err != nil {
			return err
		} else if idx := this.CheckPass(mp, rbuf.Bytes(), adler); idx >= 0 {
			adler.Reset()
			info := &AnalyseInfo{HashFile: this}
			info.Type = AnalyseTypeIndex
			info.Index = idx
			if wbuf.Len() > 0 {
				info.Data = wbuf.Bytes()
				info.Type |= AnalyseTypeData
			}
			info.Off = foff - int64(wbuf.Len()+rbuf.Len()-1)
			if err := fn(info); err != nil {
				return err
			}
			if err := file.Truncate(wbuf.Len() + rbuf.Len()); err != nil {
				return err
			}
			wbuf.Reset()
			rbuf.Reset()
			continue
		}
		if rbuf.Len() >= this.BlockSize {
			one := []byte{0}
			adler.Reset()
			foff -= int64(rbuf.Len() - 1)
			if _, err := rbuf.Read(one); err != nil {
				return err
			}
			if _, err := wbuf.Write(one); err != nil {
				return err
			}
			rbuf.Reset()
		}
		if wbuf.Len() >= this.BlockSize {
			info := &AnalyseInfo{HashFile: this}
			info.Type = AnalyseTypeData
			info.Data = wbuf.Bytes()
			info.Off = foff - int64(wbuf.Len()-1)
			if err := fn(info); err != nil {
				return err
			}
			if err := file.Truncate(wbuf.Len()); err != nil {
				return err
			}
			wbuf.Reset()
		}
	}
	if _, err := wbuf.Write(rbuf.Bytes()); err != nil {
		return err
	}
	info = &AnalyseInfo{HashFile: this}
	info.Type = AnalyseTypeClose
	info.Hash = file.Hash.Sum(nil)
	if wbuf.Len() > 0 {
		info.Type |= AnalyseTypeData
		info.Data = wbuf.Bytes()
		info.Off = this.FileSize - int64(wbuf.Len())
	}
	if err := file.Truncate(wbuf.Len()); err != nil {
		return err
	}
	return fn(info)
}

func (this *FileHashInfo) Open() error {
	if this.BlockSize == 0 {
		return errors.New("block size error")
	}
	fs, err := os.Stat(this.Path)
	if err != nil {
		return nil
	}
	this.FileSize = fs.Size()
	if this.FileSize == 0 {
		return nil
	}
	if this.FileSize%int64(this.BlockSize) == 0 {
		this.Count = (this.FileSize / int64(this.BlockSize))
	} else {
		this.Count = (this.FileSize / int64(this.BlockSize)) + 1
	}
	fd, err := os.OpenFile(this.Path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("open file error: %v", err)
	}
	this.File = fd
	return nil
}

func (this *FileHashInfo) FillHashInfo() error {
	if this.FileSize == 0 {
		return nil
	}
	if this.File == nil {
		return errors.New("file not open")
	}
	fmd5 := md5.New()
	buf := make([]byte, this.BlockSize)
	pos := int64(0)
	for i := int64(0); i < this.Count; i++ {
		hb := HashBlock{}
		if _, err := this.File.Seek(pos, io.SeekStart); err != nil {
			return fmt.Errorf("seek file error: %v", err)
		}
		rsiz, err := this.File.Read(buf)
		if err != nil {
			return fmt.Errorf("read file error: %v", err)
		}
		dat := buf[:rsiz]
		fmd5.Write(dat)
		acs := adler32.Checksum(dat)
		hb.Idx = int(i)
		hb.Len = rsiz
		hb.Off = pos
		hb.H1 = uint16((acs & 0xFFFF))
		hb.H2 = uint16(((acs >> 16) & 0xFFFF))
		hb.H3 = md5.Sum(dat)
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

func NewFileHashInfo(file string, arg ...interface{}) *FileHashInfo {
	ret := &FileHashInfo{
		Blocks:    []HashBlock{},
		BlockSize: DefaultBlockSize,
		Path:      file,
	}
	var iv interface{} = nil
	if len(arg) == 1 {
		iv = arg[0]
	}
	switch iv.(type) {
	case int:
		{
			ret.BlockSize = iv.(int)
		}
	case *HashInfo:
		{
			ret.Info = iv.(*HashInfo)
			ret.BlockSize = ret.Info.BlockSize
		}
	default:
		return ret
	}
	return ret
}
