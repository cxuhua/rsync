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
	"log"
	"os"
	"sort"
)

const (
	DefaultBlockSize = 1024
)

type HashBlock struct {
	Idx uint32
	Off uint32
	H1  uint16         //adler32 low  = (hash & 0xFFFF)
	H2  uint16         //adler32 high = ((hash > 16) & 0xFFFF)
	H3  [md5.Size]byte //md5 sum
}

func (this HashBlock) Size() int {
	return md5.Size + 4
}

func tobyte16(v uint16) []byte {
	ret := []byte{0, 0}
	ret[0] = byte(v & 0xFF)
	ret[1] = byte(v >> 8 & 0xFF)
	return ret
}

func touint16(b []byte) uint16 {
	if len(b) != 2 {
		panic(errors.New("b error"))
	}
	return uint16(b[0]) | uint16(b[1])<<8
}

func tobyte32(v uint32) []byte {
	ret := []byte{0, 0, 0, 0}
	ret[0] = byte(v & 0xFF)
	ret[1] = byte(v >> 8 & 0xFF)
	ret[2] = byte(v >> 16 & 0xFF)
	ret[3] = byte(v >> 24 & 0xFF)
	return ret
}

func touint32(b []byte) uint32 {
	if len(b) != 4 {
		panic(errors.New("b error"))
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func (this *HashBlock) Read(idx uint32, buf *bytes.Buffer) error {
	this.Idx = idx
	b1 := []byte{0, 0}
	if _, err := buf.Read(b1); err != nil {
		return err
	}
	this.H1 = touint16(b1)
	if _, err := buf.Read(b1); err != nil {
		return err
	}
	this.H2 = touint16(b1)
	b2 := []byte{0, 0, 0, 0}
	if _, err := buf.Read(b2); err != nil {
		return err
	}
	this.Off = touint32(b2)
	if _, err := buf.Read(this.H3[:]); err != nil {
		return err
	}
	return nil
}

func (this HashBlock) Write(buf *bytes.Buffer) error {
	if _, err := buf.Write(tobyte16(this.H1)); err != nil {
		return err
	}
	if _, err := buf.Write(tobyte16(this.H2)); err != nil {
		return err
	}
	if _, err := buf.Write(tobyte32(this.Off)); err != nil {
		return err
	}
	if _, err := buf.Write(this.H3[:]); err != nil {
		return err
	}
	return nil
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
	BlockSize uint16      //block size
}

func (this *HashInfo) Read(buf *bytes.Buffer) error {
	if buf.Len() == 0 {
		return nil
	}
	if len(this.MD5) != md5.Size {
		this.MD5 = make([]byte, md5.Size)
	}
	if _, err := buf.Read(this.MD5); err != nil {
		return err
	}
	bb := []byte{0, 0}
	if _, err := buf.Read(bb); err != nil {
		return err
	}
	this.BlockSize = touint16(bb)
	idx := uint32(0)
	for buf.Len() > 0 {
		b := &HashBlock{}
		if err := b.Read(idx, buf); err != nil {
			return err
		}
		this.Blocks = append(this.Blocks, *b)
		idx++
	}
	return nil
}

func (this *HashInfo) Write(buf *bytes.Buffer) error {
	if this.MD5 == nil {
		return nil
	}
	if _, err := buf.Write(this.MD5); err != nil {
		return err
	}
	if err := buf.WriteByte(byte(this.BlockSize & 0xFF)); err != nil {
		return err
	}
	if err := buf.WriteByte(byte(this.BlockSize >> 8 & 0xFF)); err != nil {
		return err
	}
	for _, v := range this.Blocks {
		if err := v.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func NewHashInfo() *HashInfo {
	return &HashInfo{
		Blocks:    []HashBlock{},
		MD5:       nil,
		BlockSize: 0,
	}
}

type HashMap map[uint16][]HashBlock

func (this HashMap) PassH1(h uint32) (uint32, bool) {
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

func (this HashMap) PassH2(h uint32) (uint32, bool) {
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

func (this HashMap) PassH3(h uint32, mv [md5.Size]byte) (uint32, bool) {
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
	return len(this.Blocks) == 0
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
		log.Println(hex.EncodeToString(mv[:]), hex.EncodeToString(hi.Hash))
		return errors.New("hash error")
	}
	if err := this.attach(); err != nil {
		return err
	}
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
	data := make([]byte, this.Info.BlockSize)
	if _, err := this.RFile.Seek(int64(b.Off)*int64(this.Info.BlockSize), io.SeekStart); err != nil {
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

//func LockFile(f *os.File) error {
//	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
//}
//
//func UnlockFile(f *os.File) error {
//	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
//}

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

func NewFileMerger(file string, hi *HashInfo) (*FileMerger, error) {
	f := &FileMerger{
		Path: file,
		Hash: md5.New(),
		Info: hi,
	}
	return f, nil
}

type FileReader struct {
	File *os.File
	Size uint16
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

func NewFileReader(f *os.File, siz uint16) *FileReader {
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
	Info      *HashInfo            //hash info from computer
	Path      string               //file path
	File      *os.File             //if file opened
	Blocks    map[string]HashBlock //block info
	Count     int64                //block count
	MD5       []byte               //file md5
	BlockSize uint16               //block size
	FileSize  int64                //file size
}

func (this *FileHashInfo) GetHashInfo() *HashInfo {
	hbs := []HashBlock{}
	for _, v := range this.Blocks {
		hbs = append(hbs, v)
	}
	sort.Slice(hbs, func(i, j int) bool {
		return hbs[i].Idx < hbs[j].Idx
	})
	return &HashInfo{
		Blocks:    hbs,
		MD5:       this.MD5,
		BlockSize: this.BlockSize,
	}
}

func HashInfoEqual(h1 *HashInfo, h2 *HashInfo) bool {
	if h1.MD5 == nil && h2.MD5 == nil {
		return true
	}
	if !bytes.Equal(h1.MD5, h2.MD5) {
		return false
	}
	if h1.BlockSize != h2.BlockSize {
		return false
	}
	if len(h1.Blocks) != len(h2.Blocks) {
		return false
	}
	for i := 0; i < len(h1.Blocks); i++ {
		if !HashBlockEqual(h1.Blocks[i], h2.Blocks[i]) {
			return false
		}
	}
	return true
}

const (
	AnalyseTypeOpen  = 1 << 0 //off=filesize
	AnalyseTypeData  = 1 << 1 //data
	AnalyseTypeIndex = 1 << 2 //index
	AnalyseTypeClose = 1 << 3 //hash
)

type AnalyseInfo struct {
	HashFile *FileHashInfo //file info
	Index    uint32        // >= 0 map to blocks
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

func (this *FileHashInfo) CheckPass(mp HashMap, buf []byte, hh hash.Hash32) (uint32, bool) {
	if len(buf) < int(this.BlockSize) {
		return 0, false
	}
	h12 := hh.Sum32()
	o, b := mp.PassH1(h12)
	if !b {
		return 0, false
	}
	o, b = mp.PassH2(h12)
	if !b {
		return 0, false
	}
	h3 := md5.Sum(buf)
	o, b = mp.PassH3(h12, h3)
	if !b {
		return 0, false
	}
	return this.Info.Blocks[o].Idx, true
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
			if _, err := this.File.Seek(foff, io.SeekStart); err != nil {
				return err
			}
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
			foff += int64(num - 1)
			if err := fn(info); err != nil {
				return fn(info)
			}
		} else if one, err := file.Read(foff); err != nil {
			return err
		} else if _, err := rbuf.Write(one); err != nil {
			return err
		} else if _, err := adler.Write(one); err != nil {
			return err
		} else if idx, ok := this.CheckPass(mp, rbuf.Bytes(), adler); ok {
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
		if rbuf.Len() >= int(this.BlockSize) {
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
		if wbuf.Len() >= int(this.BlockSize) {
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

func (this *FileHashInfo) FillHashInfo(cb func(info *HashBlock)) error {
	if this.FileSize == 0 {
		return nil
	}
	if this.File == nil {
		return errors.New("file not open")
	}
	fmd5 := md5.New()
	buf := make([]byte, this.BlockSize)
	idx := uint32(0)
	for i := int64(0); i < this.Count; i++ {
		off := i * int64(this.BlockSize)
		hb := HashBlock{}
		if _, err := this.File.Seek(off, io.SeekStart); err != nil {
			return fmt.Errorf("seek file error: %v", err)
		}
		rsiz, err := this.File.Read(buf)
		if err != nil {
			return fmt.Errorf("read file error: %v", err)
		}
		if rsiz != int(this.BlockSize) {
			break
		}
		dat := buf[:rsiz]
		if _, err := fmd5.Write(dat); err != nil {
			return fmt.Errorf("md5 write error: %v", err)
		}
		acs := adler32.Checksum(dat)
		hb.Idx = idx
		hb.Off = uint32(i)
		hb.H1 = uint16((acs & 0xFFFF))
		hb.H2 = uint16(((acs >> 16) & 0xFFFF))
		hb.H3 = md5.Sum(dat)
		ms := hex.EncodeToString(hb.H3[:])
		if _, ok := this.Blocks[ms]; ok {
			continue
		}
		if cb != nil {
			cb(&hb)
		}
		this.Blocks[ms] = hb
		idx++
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
		Blocks:    map[string]HashBlock{},
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
			ret.BlockSize = uint16(iv.(int))
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

//file file path
//args[0] blocksize
func GetFileHashInfo(file string, cb func(info *HashBlock), args ...interface{}) (*HashInfo, error) {
	df := NewFileHashInfo(file, args...)
	if err := df.Open(); err != nil {
		return nil, err
	}
	defer df.Close()
	if err := df.FillHashInfo(cb); err != nil {
		return nil, err
	}
	return df.GetHashInfo(), nil
}
