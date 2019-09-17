package rsync

type Transport interface {
	//io read
	Read(buf []byte) (int, error)
	//io write
	Write(buf []byte) (int, error)
	//process analuse info
	Analyse(info *AnalyseInfo) error
}
