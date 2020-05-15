package machofile

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	//"encoding/binary"
	"fmt"
	//"io"
	//"log"
	"math"
	"os"
	//"strings"
	//"unicode/utf16"
	//"unicode/utf8"
)

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// The following types are defined at
// https://golang.org/pkg/debug/macho/
/*
type Segment struct {
    LoadBytes
    SegmentHeader

    // Embed ReaderAt for ReadAt method.
    // Do not embed SectionReader directly
    // to avoid having Read and Seek.
    // If a client wants Read and Seek it must use
    // Open() to avoid fighting over the seek offset
    // with other clients.
    io.ReaderAt
    // contains filtered or unexported fields
}
/*

/*
type Segment64 struct {
	Cmd     LoadCmd
	Len     uint32
	Name    [16]byte
	Addr    uint64
	Memsz   uint64
	Offset  uint64
	Filesz  uint64
	Maxprot uint32
	Prot    uint32
	Nsect   uint32
	Flag    uint32
}
*/

/*
type Section struct {
    SectionHeader
    Relocs []Reloc // Go 1.10

    // Embed ReaderAt for ReadAt method.
    // Do not embed SectionReader directly
    // to avoid having Read and Seek.
    // If a client wants Read and Seek it must use
    // Open() to avoid fighting over the seek offset
    // with other clients.
    io.ReaderAt
    // contains filtered or unexported fields
}
*/

/*
type Section64 struct {
    Name     [16]byte
    Seg      [16]byte
    Addr     uint64
    Size     uint64
    Offset   uint32
    Align    uint32
    Reloff   uint32
    Nreloc   uint32
    Flags    uint32
    Reserve1 uint32
    Reserve2 uint32
    Reserve3 uint32
}
*/

/* Using native debug/macho for now - will implement
   a new type if we need more information
type MachOFileHeader struct {
	Magic  uint32
	Cpu    macho.Cpu
	SubCpu uint32
	Type   macho.Type
	Ncmd   uint32
	Cmdsz  uint32
	Flags  uint32
}
*/

type MachOFile struct {
	MFile *macho.File
	Path  string
	//Name             string //import name, apiset or on disk
	//RealName         string //on disk short name
	Sha256 string
	//Sections       []*macho.File.Sections
	//sectionHeaders []*macho.SectionHeader
	Segments       []*macho.Segment64
	segmentHeaders []*macho.SegmentHeader
	Size           int64
	//MachOFileHeader *MachOFileHeader
	RawHeaders   []byte
	oldImageBase uint64
	ImageSize    int64
}

func entropy(bs []byte) float64 {
	histo := make([]int, 256)
	for _, b := range bs {
		histo[int(b)]++
	}

	size := len(bs)
	var ret float64 = 0.0

	for _, count := range histo {
		if count == 0 {
			continue
		}

		p := float64(count) / float64(size)
		ret += p * math.Log2(p)
	}

	return -ret
}

func (mo *MachOFile) String() string {
	return fmt.Sprintf("{ Path: %s }", mo.Path)
}

// getMagic is a local function for getting the magic
// value of an input file
func getMagic(path string) (uint32, error) {

	mfile, err := macho.Open(path)

	if err != nil {
		return 0, fmt.Errorf("Error opening file - %v ", err)
	}

	// create MachoFile struct
	machofile := &MachOFile{Path: path}
	machofile.MFile = mfile

	// Check magic
	magic := machofile.MFile.Magic

	if err != nil {
		return 0, fmt.Errorf("Error: invalid Mach-O magic value - %v ", err)
	}
	return magic, err
}

// IsMachO tests the input file to check if 64-bit Mach-O
func IsMachO(path string) bool {
	magic, err := getMagic(path)

	if err != nil {
		return false
	}

	// Will need to change this if we decide to support other formats
	if magic != macho.Magic64 {
		return false
	}

	return true
}

// LoadMachOFile will parse a file from disk, given a path. The output will be a
// MachOFile object or an error
func LoadMachOFile(path string) (*MachOFile, error) {

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Error opening %s file: %v", path, err)
	}

	// get size of file, then seek back to start to reset the cursor
	size, err := file.Seek(0, 2)
	if err != nil {
		return nil, fmt.Errorf("Error getting size of file %s: %v", path, err)
	}
	file.Seek(0, 0)

	// read the file into data buffer
	data := make([]byte, size)
	if _, err = file.Read(data); err != nil {
		return nil, fmt.Errorf("Error copying file %s into buffer: %v", path, err)
	}

	// open file as debug/macho File to populate rest of struct
	mfile, err := macho.Open(path)

	if err != nil {
		return nil, fmt.Errorf("Error: %v - input file must be 64-bit Mach-O file", err)
	}

	// create MachoFile struct
	machofile := &MachOFile{Path: path}

	machofile.MFile = mfile

	// Check magic - must be Mach-O 64-bit
	magic, err := getMagic(path)
	if magic != macho.Magic64 {
		return nil, fmt.Errorf("Error: %v - file must be 64-bit Mach-O file", err)
	}
	/*
		if machofile.MFile.Magic != macho.Magic64 {
			return nil, fmt.Errorf("Error: %v - file must be 64-bit Mach-O file", err)
		}
	*/

	// need to loop through these maybe?
	fmt.Printf("fh Magic: %#x\n", mfile.FileHeader.Magic)

	for _, l := range mfile.Loads {
		switch l := l.(type) {
		case *macho.Segment:
			fmt.Printf("Segment: %s\n", l.SegmentHeader.Name)
		}
	}

	for _, load := range mfile.Loads {
		fmt.Println(load)
	}

	seg := mfile.Segment("__DATA")
	if seg != nil {
		fmt.Println(seg.Addr, seg.Addr+seg.Memsz)
		// prints mem addrs of sections, but need names - map?
		fmt.Println(mfile.Sections)
		//fmt.Println(seg)
	}

	if err := analyzeMachOFile(data, machofile); err != nil {
		return nil, err
	}
	return machofile, err

}

// LoadMachOBytes will take a Mach-O file in the form of an in memory byte array and parse it
func LoadMachOBytes(data []byte, name string) (*MachOFile, error) {
	machofile := &MachOFile{Path: name}
	machofile.Size = int64(len(data))
	if err := analyzeMachOFile(data, machofile); err != nil {
		return nil, err
	}
	return machofile, nil
}

// Sha256Sum will calcuate the sha256 of the supplied byte slice
func Sha256Sum(b []byte) (hexsum string) {
	sum := sha256.Sum256(b)
	hexsum = fmt.Sprintf("%x", sum)
	return
}

// analyzeMachOFile is the core parser for Mach-O files - most
// of this is handled by debug/macho but we may need to add
// additional functionality in the future
func analyzeMachOFile(data []byte, mfile *MachOFile) error {
	//var err error

	mfile.Sha256 = Sha256Sum(data)

	// We don't need this right now afaik
	// create reader at offset 0
	r := bytes.NewReader(data)
	fmt.Printf("r len: %d \n", r.Len())

	return nil
}

func readString(b []byte) string {
	for i := 0; ; i++ {
		if b[i] == 0x0 {
			return string(b[0:i])
		}
	}
}
