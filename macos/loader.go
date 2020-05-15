package macos

//import "encoding/binary"
//import "bytes"
//import "debug/macho"

/*
import "fmt"
import "os"
import "strings"
import "github.com/carbonblack/binee/util"
import uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
*/

/* Might need to add some consts here but not atm
const (
	F_GRANULARITY  = 0x8
	F_PROT_32      = 0x4
	F_LONG         = 0x2
	PRESENT        = 0x80
	PRIV_3         = 0x60
	PRIV_2         = 0x40
	PRIV_1         = 0x20
	PRIV_0         = 0x0
	CODE           = 0x10
	DATA           = 0x10
	TSS            = 0x0
	GATE           = 0x00
	EXEC           = 0x8
	DATA_WRITEABLE = 0x2
	CODE_READABLE  = 0x2
	DIR_CON_BIT    = 0x4
	S_GDT          = 0x0
	S_PRIV_3       = 0x3
	S_PRIV_2       = 0x2
	S_PRIV_1       = 0x1
	S_PRIV_0       = 0x0
)
*/

type MemRegions struct {
	ProcInfoSize    uint64
	TibSize         uint64
	GdtSize         uint64
	StackSize       uint64
	HeapSize        uint64
	LibSize         uint64
	ImageSize       uint64
	ProcInfoAddress uint64
	TibAddress      uint64
	GdtAddress      uint64
	StackAddress    uint64
	HeapAddress     uint64
	LibAddress      uint64
	ImageAddress    uint64
}
