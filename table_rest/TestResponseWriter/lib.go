package TestResponseWriter

import (
	"bytes"
	"fmt"
	"net/http"
	"os"

	"github.com/pschlump/dbgo"
)

var DbFlag map[string]bool

func init() {
	DbFlag = make(map[string]bool)
}

func SetDbFlag(d map[string]bool) {
	DbFlag = d
}

// --
/*
func main() {
	var buffer bytes.Buffer

	for i := 0; i < 1000; i++ {
		buffer.WriteString("a")
	}

	fmt.Println(buffer.String())
}
*/

type CliResponseWriter struct {
	status int         // HTTP Status, 200, 206, 404 etc
	hdr    http.Header // header
	buffer bytes.Buffer
	where  []string // where writen from	// may need to go multi-deep to get answers -> [][]string
	out    *os.File
	done   bool
}

func NewTestResonseWriter() *CliResponseWriter {
	return &CliResponseWriter{
		// body:   make([]byte, 0, 1),
		out:    os.Stdout,
		hdr:    make(http.Header),
		status: 200, // assume happy
	}
}

func (cli *CliResponseWriter) ServeHTTP(www http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(www, "Yep - handled request")
}

//func (cli *CliResponseWriter) Header() (hdr http.Header) {
//	return
//}

/*
type Writer interface {
	Write(p []byte) (n int, err error)
}
*/
func (cli *CliResponseWriter) Write(p []byte) (n int, err error) {
	// cli.body = append(cli.body, p...)
	cli.buffer.Write(p)
	if DbFlag["Cli.Write"] {
		fmt.Printf("AT:%s at2:%s\n", dbgo.LF(), dbgo.LF(2))
	}
	n = len(p)
	cli.where = append(cli.where, dbgo.LF(2))
	return
}

func (cli *CliResponseWriter) Header() (hdr http.Header) {
	// type http.Header map[string][]string
	// http.Header is a named slices of strings - so each name can have more than one value.
	return cli.hdr
}

func (cli *CliResponseWriter) WriteHeader(status int) {
	if cli.done {
		fmt.Printf("Error: WriteHeader more than once! %s, called from %s\n", cli.where, dbgo.LF(2))
	}
	cli.where = append(cli.where, dbgo.LF(2))
	cli.status = status
	cli.done = true
	fmt.Fprintf(cli.out, "Status: %d\n", status)
	for name, val := range cli.hdr {
		for ii := range val {
			fmt.Fprintf(cli.out, "%s: %s\n", name, val[ii])
		}
	}
	fmt.Fprintf(cli.out, "\n")
}

// cli.Flush()
func (cli *CliResponseWriter) Flush() {
	// fmt.Fprintf(cli.out, "%s\n", cli.body)
	fmt.Fprintf(cli.out, "%s\n", cli.buffer.String())
}

func (cli *CliResponseWriter) DumpWhere() {
	fmt.Fprintf(cli.out, "\nWhere: %s\n", cli.where)
}

func (cli *CliResponseWriter) GetBody() string {
	// fmt.Fprintf(cli.out, "%s\n", cli.body)
	return fmt.Sprintf("%s", cli.buffer.String())
}

// delayedEOFReader never returns (n > 0, io.EOF), instead putting
