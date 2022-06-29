package jwt_auth

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/json"
	"github.com/pschlump/uuid"
	"golang.org/x/exp/constraints"
)

// SetJsonHdr will set a content-type header to "application/json; charset=utf-8"
func SetJsonHdr(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")

}

// EmptyDflt if s is empty, then return d.  Creates a default value for parametrs
func EmptyDflt(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ReadJson read in a JSON file into a go data structure.
func ReadJson(fn string, x interface{}) (err error) {
	var buf []byte
	buf, err = ioutil.ReadFile(fn)
	if err != nil {
		return
	}
	err = json.Unmarshal(buf, x)
	return
}

// ConnectToDb creates a global that is used to connect to the PG database.
// You have to have "DATABASE_URL" setup as an environment variable first. (See setupx.sh)

func ConnectToDb() {
	ctx = context.Background()
	constr := os.Getenv("DATABASE_URL")
	var err error
	// func Connect(ctx context.Context, connString string) (*Pool, error)
	conn, err = pgxpool.Connect(ctx, constr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v connetion string [%s]\n", err, constr)
		os.Exit(1)
	}
}

// DisConnectToDb() closes connection to databse.
func DisConnectToDb() {
	conn.Close()
}

// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}

// SVar return the JSON encoded version of the data.
func SVar(v interface{}) string {
	s, err := json.Marshal(v)
	// s, err := json.MarshalIndent ( v, "", "\t" )
	if err != nil {
		return fmt.Sprintf("Error:%s", err)
	} else {
		return string(s)
	}
}

// StatusSuccess prepends to a JSON return value with a status:success.
// This will also set the "Content-Type" to "application/json; charset=utf-8".
func StatusSuccess(s string, c *gin.Context) string {
	SetJsonHdr(c)
	return `{"status":"success","data":` + s + "}\n"
}

// SVarI return the JSON encoded version of the data with tab indentation.
func SVarI(v interface{}) string {
	// s, err := json.Marshal ( v )
	s, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return fmt.Sprintf("Error:%s", err)
	} else {
		return string(s)
	}
}

// RmExt removes the extenstion from a file name if it exits.
// if filename is "bc.js", then "bc" will be retuend.
func RmExt(filename string) string {
	var extension = filepath.Ext(filename)
	if extension != "" {
		var name = filename[0 : len(filename)-len(extension)]
		return name
	}
	return filename
}

// GetMapKeys Get all the keys from any typed map.  (generic)
func GetMapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// SortSlice will Sort a slice of any type.  (generic)
func SortSlice[T constraints.Ordered](s []T) {
	sort.Slice(s, func(i, j int) bool {
		return s[i] < s[j]
	})
}

// SortMapKeys will sort the keys on a map and return a slice of sorted keys (generic)
func SortedMapKeys[K constraints.Ordered, V any](m map[K]V) []K {
	keys := GetMapKeys(m)
	SortSlice(keys)
	return keys
}

/* vim: set noai ts=4 sw=4: */
