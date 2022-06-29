package table_rest

// This file is BSD 3 Clause licensed.

import (
	"github.com/pschlump/gintools/data"
)

var gCfg *data.GlobalConfigData

func SetupCRUD(gcfg *data.GlobalConfigData) {
	gCfg = gcfg
}
