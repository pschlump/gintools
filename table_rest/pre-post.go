package table_rest

// This file is BSD 3 Clause licensed.

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

var PrePostTab = map[string]PrePostFx{
	"conv_geolocation": ConvGeolocation,
	"flush_priv_cache": PPFlushPrivCache,
}

// type PrePostFx func(c *gin.Context, pp PrePostFlag, cfgData, inData string) (outData string, status StatusType, err error)
// OLD: type PrePostFx func(c *gin.Context, inData string) (outData string, status StatusType, err error)

func AddToPrePostTab(name string, fx PrePostFx) {
	PrePostTab[name] = fx
}

func PPFlushPrivCache(c *gin.Context, pp PrePostFlag, cfgData, inData string) (outData string, status StatusType, err error) {
	if pp == PostFlag {
		// ORIG:
		// if req.Method != "GET" {
		// 	FlushPrivCache()
		// }
	}
	outData = inData
	status = OkContinueSaveOutData
	return
}

// ConvGeolocation takes a single geolocation string value in the format a,b,c,d and converts it into a set of 8 values.
func ConvGeolocation(c *gin.Context, pp PrePostFlag, cfgData, inData string) (outData string, status StatusType, err error) {
	outData = inData
	status = OkContinueSaveOutData
	if pp == PreFlag {
		if cfgData == "" {
			cfgData = "geolocation"
		}
		found, val := GetVar(cfgData, c) // qr_id is the base 36 data.
		if found {
			s1 := strings.Split(val, ",") // Assumes box format is 11,22,33,44 v.s. a more complex format.
			if len(s1) != 4 {
				status = ErrorFail
				fmt.Fprintf(logFilePtr, "Invalid qr_id input [%s], should have 4 values\n", val)
				return
			}
			// xyzzy - should change range of lat/lon -180,...,180 for each value.
			SetValue(c, fmt.Sprintf("%s_lat_ne", cfgData), s1[0])
			SetValue(c, fmt.Sprintf("%s_lon_ne", cfgData), s1[1])
			SetValue(c, fmt.Sprintf("%s_lat_sw", cfgData), s1[2])
			SetValue(c, fmt.Sprintf("%s_lon_sw", cfgData), s1[3])
			// xyzzy - must actually obscure the location w/ random value.
			SetValue(c, fmt.Sprintf("%s_obs_lat_ne", cfgData), s1[0])
			SetValue(c, fmt.Sprintf("%s_obs_lon_ne", cfgData), s1[1])
			SetValue(c, fmt.Sprintf("%s_obs_lat_sw", cfgData), s1[2])
			SetValue(c, fmt.Sprintf("%s_obs_lon_sw", cfgData), s1[3])
		} else {
			status = ErrorFail
			fmt.Fprintf(logFilePtr, "Missing %s input\n", cfgData)
			return
		}
	}
	return
}
