
# Add Templates to Handle

# add the function to the pre-post processing

This will be a post-process system.

```
	ymux.AddToPrePostTab("template_display_url", TemplateDisplayUrl)
```

# The function

```
// TemplateDisplayUrl takes each value and allows application of a template to that value.
// OLD: func TemplateDisplayUrl(www http.ResponseWriter, req *http.Request, inData string) (outData string, status ymux.StatusType, err error) {
func TemplateDisplayUrl(www http.ResponseWriter, req *http.Request, pp ymux.PrePostFlag, cfgData, inData string) (outData string, status ymux.StatusType, err error) {
	status = ymux.OkContinueSaveOutData
	outData = inData
	var mdata TemplateDisplayUrlData
	mdata.Data = make([]map[string]interface{}, 0, 10)
	err = json.Unmarshal([]byte(inData), &mdata)
	if err != nil {
		fmt.Fprintf(logFilePtr, "Error with data ->%s<- failed to parse: %s\n", inData, err)
		status = ymux.ErrorFail
		return
	}

	if mdata.Status != "success" {
		return
	}
	if len(mdata.Data) == 0 {
		return
	}

	to, e0 := url.Parse(gCfg.QRGeneration.QrBaseServerUrl)
	if DbOn["edit-urls-on-output"] {
		fmt.Printf("e0 %s to=%s\n", e0, dbgo.SVarI(to))
	}

	for ii, vv := range mdata.Data {
		dui, ok0 := vv["display_url"]
		if ok0 && dui != nil {
			duis, ok1 := dui.(string)
			if ok1 {
				uu, err := url.Parse(duis)
				if DbOn["edit-urls-on-output"] {
					fmt.Fprintf(os.Stderr, "Fixed at %d Orig (%s) err %s uu= %s\n", ii, duis, err, dbgo.SVarI(uu))
				}
				uu.Host = to.Host
				uu.Scheme = to.Scheme
				duis = fmt.Sprintf("%s", uu)
				if DbOn["edit-urls-on-output"] {
					fmt.Fprintf(os.Stderr, "\tReplaed with: %s\n", duis)
				}
				vv["display_url"] = duis
			}
		}
	}
	outData = dbgo.SVarI(mdata)

	return
}
```
