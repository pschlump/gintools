
# Output Formats

Request for data from a table by default are returned in JSON.
The data is wrapped in a json map.

If the data has 2 columns, id and name and 3 rows.

```
[
	{ "id":1, "name":"bob"},
	{ "id":2, "name":"jane"},
	{ "id":3, "name":"sally"}
]
```

Then the default wrapped JSON format is.

```
{"status":"success","data":[
		{ "id":1, "name":"bob"},
		{ "id":2, "name":"jane"},
		{ "id":3, "name":"sally"}
	]
}
```

You can also specify that the data be returned in a number of different
output formats.  This is done by specifying, `__rdfmt__`.


## `array`

```
__rdfmt__=array
```

results in

```
[
	{ "id":1, "name":"bob"},
	{ "id":2, "name":"jane"},
	{ "id":3, "name":"sally"}
]
```

This will result in an array of data, just the `[...]` will be returned.
For various security recons this is not a safe format to return and is
discouraged.



crud.go:685:
				case "AsJS":
					ContentType = "text/javascript; charset=utf-8"
					Name_found, Name := GetVar("__rdata_name__", c)
					if !Name_found || Name == "" {
						Name = "Name"
					}
					rawData = fmt.Sprintf(`var %s = {"status":"success","data":%s};`, Name, dbgo.SVarI(data))
				case "AsJSWindow":
					ContentType = "text/javascript; charset=utf-8"
					Name_found, Name := GetVar("__rdata_name__", c)
					if !Name_found || Name == "" {
						Name = "Name"
					}
					rawData = fmt.Sprintf(`window.%s = {"status":"success","data":%s};`+"\n\n", Name, dbgo.SVarI(data))
				case "AsJSWindowData":
					ContentType = "text/javascript; charset=utf-8"
					Name_found, Name := GetVar("__rdata_name__", c)
					if !Name_found || Name == "" {
						Name = "Name"
					}
					rawData = fmt.Sprintf(`window.%s = %s;`+"\n\n", Name, dbgo.SVarI(data))
				case "AsTEXT":
					ContentType = "text/plain; charset=utf-8"
				case "PreFix", "PreFix2":
				default:
					err = fmt.Errorf("Invalid __rdfmt__ value of %s, shold be '', array, AsJS, AsTEXT", aa)
					rawData = fmt.Sprintf(`{"status":"error","msg":%q}`, err)
					break


crud.go:730:
				case "PreFix":
					rawData = "while(1);" + rawData
				case "PreFix2":
					rawData = "for(;;);" + rawData
				case "AsTEXT":
					ContentType = "text/plain; charset=utf-8"
