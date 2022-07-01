# jsonCheck - validate information about a JSON file

This is used to check the presence of fields in a json hash or to
check that a field is not there.   

## Options

| Option     | Description                                |
|------------|--------------------------------------------|
| `-i <fn>`  | Input json file                            |
| `-r`       | reverse logic -check that it is not there- |
| `-z`       | Check for non-zero length of string        |
| `-u`       | Check for valid UUID                       |
| `-n`       | Check for valid Int                        |

## Example of Use (in bash)

```
$ ~/bin/jsonCheck -i register.out "status" "url_for_2fa_qr" "otp"
$ ~/bin/jsonCheck -r -i register.out "user_id" "auth_token"
```
