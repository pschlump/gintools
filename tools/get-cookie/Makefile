
all:
	check-json-syntax --ignore-tab-warning ./cfg.json
	go build 

linux:
	GOOS=linux GOARCH=amd64 go build -o get-cookie_linux

deploy: linux
	scp get-cookie_linux philip@client.com:/home/philip/tmp/get-cookie

run:


# (base) philip@victoria gin1 % go build
# # golang.org/x/sys/unix
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/syscall_darwin.1_13.go:25:3: //go:linkname must refer to declared function or variable
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/zsyscall_darwin_amd64.1_13.go:27:3: //go:linkname must refer to declared function or variable
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/zsyscall_darwin_amd64.1_13.go:40:3: //go:linkname must refer to declared function or variable
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/zsyscall_darwin_amd64.go:28:3: //go:linkname must refer to declared function or variable
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/zsyscall_darwin_amd64.go:43:3: //go:linkname must refer to declared function or variable
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/zsyscall_darwin_amd64.go:59:3: //go:linkname must refer to declared function or variable
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/zsyscall_darwin_amd64.go:75:3: //go:linkname must refer to declared function or variable
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/zsyscall_darwin_amd64.go:90:3: //go:linkname must refer to declared function or variable
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/zsyscall_darwin_amd64.go:105:3: //go:linkname must refer to declared function or variable
# ../../../../../pkg/mod/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42/unix/zsyscall_darwin_amd64.go:121:3: //go:linkname must
fix_error:
	 go get -u golang.org/x/sys


# Produciton Build Target
build: rebuild all

rebuild:
	./generate-git-commit.sh

install:
	rm -f ~/bin/get-cookie
	( cd ~/bin ; ln -s ../go/src/github.com/pschlump/gintools/tools/get-cookie/get-cookie . )

test: test001 test002

# Set Password
test001:	
	go build
	./get-cookie --set-pass --email "bob40@client.com" --pass "abcdefghij" --output-path "./y"

test002:
	go build
	./get-cookie --set-pass --email "bob40@client.com" --pass "abcdefghij" --output-path "./y" --validation-server "http://localhost:9080/api/v1/auth/login-status"


