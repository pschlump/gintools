
all:
	go build


load_data:
	./load-role -i example-privs.json

install:
	go build
	rm -f ~/bin/load-role
	( cd ~/bin ; ln -s ../go/src/github.com/pschlump/gintools/tools/load-role/load-role . )

linux:
	GOOS=linux GOARCH=amd64 go build -o load-role_linux

deploy: linux
	scp load-role_linux philip@tcs.com:/home/philip/tmp/load-role

