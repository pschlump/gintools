
all:
	go build

test: setup_test test1 

setup_test: all

post_test:
	@echo 
	@echo PASS


.PHONEY: test1
test1:
	jsonInsert -i testdata/test1.json -k aaa -v bbb

install: all
	rm -f ~/bin/jsonInsert
	( cd ~/bin ; ln -s ../go/src/github.com/pschlump/gintools/tools/jsonInsert/jsonInsert . )


linux:
	GOOS=linux GOARCH=amd64 go build -o jsonInsert_linux

deploy: linux
	scp jsonInsert_linux philip@45.79.53.54:/home/philip/tmp/jsonInsert
