
all:
	go build

test: setup_test test1 test2 test3 post_test

setup_test: all

post_test:
	@echo 
	@echo PASS


.PHONEY: test1
test1:
	jsonCheck -i testdata/good.json a b

.PHONEY: test2
test2:
	./not.sh jsonCheck -i testdata/good.json a c

.PHONEY: test3
test3:
	jsonCheck -r -i testdata/good.json e f

install: all
	rm ~/bin/jsonCheck
	( cd ~/bin ; ln -s ../go/src/github.com/pschlump/gintools/tools/jsonCheck/jsonCheck . )


linux:
	GOOS=linux GOARCH=amd64 go build -o jsonCheck_linux

deploy: linux
	scp jsonCheck_linux philip@45.79.53.54:/home/philip/tmp/jsonCheck
