
all:
	go build

test01:
	go build
	cat testdata/01.txt | stream-split --output-dir ./testout --size-k 20 -pattern "z-%06d"

test02:
	-rm -rf ./testout
	mkdir -p ./testout
	go build
	cat testdata/01.txt | stream-split --output-dir ./testout --size-k 200 -pattern "z-%06d" --tmp-dir ./tmp
	cat testout/* >,a
	diff ,a testdata/01.txt
	@echo PASS | color-cat -c green

test03:
	-rm -rf ./testout
	mkdir -p ./testout
	go build
	cat testdata/03.txt | stream-split --output-dir ./testout --size-k 1 -pattern "z-%02d" --tmp-dir ./tmp
	cat testout/* >,a
	diff ,a testdata/03.txt
	@echo PASS | color-cat -c green

test04:
	-rm -rf ./testout
	mkdir -p ./testout
	go build
	cat testdata/03.txt | stream-split --output-dir ./testout --size-k 1 -pattern "z-%02d" --tmp-dir ./tmp -exec-cmd ./testdata/04.sh
	cat testout/* >,a
	diff ,a testdata/03.txt
	@echo PASS | color-cat -c green




install: all
	rm -f ~/bin/stream-split
	( cd ~/bin ; ln -s ../go/src/github.com/pschlump/gintools/tools/stream-split/stream-split . )


linux:
	GOOS=linux GOARCH=amd64 go build -o stream-split_linux

deploy: linux
	scp stream-split_linux philip@45.79.53.54:/home/philip/tmp/stream-split
