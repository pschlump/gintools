
all:
	go build

test: test_setup test01 test02 test_done

test_done:
	@echo PASS

test_setup:
	go build
	mkdir -p ./out ./ref

test01:
	./url-encode "bob@example.com" >./out/test.out
	diff ./out/test.out ./ref/test.out

test02:
	./url-encode --input test/data02.txt --output out/test02.out
	diff ./out/test02.out ./ref/test02.out

install:
	go build
	rm -f ~/bin/url-encode
	( cd ~/bin ; ln -s ../go/src/github.com/pschlump/gintools/tools/url-encode/url-encode . )

