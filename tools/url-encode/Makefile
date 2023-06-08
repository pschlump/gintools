
all:
	go build

test:
	go build
	mkdir -p ./out ./ref
	./url-encode "bob@example.com" >./out/test.out
	diff ./out/test.out ./ref/test.out
	@echo PASS

install:
	go build
	rm -f ~/bin/url-encode
	( cd ~/bin ; ln -s ../go/src/github.com/pschlump/gintools/tools/url-encode/url-encode . )

