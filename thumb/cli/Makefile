
all:
	go build

test: testSetup test1 test2 testSuccess

testSetup:
	mkdir -p out ref

testSuccess:
	@echo PASS

test1:
	./cli -w 250 -h 0  -oh 250 -ow 250 ./testdata/p*.jpg
	mv dst.jpg out/test1.jpg
	diff out/test1.jpg ref

test2:
	./cli -w 250 -h 0  -oh 250 -ow 250 ./testdata/l*.png
	mv dst.jpg out/test2.jpg
	diff out/test2.jpg ref

