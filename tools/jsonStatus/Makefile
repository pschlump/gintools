
all:
	go build

test: setup_test test1 test2 test3 test4 test5 post_test

setup_test: all

post_test:
	@echo 
	@echo PASS

.PHONEY: test1
test1:
	jsonStatus -i testdata/good.json 

.PHONEY: test2
test2:
	-jsonStatus -i testdata/bad.json 

.PHONEY: test3
test3:
	jsonStatus -i testdata/register 

.PHONEY: test4
test4:
	jsonStatus -r -i testdata/register-err

install: all
	cp jsonStatus ~/bin

# test on empty file
test5:
	./not.sh jsonStatus -i testdata/empty 
