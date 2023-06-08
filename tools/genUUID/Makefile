
all:
	go build

install:
	( cd ~/bin ; rm -f genUUID )
	( cd ~/bin ; ln -s ~/go/src/github.com/pschlump/gintools/tools/genUUID/genUUID . )

	
linux:
	GOOS=linux GOARCH=amd64 go build -o genUUID_linux

deploy: linux
	scp genUUID_linux philip@client.com:/home/philip/tmp/genUUID

