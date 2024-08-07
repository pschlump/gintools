
all:
	go build

all_types: create_and_sign ct2 ct3

install: all
	cp jwt-cli ~/bin

create_and_sign:
	echo '{"foo":"bar"}' | ./jwt-cli -key ./test/sample_key -alg RS256 -sign - | tee edSignedToken.txt | ./jwt-cli -key ./test/sample_key.pub -alg RS256 -verify -

# RSA working. - generate by big.
ct2:
	echo '{"foo":"bar"}' | ./jwt-cli -key  \
		./test/RSA/RSA_private.pem \
	-alg RS256 -sign - | tee rsaSignedToken.txt | ./jwt-cli -key  \
		./test/RSA/RSA_public.pem \
	-alg RS256 -verify -


## Works - example keys from 
# export jwtlib=/Users/philip/go/src/github.com/dgrijalva/jwt-go
ct3:
	echo '{"foo":"bar"}' | ./jwt-cli -key  \
		./test/ec256-private.pem \
	-alg ES256 -sign - | tee ec256SignedToken.txt | ./jwt-cli -key  \
		./test/ec256-public.pem \
	-alg ES256 -verify -

## Non working - keys generated by $big - genEC - but not in correct format.
# export big=/Users/philip/go/src/github.com/bigmikes/ed25519signature/
ct4:
	echo '{"foo":"bar"}' | ./jwt-cli -key  \
		./keys/ec256_private.pem \
	-alg ES256 -sign - | tee ec256SignedToken.txt | ./jwt-cli -key  \
		./keys/ec256_public.pem \
	-alg ES256 -verify -

# Working - with openssl to generate keys.
ct5_gen_keys:
	# generate a private key for a curve
	openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
	# generate corresponding public key
	openssl ec -in private-key.pem -pubout -out public-key.pem
	# Generates ->   private-key.pem public-key.pem

ct5:
	echo '{"foo":"bar"}' | ./jwt-cli -key  \
		./keys/ec256-openssl-private.pem \
	-alg ES256 -sign - | tee ec256SignedToken.txt | ./jwt-cli -key  \
		./keys/ec256-openssl-public.pem \
	-alg ES256 -verify -

ct5a:
	echo '{"foo":"bar"}' | ./jwt-cli -key  \
		./private-key.pem \
	-alg ES256 -sign - | tee ec256SignedToken.txt | ./jwt-cli -key  \
		./public-key.pem \
	-alg ES256 -verify -

test001: all
	mkdir -p ./testdata ./out ./ref
	echo '{"foo":"bar","auth_token":"123-456-7890"}' >./testdata/data001.json
	~/bin/check-json-syntax --pretty ./testdata/data001.json >./ref/test001.out
	./jwt-cli -key  ./keys/ec256-openssl-private.pem -alg ES256 -sign ./testdata/data001.json >./out/test001.token
	./jwt-cli -key  ./keys/ec256-openssl-public.pem -alg ES256 -verify ./out/test001.token >./out/test001.out
	diff -w ./out/test001.out ./ref/test001.out
	@echo PASS

# Run `$ make ct5_gen_keys` first to generate the 2 key files i the current directory.
test002: all
	mkdir -p ./testdata ./out ./ref
	echo '{"foo":"bar","auth_token":"123-456-7890"}' >./testdata/data002.json
	~/bin/check-json-syntax --pretty ./testdata/data002.json >./ref/test002.out
	./jwt-cli -key  ./private-key.pem -alg ES256 -sign ./testdata/data002.json >./out/test002.token
	./jwt-cli -key  ./public-key.pem -alg ES256 -verify ./out/test002.token >./out/test002.out
	diff -w ./out/test002.out ./ref/test002.out
	@echo PASS

test003: all
	mkdir -p ./testdata ./out ./ref
	echo '{"foo":"bar","auth_token":"123-456-7890"}' >./testdata/data003.json
	~/bin/check-json-syntax --pretty ./testdata/data003.json >./ref/test003.out
	./jwt-cli -key  ./private-key.pem -alg ES256 -sign ./testdata/data003.json --out ./out/test003.token
	./jwt-cli -key  ./public-key.pem -alg ES256 -verify ./out/test003.token --out ./out/test003.out
	diff -w ./out/test003.out ./ref/test003.out
	@echo PASS

test004: all
	mkdir -p ./testdata ./out ./ref
	echo '{"foo":"bar","auth_token":"123-456-7890"}' >./testdata/data004.json
	./jwt-cli -key  ./private-key.pem -alg ES256 -sign ./testdata/data004.json --out ./out/test004.token --claim auth_token=331144331144331144
	./jwt-cli -key  ./public-key.pem -alg ES256 -show ./out/test004.token --out ./out/test004.out 
	./jwt-cli -key  ./public-key.pem -alg ES256 -verify ./out/test004.token --out ./out/test004.out --debug VerifyToken
	diff -w ./out/test004.out ./ref/test004.out
	@echo PASS


#(base) philip@victoria jwt-cli % go run x.go
#/var/folders/gd/89_p5db5627_l0sc9t55g_440000gn/T/go-build1755204152/b001/exe/x : generate pem formatted ed25519 keys
#    provide a single argument for the private key name
#    the public key name will have '.pub' appended

# Test that runs with the exitsting 'bob'/'bob.pub' key pair
test005: 
	mkdir -p ./testdata ./out ./ref
	echo '{"foo":"bar","auth_token":"123-456-7890"}' >./testdata/data005.json
	./jwt-cli -key  ./bob     -alg EdDSA -sign ./testdata/data005.json --out ./out/test005.token --claim auth_token=331144331144331144
	./jwt-cli -key  ./bob.pub -alg EdDSA -show ./out/test005.token --out ./out/test005.out 
	./jwt-cli -key  ./bob.pub -alg EdDSA -verify ./out/test005.token --out ./out/test005.out --debug VerifyToken
	diff -w ./out/test005.out ./ref/test005.out
	@echo PASS


gen_es384:
		./jwt-cli --generate jane --alg ES384

gen_rs384:
		./jwt-cli --generate r384 --alg RS384

gen_hs384:
		./jwt-cli --generate h256 --alg HS256

test006: 
	mkdir -p ./testdata ./out ./ref
	echo '{"foo":"bar","auth_token":"123-456-7890"}' >./testdata/data006.json
	./jwt-cli -key  ./jane-private.pem -alg ES256 -sign ./testdata/data006.json --out ./out/test006.token --claim auth_token=331144331144331144
	./jwt-cli -key  ./jane-public.pem  -alg ES256 -show ./out/test006.token --out ./out/test006.out 
	./jwt-cli -key  ./jane-public.pem  -alg ES256 -verify ./out/test006.token --out ./out/test006.out --debug VerifyToken
	diff -w ./out/test006.out ./ref/test006.out
	@echo PASS


# "return generateKeys(*flagGenKeys, *flagKey, *flagAlg)"
generate_ed25519:
		mkdir -p x
		( cd x ; ../jwt-cli --generate ed25519-aaa --alg EdDSA )

key1priv=./x/ed25519-aaa-Ed25519-private.pem
key1pub=./x/ed25519-aaa-Ed25519-public.pem

test_generate_ed25519:
	mkdir -p ./testdata ./out ./ref
	echo '{"foo":"bar","auth_token":"123-456-7890"}' >./testdata/data007.json
	./jwt-cli -key  ${key1priv} -alg EdDSA -sign ./testdata/data007.json --out ./out/test007.token --claim auth_token=331144331144331144
	./jwt-cli -key  ${key1pub}  -alg EdDSA -show ./out/test007.token --out ./out/test007.out 
	./jwt-cli -key  ${key1pub}  -alg EdDSA -verify ./out/test007.token --out ./out/test007.out --debug VerifyToken
	diff -w ./out/test007.out ./ref/test007.out
	@echo PASS

