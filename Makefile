
MODS=\
	awss3v2 \
	data \
	email \
	jwt_auth \
	log_enc \
	path_rewriter \
	qr_svr2 \
	run_template \
	setDefault \
	request_id \
	table_rest 

all:

build_all:
	./build-child.sh $(MODS)



