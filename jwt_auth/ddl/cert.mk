
# Self Signed
# From: https://www.postgresql.org/docs/10/ssl-tcp.html

server_key:
	openssl req -new -x509 -days 365 -nodes -text -out server.crt \
		-keyout server.key -subj "/CN=victoria.ethereum-plumbing.com"
	chmod 0600 server.crt

# Self Signed Root
root_key:
	openssl req -new -nodes -text -out root.csr \
		-keyout root.key -subj "/CN=victoria.ethereum-plumbing.com"
	chmod 0600 root.key



# Fix the error “Error Loading extension section v3_ca” on macOS 
# ... add the following to your /etc/ssl/openssl.cnf
# -- cut --
# [ v3_ca ]
# basicConstraints = critical,CA:TRUE
# subjectKeyIdentifier = hash
# authorityKeyIdentifier = keyid:always,issuer:always
# -- cut --

# 
root_crt:
	openssl x509 -req -in root.csr -text -days 3650 \
	  -extfile /etc/ssl/openssl.cnf -extensions v3_ca \
	  -signkey root.key -out root.crt

# 
server_csr:
	openssl req -new -nodes -text -out server.csr \
		-keyout server.key -subj "/CN=victoria.ethereum-plumbing.com"
	chmod 0600 server.key
	openssl x509 -req -in server.csr -text -days 365 \
		-CA root.crt -CAkey root.key -CAcreateserial \
		-out server.crt
