### Container

.PHONY: build-container
build-container:
	sudo podman build -t femtoldap .

### TLS

.PHONY: reset-tls
reset-tls:
	rm -f tls.dhparam tls.crt tls.key

tls.dhparam:
	openssl dhparam -dsaparam -out $@ 4096

tls.key:
# openssl genrsa -out $@ 4096
	openssl ecparam -name secp521r1 -genkey -out $@ -outform PEM

tls.crt: tls.key
	openssl req -new -x509 -batch \
		-key $< -keyform PEM \
		-out $@ -outform PEM \
		-sha512 \
		-days 365 \
		-subj '/CN=ldaps/'
