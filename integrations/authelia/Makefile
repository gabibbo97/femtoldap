.PHONY: run
run: stop tls.crt
	sudo podman run --rm -it --name authelia \
		--network host \
		--volume $(CURDIR)/config.yml:/config/configuration.yml:ro,Z \
		--volume $(CURDIR)/tls.crt:/config/tls.crt:ro,Z \
		--volume $(CURDIR)/tls.key:/config/tls.key:ro,Z \
		ghcr.io/authelia/authelia:4.38.19

.PHONY: stop
stop:
	sudo podman rm -f -i authelia

### TLS

.PHONY: reset-tls
reset-tls:
	rm -f tls.dhparam tls.crt tls.key

tls.dhparam:
	openssl dhparam -dsaparam -out $@ 4096

tls.key:
	openssl ecparam -name secp521r1 -genkey -out $@ -outform PEM

tls.crt: tls.key
	openssl req -new -x509 -batch \
		-key $< -keyform PEM \
		-out $@ -outform PEM \
		-sha512 \
		-days 365 \
		-subj '/CN=authelia/' \
		-addext 'subjectAltName=IP:127.0.0.1'
