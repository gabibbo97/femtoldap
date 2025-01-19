.PHONY: run
run: stop
	sudo podman run --rm --detach --name forgejo \
		--network host \
		--volume $(CURDIR)/config.ini:/data/gitea/conf/app.ini:ro,Z \
		codeberg.org/forgejo/forgejo:10
	sudo podman exec -u 1000 -it forgejo forgejo migrate
	sudo podman exec -u 1000 -it forgejo forgejo admin auth add-ldap \
		--active --skip-tls-verify \
		--name ldap \
		--host 127.0.0.1 --port 3389 \
		--user-search-base 'ou=users,dc=example,dc=com' \
		--user-filter '(&(objectClass=inetOrgPerson)(|(uid=%[1]s)(mail=%[1]s)))' \
		--admin-filter '(memberOf=cn=sample_admin_group1,ou=groups,dc=example,dc=com)' \
		--allow-deactivate-all \
		--username-attribute uid \
		--firstname-attribute givenName \
		--surname-attribute sn \
		--email-attribute mail \
		--public-ssh-key-attribute sshPublicKey \
		--bind-dn uid=sample_app1,ou=apps,dc=example,dc=com \
		--bind-password sample_password \
		--synchronize-users \
		--security-protocol unencrypted \
		--attributes-in-bind
	sudo podman exec -u 1000 -it forgejo forgejo admin auth list

.PHONY: stop
stop:
	sudo podman rm -f -i forgejo
