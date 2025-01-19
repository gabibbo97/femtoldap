#!/bin/sh

ldapSearch() {
    ldapsearch \
        -D 'uid=sample_app1,ou=apps,dc=example,dc=com' \
        -w 'sample_password' \
        -H 'ldap://127.0.0.1:3389' \
        "$@"
}

#
# Root
#
printf '\n==> Searching root DSE\n\n'
ldapSearch -b ''

#
# Groups
#
printf '\n==> Searching groups\n\n'
ldapSearch -b ou=groups,dc=example,dc=com


#
# Users
#
printf '\n==> Searching users\n\n'
ldapSearch -b ou=users,dc=example,dc=com

#
# Mail aliases
#
printf '\n==> Searching mail aliases\n\n'
ldapSearch -b ou=aliases,ou=mail,dc=example,dc=com

#
# Self
#
printf '\n==> Searching self\n\n'
ldapSearch -b uid=sample_app1,ou=apps,dc=example,dc=com

#
# Apps
#
printf '\n==> Searching apps (should fail besides self)\n\n'
ldapSearch -b ou=apps,dc=example,dc=com
