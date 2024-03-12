# IPA IDrange Analysis tool

A simple tool that accepts output of 
```
ipa idrange-find --all --raw
```
or 
```
ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=ranges,cn=etc,$SUFFIX" "(objectClass=ipaIDrange)"
```
and returns currently configured IPA ID ranges in digestible way, alongside some common issues and commands that would help troublesooting issues with IPA ID ranges, mostly following this solution - [How to solve users unable to authenticate to IPA/IDM with PAC issues - S4U2PROXY_EVIDENCE_TKT_WITHOUT_PAC error](https://access.redhat.com/solutions/7052703).

## Getting started

This is a simple Python3 script, with no external libraries apart from `sys` so it should run on basically any system where `python3` is installed.

```
git clone https://gitlab.cee.redhat.com/gss-emea/ipa-idrange-analysis-tool.git
cd ipa-idrange-analysis-tool
```

## Using the tool

```
python3 idrange-analyse.py < inputfile
```

## What does the tool do?

All the code runs in memory, there are no changes to the input stream. 
- We create an easy-looking table with data from the input;
- We check the ranges inputed are not overlapping or stretch out of the reasonable ID range 1000-2147483647;
- We propose `ldapsearch`es that will reveal POSIX users and groups that are outside of currently present ranges;
- We try to porpose suitable RID bases to fill in the missing ones alongside the `ldapmodify` commands to apply the changes.

## Sample outputs
```
$ python3 idrange-analyse.py < examples/testranges
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| range_name                           | type         | size       | first_id   | last_id    | base_rid   | last_base_rid | secondary_base_rid | last_secondary_rid | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| EXAMPLE.DOMAIN.LOCAL_under1000_range |    ipa-local |       1000 |        900 |       1899 |            |               |                    |                    | 
|    EXAMPLE.DOMAIN.LOCAL_middle_range |    ipa-local |    2000000 |   50000000 |   51999999 |            |               |                    |                    | 
|        EXAMPLE.DOMAIN.LOCAL_id_range |    ipa-local |     200000 |  555500000 |  555699999 |       1000 |        201000 |          100000000 |          100200000 | 
| EXAMPLE.DOMAIN.LOCAL_extra_big_range |    ipa-local |   10000000 | 1230000000 | 1239999999 |            |               |                    |                    | 
|     EXAMPLE.DOMAIN.LOCAL_subid_range | ipa-ad-trust | 2147352576 | 2147483648 | 4294836223 | 2147283648 |               |                    |                    | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------
Range sanity check
--------------------------------------------------------------------------------

WARNING! Range EXAMPLE.DOMAIN.LOCAL_under1000_range overlaps with default system local range (IDs lower 1000 are reserved for system and service users and groups)!

--------------------------------------------------------------------------------
LDAP searches to detect IDs out of ranges
--------------------------------------------------------------------------------

LDAP Search Commands for Users outside of ranges:
# ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=users,cn=accounts,dc=example,dc=domain,dc=local" "(&(objectClass=posixaccount)(|(&(uidNumber>=1)(uidNumber<=899))(&(uidNumber>=1900)(uidNumber<=49999999))(&(uidNumber>=52000000)(uidNumber<=555499999))(&(uidNumber>=555700000)(uidNumber<=1229999999))(&(uidNumber>=1240000000)(uidNumber<=2147483647))))" dn uidNumber

LDAP Search Commands for Groups outside of ranges:
# ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=groups,cn=accounts,dc=example,dc=domain,dc=local" "(&(objectClass=posixgroup)(|(&(gidNumber>=1)(gidNumber<=899))(&(gidNumber>=1900)(gidNumber<=49999999))(&(gidNumber>=52000000)(gidNumber<=555499999))(&(gidNumber>=555700000)(gidNumber<=1229999999))(&(gidNumber>=1240000000)(gidNumber<=2147483647))))" dn gidNumber

--------------------------------------------------------------------------------
RID bases check
--------------------------------------------------------------------------------

Proposition for missing RID bases:

EXAMPLE.DOMAIN.LOCAL_under1000_range: proposed values: Base RID = 301000, Secondary Base RID = 100300000.

LDAP command to apply would look like: 
~~~
# ldapmodify -D "cn=Directory Manager" -W -x << EOF
dn: cn=EXAMPLE.DOMAIN.LOCAL_under1000_range,cn=ranges,cn=etc,dc=example,dc=domain,dc=local                  
changetype: modify
add: ipabaserid
ipabaserid: 301000
-                  
add: ipasecondarybaserid
ipasecondarybaserid: 100300000
EOF
~~~

EXAMPLE.DOMAIN.LOCAL_middle_range: proposed values: Base RID = 402000, Secondary Base RID = 100401000.

LDAP command to apply would look like: 
~~~
# ldapmodify -D "cn=Directory Manager" -W -x << EOF
dn: cn=EXAMPLE.DOMAIN.LOCAL_middle_range,cn=ranges,cn=etc,dc=example,dc=domain,dc=local                  
changetype: modify
add: ipabaserid
ipabaserid: 402000
-                  
add: ipasecondarybaserid
ipasecondarybaserid: 100401000
EOF
~~~

EXAMPLE.DOMAIN.LOCAL_extra_big_range: proposed values: Base RID = 2502000, Secondary Base RID = 102501000.

LDAP command to apply would look like: 
~~~
# ldapmodify -D "cn=Directory Manager" -W -x << EOF
dn: cn=EXAMPLE.DOMAIN.LOCAL_extra_big_range,cn=ranges,cn=etc,dc=example,dc=domain,dc=local                  
changetype: modify
add: ipabaserid
ipabaserid: 2502000
-                  
add: ipasecondarybaserid
ipasecondarybaserid: 102501000
EOF
~~~
```
After proposed changes:
```
$ python3 idrange-analyse.py < examples/testranges_changed 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| range_name                           | type         | size       | first_id   | last_id    | base_rid   | last_base_rid | secondary_base_rid | last_secondary_rid | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| EXAMPLE.DOMAIN.LOCAL_under1000_range |    ipa-local |       1000 |        900 |       1899 |     301000 |        302000 |          100300000 |          100301000 | 
|    EXAMPLE.DOMAIN.LOCAL_middle_range |    ipa-local |    2000000 |   50000000 |   51999999 |     402000 |       2402000 |          100401000 |          102401000 | 
|        EXAMPLE.DOMAIN.LOCAL_id_range |    ipa-local |     200000 |  555500000 |  555699999 |       1000 |        201000 |          100000000 |          100200000 | 
| EXAMPLE.DOMAIN.LOCAL_extra_big_range |    ipa-local |   10000000 | 1230000000 | 1239999999 |    2502000 |      12502000 |          102501000 |          112501000 | 
|     EXAMPLE.DOMAIN.LOCAL_subid_range | ipa-ad-trust | 2147352576 | 2147483648 | 4294836223 | 2147283648 |               |                    |                    | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------
Range sanity check
--------------------------------------------------------------------------------

WARNING! Range EXAMPLE.DOMAIN.LOCAL_under1000_range overlaps with default system local range (IDs lower 1000 are reserved for system and service users and groups)!

--------------------------------------------------------------------------------
LDAP searches to detect IDs out of ranges
--------------------------------------------------------------------------------

LDAP Search Commands for Users outside of ranges:
# ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=users,cn=accounts,dc=example,dc=domain,dc=local" "(&(objectClass=posixaccount)(|(&(uidNumber>=1)(uidNumber<=899))(&(uidNumber>=1900)(uidNumber<=49999999))(&(uidNumber>=52000000)(uidNumber<=555499999))(&(uidNumber>=555700000)(uidNumber<=1229999999))(&(uidNumber>=1240000000)(uidNumber<=2147483647))))" dn uidNumber

LDAP Search Commands for Groups outside of ranges:
# ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=groups,cn=accounts,dc=example,dc=domain,dc=local" "(&(objectClass=posixgroup)(|(&(gidNumber>=1)(gidNumber<=899))(&(gidNumber>=1900)(gidNumber<=49999999))(&(gidNumber>=52000000)(gidNumber<=555499999))(&(gidNumber>=555700000)(gidNumber<=1229999999))(&(gidNumber>=1240000000)(gidNumber<=2147483647))))" dn gidNumber

--------------------------------------------------------------------------------
RID bases check
--------------------------------------------------------------------------------

All RID bases are in order.

```
Correct setup with AD trust (output from `ldapsearch`):
```
$ python3 idrange-analyse.py < examples/testranges_ldap 
----------------------------------------------------------------------------------------------------------------------------------------------------------
| range_name                | type         | size       | first_id   | last_id    | base_rid   | last_base_rid | secondary_base_rid | last_secondary_rid | 
----------------------------------------------------------------------------------------------------------------------------------------------------------
|  WINDOMAIN.LOCAL_id_range | ipa-ad-trust |     200000 | 1001600000 | 1001799999 |          0 |               |                    |                    | 
|    EXAMPLE.LOCAL_id_range |    ipa-local |     200000 | 1862000000 | 1862199999 |       1000 |        201000 |          100000000 |          100200000 | 
| EXAMPLE.LOCAL_subid_range | ipa-ad-trust | 2147352576 | 2147483648 | 4294836223 | 2147283648 |               |                    |                    | 
----------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------
Range sanity check
--------------------------------------------------------------------------------

All ranges seem to be in order.

--------------------------------------------------------------------------------
LDAP searches to detect IDs out of ranges
--------------------------------------------------------------------------------

LDAP Search Commands for Users outside of ranges:
# ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=users,cn=accounts,dc=example,dc=local" "(&(objectClass=posixaccount)(|(&(uidNumber>=1)(uidNumber<=1861999999))(&(uidNumber>=1862200000)(uidNumber<=2147483647))))" dn uidNumber

LDAP Search Commands for Groups outside of ranges:
# ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=groups,cn=accounts,dc=example,dc=local" "(&(objectClass=posixgroup)(|(&(gidNumber>=1)(gidNumber<=1861999999))(&(gidNumber>=1862200000)(gidNumber<=2147483647))))" dn gidNumber

--------------------------------------------------------------------------------
RID bases check
--------------------------------------------------------------------------------

All RID bases are in order.

```