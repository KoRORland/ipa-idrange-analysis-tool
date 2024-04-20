# IPA IDrange Analysis tool

A tool for analysis of existing IPA ranges, and providing advice on how to resolve issues, add new ranges, etc.

It is able to provide a easily digestible table representation on already configured ranges, alongside some common issues and commands that would help troubleshooting issues with IPA ID ranges, mostly following this solution - [How to solve users unable to authenticate to IPA/IDM with PAC issues - S4U2PROXY_EVIDENCE_TKT_WITHOUT_PAC error](https://access.redhat.com/solutions/7052703).

**DISCLAIMER** 

Please check the commands you run on you IPA installation thoroughly *before* you run them. This tool provides a mere advice on how to approach IPA idrange issues, the author bears no responsibility for the commands you run on your IPA installation.

## Getting started

This is a simple Python3 script, with no external libraries apart from `sys` and `argparse` so it should run on basically any system where `python3` is installed.

```
git clone https://gitlab.cee.redhat.com/gss-emea/ipa-idrange-analysis-tool.git
cd ipa-idrange-analysis-tool
```

## Using the tool
### Basic first step
Get the output for existing IPA ranges to the file:
```
ipa idrange-find --all --raw > idranges.txt
```
or via `ldapsearch`:
```
ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=ranges,cn=etc,$SUFFIX" "(objectClass=ipaIDrange)" > idranges.txt
```
and then provide it to the tool as an argument:
```
python3 idrange-analyse.py --ranges idranges.txt
```
or straightaway via `stdin`:
```
ipa idrange-find --all --raw | python3 idrange-analyse.py
```
### Range proposal for users and groups that are out of the ranges
After first basic run, the tool will provide `ldapsearch`es to determine users and groups outside of existing IPA ranges. You can provide resulting `outofranges.ldif` as an argument to get advice on which ranges to create:
```
python3 idrange-analyse.py --ranges idranges --outofrange outofranges.ldif
```
### Advanced attributes
```
--ridoffset INT
```
An offset tool is using to propose new base RIDs for ranges. We introduce offset in order to have an ability to increase ranges in the future, increase to more than offset will result to RID bases overlapping, and will be denied. If set to 0, there will be no offset, proposed RID ranges will start directly one after another.
Default - 100000, allowed values - from 0 to 2^31
```
--rangegap INT
```
A number of IDs between out of ranges IDs to be considered to big to be inside a proposed range. If the gap is bigger than this attribute, new range will be started. If set to 0, every entity will get it's own range, if allowed by `--minrange`.
Default - 200000, allowed values - from 0 to 2^31
```
--minrange INT
```
A minimal size of IDs in a range the tool considers to be a valid range. All IDs in ranges with less than this number will be considered outliers, not worth creating an IDrange for, and will be listed explicitly to be moved manually. If set to 1, every entity, even if single in the middle of an empty space, will be proposed with a range.
Default - 10, allowed values - from 1 to 2^31
```
--allowunder1000
```
A flag to allow proposing ranges that start with IDs lower than 1000. Remember, this is not recommended - IDs under 1000 are reserved for system and service users and groups, and IDranges with these low IDs may result with overlapping of IPA and system local users and groups, which can be a serious security issue and generally produce a lot of issues around these entities' resolution.
```
--norounding
```
A flag to turn off idrange starting id and size rounding - e.g. if we find ID 1234, and the size 567, it will stay that way, the proposed range will start at ID 1234, and have a 567 size. If not specified, basic rounding to outer margins will be applied.

## What does the tool do?

All the code runs in memory, there are no changes to the input stream(s).
- We create an easy-looking table with data from the input;
- We check the ranges provided are not overlapping or stretch out of the reasonable ID range 1000-2147483647;
- We try to porpose suitable RID bases to fill in the missing ones alongside the `ldapmodify` commands to apply the changes;

If no identities out of ranges are provided:
- We propose `ldapsearch`es that will reveal POSIX users and groups that are outside of currently present ranges;

If identities out of ranges are provided:
- We provide propositions on what ranges to create to cover most of the identities provided;
- We provide a list of 'outliers' - users and groups too far away and too small in number to get a separate idrange;
- We provide a list of users and group with IDs under 1000, to be moved out of system-reserved range manually;

As a finale of the run tool creates a second table on how the ranges will look like if all the advices are applied.

## Design considerations

### RID base selection

Default IPA local IDrange has RID bases of `base_rid = 1000` and `secondary_base_rid = 100000000`. The tool will try to propose the RID bases in same logic:
```
base_rid =  last base_rid + last range size + offset
secondary_base_rid = last secondary_base_rid + last range size + offset
```
Offset is used to offer the ability to extend already existing ranges in the future, by the number of IDS no bigger than the offset. It is a tunable parameter (`--ridoffset INT`).

If this fails for any reason, the tool will fall back to this logic:
```
base_rid = biggest RID of any kind + offset
secondary_base_rid =  biggest RID of any kind, including already proposed base_rid, + offset
```
If both logics failed, it is likely due to constraints violation - either we are going over 2^31, which is reserved for SubID RIDs, or we have some unforeseen overlaps. In this case, the script will put out the bases it tried and failed, and will continue without proposing a valid bases.

### IDranges propositions

Dissecting an unknown set of IDs into viable IDranges is not a trivial task. During design consideration for this feature, we faced following constraints:
- IDranges have to be rather populated, we don't want huge gaps inside ranges to be empty;
- IDranges have to be rather small, we don't want IDranges covering millions and millions of IDs, even though it is possible, it may pose a problem during ID mappings in IPA-IPA trust;
- IDranges have to be rather small in amount, we don't want thousands of ultra-small IDranges to litter the installation. It is possible, and in rare cases, required, to create an IDrange for just one entity, but we don't want to make it a rule. Too many IDranges can negatively affect performance;
- we still want the script to be easy-running on basically every system with Python3, so no sophisticated statistical libraries should be used;
- the solution needs to be flexible enough to account for various scenarios existing in deployed installations.

The solution was to introduce tunable parameters: minimal IDrange size (`--minrange INT`) and maximum gap allowed(`--rangegap INT`). 

The algorithm works like this:
- array of identities is sorted;
- then array is split into groups via finding big enough gaps between IDs, if big enough gap is detected, it starts a new group;
- then these groups are analyzed, if there are groups that are too small in size, the IDs in that group are declared as outliers, not worth creating a separate IDrange for, and will be listed separately;
- for the remaining groups, IDranges are proposed.

### IDranges rounding

Due to the historical nature of identities out of IPA ranges, they rarely fit into rounded ranges that are easy to digest by a user. The solution was to propose ranges that are rounded to the outer margins to the next closest 'round' number to beginning and the end of the range, depending on the range size. Thus, ranges with a size of hundreds will be rounded to closest outer round hundreds, ranges with the size of hundred thousands will be rounded to closest hundred thousands. 

This can introduce unexpected overlaps, so if this rounding fails, the range will be proposed without any rounding.

Rounding can be turned off by using `--norounding` attribute.

## Sample outputs
Help output:
```
$ python3 idrange-analyse.py --help
usage: idrange-analyse.py [-h] [--ranges idranges] [--ridoffset 100000]
                          [--outofrange outofranges.ldif] [--rangegap 200000]
                          [--minrange 10] [--allowunder1000] [--norounding]

Tool to process IPA ID ranges data

optional arguments:
  -h, --help            show this help message and exit
  --ranges idranges     Path to file containing ID ranges data - output of
                        `ipa idrange-find --all --raw > idranges`
  --ridoffset 100000    Offset for a next base RID from previous RID range.
                        Needed for future range size expansions. Has to be > 0
  --outofrange outofranges.ldif
                        Path to file for out of range users and groups, that
                        we got from ldapsearches provided
  --rangegap 200000     Threshold for a gap between outofrange IDs to be
                        considered a different range. Has to be > 0
  --minrange 10         Minimal considered range size for outofrange IDs. All
                        ranges lower than this number will be discarded and
                        IDs will be listed to be moved. Has to be > 1
  --allowunder1000      Allow idranges to start below 1000. Be careful to not
                        overlap IPA users/groups with existing system-local
                        ones!
  --norounding          Disable IDrange rounding attempt in order to get
                        ranges exactly covering just IDs provided
```
Output with test ranges:
```
$ python3 idrange-analyse.py --ranges examples/ranges.txt

--------------------------------------------------------------------------------
Range table
--------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| name                                 | type         | size       | first_id   | last_id    | base_rid   | last_base_rid | secondary_base_rid | last_secondary_rid | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| EXAMPLE.DOMAIN.LOCAL_under1000_range |    ipa-local |       1000 |        900 |       1899 |            |               |                    |                    | 
|    EXAMPLE.DOMAIN.LOCAL_middle_range |    ipa-local |    2000000 |   50000000 |   51999999 |            |               |                    |                    | 
|             WINDOMAIN.LOCAL_id_range | ipa-ad-trust |     200000 | 1001600000 | 1001799999 |          0 |               |                    |                    | 
|        EXAMPLE.DOMAIN.LOCAL_id_range |    ipa-local |     200000 | 1397400000 | 1397599999 |       1000 |        201000 |          100000000 |          100200000 | 
|     EXAMPLE.DOMAIN.LOCAL_subid_range | ipa-ad-trust | 2147352576 | 2147483648 | 4294836223 | 2147283648 |               |                    |                    | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------
Range sanity check
--------------------------------------------------------------------------------

WARNING! Range EXAMPLE.DOMAIN.LOCAL_under1000_range overlaps with default system local range (IDs lower 1000 are reserved for system and service users and groups)!

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

--------------------------------------------------------------------------------
LDAP searches to detect IDs out of ranges
--------------------------------------------------------------------------------

LDAP Search Commands for Users outside of ranges:
# ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=users,cn=accounts,dc=example,dc=domain,dc=local" "(&(objectClass=posixaccount)(|(&(uidNumber>=1)(uidNumber<=899))(&(uidNumber>=1900)(uidNumber<=49999999))(&(uidNumber>=52000000)(uidNumber<=1397399999))(&(uidNumber>=1397600000)(uidNumber<=2147483647))))" dn uidNumber >> outofranges.ldif

LDAP Search Commands for Groups outside of ranges:
# ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=groups,cn=accounts,dc=example,dc=domain,dc=local" "(&(objectClass=posixgroup)(|(&(gidNumber>=1)(gidNumber<=899))(&(gidNumber>=1900)(gidNumber<=49999999))(&(gidNumber>=52000000)(gidNumber<=1397399999))(&(gidNumber>=1397600000)(gidNumber<=2147483647))))" dn gidNumber >> outofranges.ldif

You can provide the resulting file as --outofrange option to this tool to get advise on which ranges to create.

--------------------------------------------------------------------------------
End result with proposed changes
--------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| name                                 | type         | size       | first_id   | last_id    | base_rid   | last_base_rid | secondary_base_rid | last_secondary_rid | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| EXAMPLE.DOMAIN.LOCAL_under1000_range |    ipa-local |       1000 |        900 |       1899 |     301000 |        302000 |          100300000 |          100301000 | 
|    EXAMPLE.DOMAIN.LOCAL_middle_range |    ipa-local |    2000000 |   50000000 |   51999999 |     402000 |       2402000 |          100401000 |          102401000 | 
|             WINDOMAIN.LOCAL_id_range | ipa-ad-trust |     200000 | 1001600000 | 1001799999 |          0 |               |                    |                    | 
|        EXAMPLE.DOMAIN.LOCAL_id_range |    ipa-local |     200000 | 1397400000 | 1397599999 |       1000 |        201000 |          100000000 |          100200000 | 
|     EXAMPLE.DOMAIN.LOCAL_subid_range | ipa-ad-trust | 2147352576 | 2147483648 | 4294836223 | 2147283648 |               |                    |                    | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
```
After proposed changes, and with outofranges.ldif provided by proposed searches:
```
$ python3 idrange-analyse.py --ranges examples/ranges_changed.txt --outofrange examples/outofranges.ldif

--------------------------------------------------------------------------------
Range table
--------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| name                                 | type         | size       | first_id   | last_id    | base_rid   | last_base_rid | secondary_base_rid | last_secondary_rid | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| EXAMPLE.DOMAIN.LOCAL_under1000_range |    ipa-local |       1000 |       1010 |       2009 |     301000 |        302000 |          100300000 |          100301000 | 
|    EXAMPLE.DOMAIN.LOCAL_middle_range |    ipa-local |    2000000 |   50000000 |   51999999 |     402000 |       2402000 |          100401000 |          102401000 | 
|             WINDOMAIN.LOCAL_id_range | ipa-ad-trust |     200000 | 1001600000 | 1001799999 |          0 |               |                    |                    | 
|        EXAMPLE.DOMAIN.LOCAL_id_range |    ipa-local |     200000 | 1397400000 | 1397599999 |       1000 |        201000 |          100000000 |          100200000 | 
|     EXAMPLE.DOMAIN.LOCAL_subid_range | ipa-ad-trust | 2147352576 | 2147483648 | 4294836223 | 2147283648 |               |                    |                    | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------
Range sanity check
--------------------------------------------------------------------------------

All ranges seem to be in order.

--------------------------------------------------------------------------------
RID bases check
--------------------------------------------------------------------------------

All RID bases are in order.

--------------------------------------------------------------------------------
IDranges for IDs out of ranges proposal
--------------------------------------------------------------------------------

Following identities have IDs lower 1000, which is not recommeneded (if you definitely need ranges proposed for those, use --allowunder1000):

group(groupname='under1000group', gid='101', dn='dn: cn=under1000group,cn=groups,cn=accounts,dc=example,dc=domain,dc=local')

Following identities are too far away from the others to get ranges (try adjusting --minrange, or moving them to already created ranges):

group(groupname='outliergroup', gid='1010000', dn='dn: cn=outliergroup,cn=groups,cn=accounts,dc=example,dc=domain,dc=local')

Proposition for a range for existing IDs out of ranges with start id 10001 and end id 10025:

# ipa idrange-add EXAMPLE.DOMAIN.LOCAL_id_range_001 --base-id=10000 --range-size=30 --rid-base=2502000 --secondary-rid-base=102501000

--------------------------------------------------------------------------------
End result with proposed changes
--------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| name                                 | type         | size       | first_id   | last_id    | base_rid   | last_base_rid | secondary_base_rid | last_secondary_rid | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
| EXAMPLE.DOMAIN.LOCAL_under1000_range |    ipa-local |       1000 |       1010 |       2009 |     301000 |        302000 |          100300000 |          100301000 | 
|    EXAMPLE.DOMAIN.LOCAL_id_range_001 |    ipa-local |         30 |      10000 |      10029 |    2502000 |       2502030 |          102501000 |          102501030 | 
|    EXAMPLE.DOMAIN.LOCAL_middle_range |    ipa-local |    2000000 |   50000000 |   51999999 |     402000 |       2402000 |          100401000 |          102401000 | 
|             WINDOMAIN.LOCAL_id_range | ipa-ad-trust |     200000 | 1001600000 | 1001799999 |          0 |               |                    |                    | 
|        EXAMPLE.DOMAIN.LOCAL_id_range |    ipa-local |     200000 | 1397400000 | 1397599999 |       1000 |        201000 |          100000000 |          100200000 | 
|     EXAMPLE.DOMAIN.LOCAL_subid_range | ipa-ad-trust | 2147352576 | 2147483648 | 4294836223 | 2147283648 |               |                    |                    | 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
```
