# IPA IDrange Analysis tool

A simple tool that accepts output of 
```
# ipa idrange-find --all --raw
```
or 
```
# ldapsearch -xLLL -D "cn=Directory Manager" -W -b "cn=ranges,cn=etc,$SUFFIX" "(objectClass=ipaIDrange)"
```
and returns currently configured IPA ID ranges in digestible way, alongside some common issues and commands that would help troublesooting issues with IPA ID ranges, mostly following this solution - [How to solve users unable to authenticate to IPA/IDM with PAC issues - S4U2PROXY_EVIDENCE_TKT_WITHOUT_PAC error](https://access.redhat.com/solutions/7052703).

## Getting started

This is a simple Python3 script, with no external libraries apart from `sys` so it should run on basically on any system where `python3` is installed.

```
git clone https://gitlab.cee.redhat.com/gss-emea/ipa-idrange-analysis-tool.git
cd ipa-idrange-analysis-tool
```

## Using the tool

```
python3 idrange-analyse.py < inputfile
```

## What is being done?

All the code runs in memory, there are no changes to the input stream. 
- We create an easy-looking table with data from the imput;
- We check the ranges inputed are not overlapping;
- We propose `ldapsearch`es that will reveal POSIX users and groups that are  outside of the ranges;
- We try to porpose suitable RID bases to fill in the missing ones alongside the `ldapmodify` commands.

## Sample outputs
