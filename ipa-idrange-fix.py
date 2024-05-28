#!/usr/bin/python3 -I

import logging
import ldap

from ipalib import api
from ipapython.admintool import AdminTool
from ipapython.dn import DN
from ipapython import ipautil

logger = logging.getLogger(__name__)

# Class for ID Range
class IDRange:

    def __init__(self):
        self.name               : str = None
        self.size               : int = None
        self.first_id           : int = None
        self.base_rid           : int = None
        self.secondary_base_rid : int = None
        self.suffix             : str = None
        self.type               : str = None
        self.last_id            : int = None
        self.last_base_rid      : int = None
        self.last_secondary_rid : int = None
        self.dn                 : str = None
        self.proposed           : bool = False

    def count(self):
        self.last_id = self.first_id + self.size - 1
        if self.type == "ipa-local":
            self.last_base_rid = self.base_rid + self.size if self.base_rid is not None else None
            self.last_secondary_rid = self.secondary_base_rid + self.size if self.secondary_base_rid is not None else None

    def __repr__(self):
        return f"IDRange(name='{self.name}', type={self.type}, size={self.size}, first_id={self.first_id}, " \
               f"base_rid={self.base_rid}, secondary_base_rid={self.secondary_base_rid})"
    
# Class for ID entity 
class IDentity:
    def __init__(self):
        self.dn     : str = None
        self.name   : str = None
        self.user   : bool = None
        self.number : int = None

    def __repr__(self):
        if self.user:
            return f"user(username='{self.name}', uid={self.number}, {self.dn})"
        else:
            return f"group(groupname='{self.name}', gid={self.number}, {self.dn})"


class IPAIDRangeFix(AdminTool):
    command_name = "ipa-idrange-fix"
    log_file_name = "/var/log/ipa-idrange-fix.log"
    usage = "%prog"
    description = "Analyze and fix IPA ID ranges"

    @classmethod
    def add_options(cls, parser):
        super(IPAIDRangeFix, cls).add_options(parser)
        parser.add_option(
            '--ridoffset', 
            dest='ridoffser', type=int, default=100000, metavar=100000, \
            help="Offset for a next base RID from previous RID range. Needed for future range size expansions. Has to be > 0")
        parser.add_option(
            '--rangegap', 
            dest='rangegap', type=int, default=200000, metavar=200000, \
            help="Threshold for a gap between outofrange IDs to be considered a different range. Has to be > 0")
        parser.add_option(
            '--minrange', 
            dest='minrange', type=int, default=10, metavar=10, \
            help="Minimal considered range size for outofrange IDs. All ranges lower than this number will be discarded and IDs will be listed to be moved. Has to be > 1")
        parser.add_option(
            '--allowunder1000', 
            dest='allowunder1000', action="store_true", default=False, \
            help="Allow idranges to start below 1000. Be careful to not overlap IPA users/groups with existing system-local ones!")
        parser.add_option(
            '--norounding', 
            dest='norounding', action="store_true", default=False, \
            help="Disable IDrange rounding attempt in order to get ranges exactly covering just IDs provided")
        parser.add_option(
            '--unattended', 
            dest='unattended', action="store_true", default=False, \
            help="Automatically fix all range issues found without asking for confirmation")

    def validate_options(self):
        super(IPAIDRangeFix, self).validate_options(needs_root=True)

    def run(self):
        api.bootstrap(in_server=True)
        api.finalize()

        self.realm = api.env.realm
        self.suffix = ipautil.realm_to_suffix(self.realm)

        try:
            api.Backend.ldap2.connect()
            
            id_ranges:list[IDRange] = read_ranges(self.suffix, api)
            draw_ascii_table(id_ranges)

            id_entities = read_outofrange_identities(self.suffix, id_ranges, api)
            for id_entity in id_entities:
                print(id_entity)

        finally:
            if api.Backend.ldap2.isconnected():
                api.Backend.ldap2.disconnect()

        return 0

if __name__ == "__main__":
    tool = IPAIDRangeFix()
    tool.run_cli()


"""
Working with output
"""
#region
# Function to draw range output table
def draw_ascii_table(id_ranges: list[IDRange]) -> None:
    # Calculate the maximum width required for each column including column names
    max_widths = {column: max(len(str(column)), max(len(str(getattr(id_range, column))) if getattr(id_range, column) is not None else 0 for id_range in id_ranges)) for column in ["name", "type", "size", "first_id", "last_id", "base_rid", "last_base_rid", "secondary_base_rid", "last_secondary_rid"]}

    # Draw the table header
    header = "| "
    for column, width in max_widths.items():
        header += f"{column.ljust(width)} | "
    horizontal_line = "-" * (len(header)-1)
    print(horizontal_line)
    print(header)
    print(horizontal_line)

    # Draw the table rows
    for id_range in id_ranges:
        row = "| "
        for column, width in max_widths.items():
            value = getattr(id_range, column)
            if value is not None:
                row += f"{str(value).rjust(width)} | "
            else:
                row += " " * (width + 1) + "| "  # Add 3 to account for leading and trailing spaces and the separator
        print(row)
    print(horizontal_line)

#endregion
"""
Reading from LDAP
"""
#region
# Function to read ID ranges from LDAP
def read_ranges(suffix, api) -> list[IDRange]:
    ranges = api.Backend.ldap2.get_entries(DN(api.env.container_ranges, suffix), ldap.SCOPE_ONELEVEL, "(objectclass=ipaIDRange)")
    id_ranges:IDRange = []

    for entry in ranges:
        sv = entry.single_value
        id_range = IDRange()
        id_range.name = sv.get('cn')
        id_range.size = int(sv.get('ipaidrangesize'))
        id_range.first_id = int(sv.get('ipabaseid'))
        id_range.base_rid = int(sv.get('ipabaserid')) if sv.get('ipabaserid') else None
        id_range.secondary_base_rid = int(sv.get('ipasecondarybaserid')) if sv.get('ipasecondarybaserid') else None
        id_range.suffix = suffix
        id_range.type = sv.get('iparangetype')
        id_range.dn = entry.dn

        id_range.count()
        logger.debug(f"ID range found: {id_range}")

        id_ranges.append(id_range)

    id_ranges.sort(key=lambda x: x.first_id)
    return id_ranges

# Funtction to get out of range users and groups
def read_outofrange_identities(suffix, id_ranges, api) -> list[IDentity]:
    id_entities = []

    filter = get_outofrange_filter(id_ranges, "account", "uid")
    logger.debug(f"Searching users with filter: {filter}")
    try:
        identities = api.Backend.ldap2.get_entries(DN(api.env.container_user, suffix), ldap.SCOPE_ONELEVEL, filter)
        logger.info(f"Out of range users found: {len(identities)}")
        for entry in identities:
            id_entities.append(read_identity(entry, user=True))
    except Exception as e:
        if e == "no matching entry found":
            logger.info("No out of range users found!")
        else:
            logger.error(f"Exception while reading users: {e}")

    filter = get_outofrange_filter(id_ranges, "group", "gid")
    logger.debug(f"Searching groups with filter: {filter}")
    try:        
        identities = api.Backend.ldap2.get_entries(DN(api.env.container_group, suffix), ldap.SCOPE_ONELEVEL, filter)
        logger.info(f"Out of range groups found: {len(identities)}")
        for entry in identities:
            id_entities.append(read_identity(entry, user=False))
    except Exception as e:
        if e == "no matching entry found":
            logger.info("No out of range groups found!")
        else:
            logger.error(f"Exception while reading groups: {e}")

    return id_entities

# Funtion to convert ldap entry to IDentity object
def read_identity(ldapentry, user:bool=True) -> IDentity:
    sv = ldapentry.single_value
    id_entity = IDentity()
    id_entity.dn = ldapentry.dn
    id_entity.name = sv.get('cn')
    id_entity.number = int(sv.get('uidNumber')) if user else int(sv.get('gidNumber'))
    id_entity.user = user
    logger.debug(f"Out of range found: {id_entity}")
    return id_entity

def get_outofrange_filter(id_ranges_all: list[IDRange], object_class: str, id: str) -> str:
     # we need to look only for ipa-local ranges
    id_ranges = get_ipa_local_ranges(id_ranges_all)

    filter = f"(&(objectClass=posix{object_class})(|"

    # adding gaps in ranges to the filter
    for i in range(len(id_ranges)+1):
        if i == 0:
            start_condition = f"({id}Number>=1)"
        else:
            start_condition = f"({id}Number>={id_ranges[i-1].last_id + 1})"

        if i < len(id_ranges):
            end_condition = f"({id}Number<={id_ranges[i].first_id - 1})"
        else:
            end_condition = f"({id}Number<=2147483647)"
    
        filter += f"(&{start_condition}{end_condition})"

    filter += "))"
    
    return filter
#endregion
"""
Writing to LDAP
"""
#region
def apply_ridbases(id_range: IDRange, api) -> None:
    try:
        api.Backend.ldap2.modify_s(id_range.dn,
                                         [(ldap.MOD_ADD, "ipaBaseRID",
                                                 str(id_range.base_rid)),
                                         (ldap.MOD_ADD, "ipaSecondaryBaseRID",
                                                 str(id_range.secondary_base_rid))])
        logger.info(f"RID bases updated for range {id_range.name}")

    except ldap.CONSTRAINT_VIOLATION as e:
        logger.error(f"Failed to add RID bases to the range {id_range.name}. Constraint violation.\n"
                               "object:\n  %s" % e[0]['info'])
        raise RuntimeError("Constraint violation.\n")

    except Exception as e:
        logger.error(f"Exception while updating RID bases for range {id_range.name}: {e}")
        raise RuntimeError("Failed to update RID bases.\n")

#endregion
"""
Working with ranges
"""
#region
# Function to get ipa-local ranges only
def get_ipa_local_ranges(id_ranges: list[IDRange]) -> list[IDRange]:
    ipa_local_ranges = []

    for id_range in id_ranges:
        if id_range.type == "ipa-local":
            ipa_local_ranges.append(id_range)

    return ipa_local_ranges




#endregion
