#!/usr/bin/python3 -I

import logging
import ldap

from ipalib import api, errors
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
            dest='ridoffset', type=int, default=100000, metavar=100000, \
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
            
            # Reading range data
            id_ranges:list[IDRange] = read_ranges(self.suffix, api)
            
            if len(id_ranges) == 0:
                logger.info("No ID ranges found!")
                return 0

            draw_ascii_table(id_ranges)
            
            if not ranges_overlap_check(id_ranges):
                logger.error("Ranges overlap detected, cannot proceed! Please adjust existing ranges manually.")
                return 1
            
            # Sanity check done, proceeding with the rest
            propositions_rid = []
            propositions_new = []
            outliers = []
            under1000 = []

            # Checking RID bases for existing ranges
            id_ranges_nobase = get_ranges_no_base(id_ranges)

            if len(id_ranges_nobase) > 0:
                logger.info(f"Found {len(id_ranges_nobase)} ranges without base RIDs")
                for id_range in id_ranges_nobase:
                    logger.debug(f"Range {id_range.name} has rid base {id_range.base_rid} and secondary rid base {id_range.secondary_base_rid}")
                propose_rid_ranges(id_ranges, self.options.ridoffset, propositions_rid)
            else:
                logger.info("All ID ranges have base RIDs set, RID adjustments not needed.")

            # reading out of range IDs
            id_entities = read_outofrange_identities(self.suffix, id_ranges, api)

            if len(id_entities) == 0:
                logger.info("No out of range IDs found!")
            else:
                logger.info(f"Found overall {len(id_entities)} IDs out of already set up ID ranges.")
                # ruling out IDs under 1000 if flag is not set
                if not self.options.allowunder1000:
                    under1000, id_entities = separate_under1000(id_entities)
                    if len(under1000) > 0:
                        logger.info("Found IDs under 1000, which is not recommeneded (if you definitely need ranges proposed for those, use --allowunder1000):")
                        for identity in under1000:
                            logger.info(f"{identity}")

                # Get initial divide of IDs into groups
                groups = group_identities_by_threshold(id_entities, self.options.rangegap)

                # Get outliers from too small groups and clean groups for further processing
                outliers, cleangroups = separate_ranges_and_outliers(groups, self.options.minrange)

                # Print the outliers, they have to be moved manually
                if len(outliers) > 0:
                    print()
                    logger.info(f"Following identities are too far away from the others to get ranges (try adjusting --minrange, or moving them to already existing ranges):")
                    for identity in outliers:
                        logger.info(f"{identity}")

                if len(cleangroups) > 0:
                    # Get IDrange name base
                    basename = get_rangename_base(id_ranges)

                    # Create propositions for new ranges from groups
                    for group in cleangroups:
                        newrange = propose_range(group, id_ranges, self.options.ridoffset, basename, self.options.norounding)
                        if newrange is not None:
                            propositions_new.append(newrange)
                            id_ranges.append(newrange)
                            id_ranges.sort(key=lambda x: x.first_id)
                else:
                    print()
                    logger.info("No IDs fit for ID range to propose! Try tuning the parameters --minrange or --rangegap!")
            
            # Print the propositions
            print_intentions(id_ranges, propositions_rid, propositions_new, outliers, under1000)

            # If there are no propositions, we have nothing to do, exiting
            if len(propositions_rid) == 0 and len(propositions_new) == 0:
                return 0

            if (self.options.unattended):
                logger.info("Unattended mode enabled, proceeding with applying changes...")
            else:
                response = ipautil.user_input('Enter "yes" to proceed')
                if response.lower() != 'yes':
                    logger.info("Not proceeding.")
                    return 0
                logger.info("Proceeding.")

            # Applying changes
            for id_range in propositions_rid:
                apply_ridbases(id_range, api)

            for id_range in propositions_new:    
                create_range(id_range, api)

            logger.info("All changes applied successfully!")

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

def print_intentions(id_ranges:list[IDRange], propositions_rid: list[IDRange], propositions_new: list[IDRange], outliers: list[IDentity], under1000: list[IDentity]) -> None:
    
    print("\n\n")
    logger.info("Summary:")

    if len(outliers) > 0:
        logger.info("Outlier IDs that are too far away to get a range:")
        for identity in outliers:
            logger.info(f"{identity}")

    if len(under1000) > 0:
        logger.info("IDs under 1000:")
        for identity in under1000:
            logger.info(f"{identity}")
    else:
        logger.info("No IDs under 1000 found.")

    if len(propositions_rid) > 0:
        logger.info("Proposed changes to existing ranges:")
        for id_range in propositions_rid:
            logger.info(f"Range {id_range.name} - base RID: {id_range.base_rid}, secondary base RID: {id_range.secondary_base_rid}")
    else:
        logger.info("No changes proposed for existing ranges.")

    if len(propositions_new) > 0:
        logger.info("Proposed new ranges:")
        for id_range in propositions_new:
            logger.info(f"Range {id_range.name} - start ID: {id_range.first_id}, end ID: {id_range.last_id}, base RID: {id_range.base_rid}, secondary base RID: {id_range.secondary_base_rid}")
    else:
        logger.info("No new ranges proposed.")

    if len(propositions_rid) == 0 and len(propositions_new) == 0:
        logger.info("\nNo changes proposed, nothing to do.")
    else:
        print("\nID ranges table after proposed changes:")
        draw_ascii_table(id_ranges)

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
        id_range.proposed = False

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
    except errors.NotFound:
        logger.info("No out of range users found!")
    except Exception as e:
        logger.error(f"Exception while reading users: {e}")

    filter = get_outofrange_filter(id_ranges, "group", "gid")
    logger.debug(f"Searching groups with filter: {filter}")
    try:        
        identities = api.Backend.ldap2.get_entries(DN(api.env.container_group, suffix), ldap.SCOPE_ONELEVEL, filter)
        logger.info(f"Out of range groups found: {len(identities)}")
        for entry in identities:
            id_entities.append(read_identity(entry, user=False))
    except errors.NotFound:
        logger.info("No out of range groups found!")
    except Exception as e:
        logger.error(f"Exception while reading groups: {e}")

    id_entities.sort(key=lambda x: x.number)

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


def create_range(id_range: IDRange, api) -> None:
    try:
        logger.info(f"Creating range {id_range.name}...")

        entry = api.Backend.ldap2.make_entry(
            DN(id_range.dn),
            objectclass = ['ipaIDRange','ipadomainidrange'],
            ipaidrangesize=[str(id_range.size)],
            ipabaseid=[str(id_range.first_id)],
            ipabaserid=[str(id_range.base_rid)],
            ipasecondarybaserid=[str(id_range.secondary_base_rid)],
            iparangetype=[id_range.type],
        )
        
        api.Backend.ldap2.add_entry(entry)
        logger.info(f"Range {id_range.name} created")
    except Exception as e:
        logger.error(f"Exception while creating range {id_range.name}: {e}")
        raise RuntimeError("Failed to create range.\n")
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

# Function to check if two ranges overlap
def range_overlap_check(range1start: int, range1end: int, range2start: int, range2end: int) -> bool:
    # if range2start is inside range1, it's a fail
    if range1start <= range2start and range1end >= range2start:
        return False
    # if range2end is inside range1, it's a fail
    elif range1start <= range2end and range1end >= range2end:
        return False
    # if range1start is inside range2, it's a fail
    elif range2start <= range1start and range2end >= range1start:
        return False
    else:
        return True

# Function to check if proposed range overlaps with existing ones
def newrange_overlap_check(id_ranges: list[IDRange], newrange: IDRange) -> bool:
    for idrange in id_ranges:
        if not range_overlap_check(idrange.first_id,idrange.last_id,newrange.first_id,newrange.last_id):
            return False
    return True

# Function to check existing ranges for overlaps
def ranges_overlap_check(id_ranges: list[IDRange]) -> bool:
    if len(id_ranges) < 2:
        return True
    for i in range(len(id_ranges)-1):
        for j in range(i+1, len(id_ranges)):
            if not range_overlap_check(id_ranges[i].first_id, id_ranges[i].last_id, id_ranges[j].first_id, id_ranges[j].last_id):
                logger.error(f"Ranges {id_ranges[i].name} and {id_ranges[j].name} overlap!")
                return False
    return True
#endregion

"""
Working with RID bases
"""
#region
# Function to propose RID bases
def propose_rid_ranges(id_ranges: list[IDRange], delta: int, propositions: list[IDRange]) -> None:
    # delta repersents for far we start new base off existing range, used in order to allow for future expansion of existing ranges up to [delta] IDs
    ipa_local_ranges = get_ipa_local_ranges(id_ranges)

    for range in ipa_local_ranges:
        proposed_base_rid = 0
        proposed_secondary_base_rid = 0

        # Calculate proposed base RID and secondary base RID
        if range.base_rid is None:
            result, proposed_base_rid = propose_rid_base(range, ipa_local_ranges, delta, True)
            if (result):
                range.base_rid = proposed_base_rid
                range.last_base_rid = proposed_base_rid + range.size
            else:
                # if this fails too, we print the warning and abandon the idea
                logger.warning(f"Warning: Proposed base RIDs {proposed_base_rid} for {range.name} both failed, please adjust manually")
                continue

        if range.secondary_base_rid is None:
            result, proposed_secondary_base_rid = propose_rid_base(range, ipa_local_ranges, delta, False)
            if (result):
                range.secondary_base_rid = proposed_secondary_base_rid
                range.last_secondary_rid = proposed_secondary_base_rid + range.size
            else:
                # if this fails too, we print the warning and abandon the idea
                logger.warning(f"Warning: Proposed secondary base RIDs {proposed_secondary_base_rid} for {range.name} failed, please adjust manually")
                continue

        # Add range to the propositions if we changed something successfully
        if proposed_base_rid > 0 or proposed_secondary_base_rid > 0:
            logger.debug("Proposed RIDs for range %s: pri %s, sec %s", range.name, proposed_base_rid, proposed_secondary_base_rid)
            propositions.append(range)

# Function to propose base RID
def propose_rid_base(idrange: IDRange, ipa_local_ranges: list[IDRange], delta: int, primary: bool =True) -> tuple[bool,str]:
    # we are getting the biggest base RID + size + delta and try if it's a viable option, check same kind first
    proposed_base_rid = max_rid(ipa_local_ranges, primary) + delta
    if check_rid_base(ipa_local_ranges, proposed_base_rid, idrange.size):
        return True, proposed_base_rid
    else:
        # if we fail, we try the same with biggest of a different kind
        proposed_base_rid_orig = proposed_base_rid
        proposed_base_rid = max_rid(ipa_local_ranges, not primary) + delta
        if check_rid_base(ipa_local_ranges, proposed_base_rid, idrange.size):
            return True, proposed_base_rid
        else:
            # if it fails, we return both RID proposals for the range
            return False, f"{proposed_base_rid_orig} and {proposed_base_rid}"    

# Funtion to get maximum used primary or secondary RID
def max_rid(id_ranges: list[IDRange], primary: bool =True) -> int:
    max_rid = 0
    for range in id_ranges:

        # looking only for primary RIDs
        if primary:
            if not range.last_base_rid is None:
                if range.last_base_rid > max_rid:
                    max_rid = range.last_base_rid
        # looking only for secondary RIDs
        else:
            if not range.last_secondary_rid is None:
                if range.last_secondary_rid > max_rid:
                    max_rid = range.last_secondary_rid
            
    return max_rid

# Function to check if proposed RID overlaps with any other RID 'ranges'
def check_rid_base(id_ranges: list[IDRange], base: int, size: int) -> bool:
    end = base + size + 1

    # Checking sanity of RID range
    if base + size > 2147483647:
        return False
    if base < 1000:
        return False

    # Checking RID range overlaps
    for range in id_ranges:
        # we are interested only in ipa-local ranges
        if range.type != "ipa-local":
            continue
        
        # if there is no base rid set, there is no secondary base rid set, nothing to overlap with
        if range.base_rid is None:
            continue

        # checking for an overlap
        if not range_overlap_check(base, end, range.base_rid, range.last_base_rid):
            logger.debug(f"RID check failure: proposed pri {base} + {size}, intersects with {range.base_rid}-\
                    {range.last_base_rid} from {range.name}")
            return False
        
        # if there is no secondary base rid set, nothing to overlap with
        if range.secondary_base_rid is None:
            continue

        # if either start of end of the range fails iside existing range, or existing range is inside proposed one, we have an overlap
        if not range_overlap_check(base, end, range.secondary_base_rid, range.last_secondary_rid):
            logger.debug(f"RID check failure: proposed sec {base} + {size}, intersects with {range.secondary_base_rid}-\
                    {range.last_secondary_rid} from {range.name}")
            return False

    return True

# Function to get ranges that have either of the RID bases not set
def get_ranges_no_base(id_ranges: list[IDRange]) -> list[IDRange]:
    ipa_local_ranges = get_ipa_local_ranges(id_ranges)
    ranges_no_base = []
    for range in ipa_local_ranges:
        if range.base_rid is None or range.secondary_base_rid is None:
            ranges_no_base.append(range)
        
    return ranges_no_base

#endregion
"""
Working with IDentities out of range
"""
# region
# Function to get outofrange IDs into groups to create ranges
def group_identities_by_threshold(identities: list[IDentity], threshold: int) -> list[list[IDentity]]:
    groups : list[list[IDentity]]= []
    currentgroup : list[IDentity] = []
    if len(identities) == 0:
        return groups

    for i in range(len(identities) - 1):
        # add id to current group
        currentgroup.append(identities[i])
         
        # If the difference with the next one is greater than the threshold, start a new group
        if identities[i + 1].number - identities[i].number > threshold:
            groups.append(currentgroup)
            currentgroup = []

    # Add the last ID number to the last group
    currentgroup.append(identities[-1])
    groups.append(currentgroup)

    return groups

# Function to remove identities with numbers under 1000 (expects sorted list):
def separate_under1000(identities: list[IDentity]) -> tuple[list[IDentity],list[IDentity]]:
    for i in range(len(identities)):
        if identities[i].number >=1000:
            if i==0:
                # all ids are over 1000
                return [],identities
            else:
                return identities[:i],identities[i:]
    # no ids over 1000 found
    return identities,[]

# Function to get users from groups that are smaller then minimum range size
def separate_ranges_and_outliers(groups: list[list[IDentity]], minrangesize = int) -> tuple[list[list[IDentity]],list[list[IDentity]]]:
    outliers = []
    cleangroups = []
    for group in groups:
        # if group is smaller than minrangesize, add it's memebers to ourliers
        if group[-1].number - group[0].number + 1 < minrangesize :
            for identity in group:
                outliers.append(identity)
        # if the group is OK, add it to cleaned groups
        else:
            cleangroups.append(group)
    
    return outliers, cleangroups

# Function to round up range margins
def round_idrange(start: int, end: int) -> tuple[int,int]:
    # calculating power of the size
    sizepower = len(str(end - start + 1))
    # multiplier for the nearest rounded number
    multiplier = 10 ** (sizepower - 1)
    # getting rounded range margins
    rounded_start = (start // multiplier) * multiplier
    rounded_end = ((end + multiplier) // multiplier) * multiplier - 1

    return rounded_start, rounded_end

# Function to get a range name for proposal
def get_rangename_base(id_ranges: list[IDRange], counter: int = 1) -> str:
    base_name = ''
    # we want to use default range name as a base for new ranges
    for range in id_ranges:
        if range.base_rid == 1000:
            base_name = range.name
    
    # if we didn't find it, propose generic name
    if base_name == '': base_name = 'Auto_added_range'

    return base_name

# Function to get a new range name, we add the counter as 3-digit number extension and make sure it's unique
def get_rangename(id_ranges: list[IDRange], basename: str) -> str:
    counter = 1
    full_name = f"{basename}_{counter:03}"
    while any(id_range.name == full_name for id_range in id_ranges):
        counter += 1
        full_name = f"{basename}_{counter:03}"
    return full_name

# Function to try and create a new range from group
def propose_range(group:list[IDentity], id_ranges: list[IDRange], delta: int, basename: str, norounding: bool) -> IDRange:
    startid = group[0].number
    endid = group[-1].number

    logger.debug(f"Proposing a range for existing IDs out of ranges with start id {startid} and end id {endid}...")

    # creating new range
    newrange = IDRange()
    newrange.type = "ipa-local"
    newrange.name = get_rangename(id_ranges, basename)
    newrange.proposed = True
    newrange.suffix = id_ranges[0].suffix
    newrange.dn = f"cn={newrange.name},cn=ranges,cn=etc,{newrange.suffix}"

    if (norounding):
        newrange.first_id = startid
        newrange.last_id = endid
        newrange.size = newrange.last_id - newrange.first_id + 1
    else:
        # first trying to round up ranges to look pretty
        newrange.first_id, newrange.last_id = round_idrange(startid, endid)
        newrange.size = newrange.last_id - newrange.first_id + 1

    # if this creates an overlap, try without rounding
    if not newrange_overlap_check(id_ranges,newrange):
        newrange.first_id = startid
        newrange.last_id = endid
        newrange.size = newrange.last_id - newrange.first_id + 1
        # if we still failed, abandon idea
        if not newrange_overlap_check(id_ranges,newrange):
            logger.error("ERROR! Failed to create idrange for existing IDs out of ranges\
                          with start id {startid} and end id {endid}, it overlaps with existing range!")
            return None
    
    # creating RID bases
    ipa_local_ranges = get_ipa_local_ranges(id_ranges)

    result, proposed_base_rid = propose_rid_base(newrange, ipa_local_ranges, delta, True)
    if (result):
        newrange.base_rid = proposed_base_rid
        newrange.last_base_rid = proposed_base_rid + newrange.size
    else:
        # if this fails we print the warning
        logger.warning(f"Warning! Proposed base RIDs {proposed_base_rid} for new range start id {newrange.first_id} and \
end id {newrange.last_id} both failed, please adjust manually")
    

    result, proposed_secondary_base_rid = propose_rid_base(newrange, ipa_local_ranges, delta, False)
    if (result):
        newrange.secondary_base_rid = proposed_secondary_base_rid
        newrange.last_secondary_rid = proposed_secondary_base_rid + newrange.size
    else:
        # if this fails we print the warning
        logger.warning(f"Warning! Proposed secondary base RIDs {proposed_secondary_base_rid} for new range start id {newrange.first_id} and \
end id {newrange.last_id} both failed, please adjust manually")
        
    #print(f"{create_range_command(newrange)}")
    logger.debug(f"Proposed range: {newrange}")
    
    return newrange
#endregion