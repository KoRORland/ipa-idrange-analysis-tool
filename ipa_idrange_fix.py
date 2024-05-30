"""Tool to analyze and fix IPA ID ranges"""
# Authors: Aleksandr Sharov <asharov@redhat.com>
#
# Copyright (C) 2024  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import logging
import ldap

from ipalib import api, errors
from ipapython.admintool import AdminTool
from ipapython.dn import DN
from ipapython import ipautil

logger = logging.getLogger(__name__)


class IDRange:
    """Class for ID range entity"""

    def __init__(self):
        self.name: str = None
        self.size: int = None
        self.first_id: int = None
        self.base_rid: int = None
        self.secondary_base_rid: int = None
        self.suffix: str = None
        self.type: str = None
        self.last_id: int = None
        self.last_base_rid: int = None
        self.last_secondary_rid: int = None
        self.dn: str = None

    def count(self):
        """Function to calculate last IDs for the range"""
        self.last_id = self.first_id + self.size - 1
        if self.type == "ipa-local":
            self.last_base_rid = (
                self.base_rid + self.size
                if self.base_rid is not None
                else None
            )
            self.last_secondary_rid = (
                self.secondary_base_rid + self.size
                if self.secondary_base_rid is not None
                else None
            )

    def __repr__(self):
        return f"IDRange(name='{self.name}',\
type={self.type}, \
size={self.size}, \
first_id={self.first_id}, \
base_rid={self.base_rid}, \
secondary_base_rid={self.secondary_base_rid})"

    def __eq__(self, other):
        return self.first_id == other.first_id


class IDentity:
    """Class for ID entity"""

    def __init__(self):
        self.dn: str = None
        self.name: str = None
        self.user: bool = None
        self.number: int = None

    def __repr__(self):
        if self.user:
            return (
                f"user(username='{self.name}', "
                f"uid={self.number}, "
                f"{self.dn})"
            )
        return (
            f"group(groupname='{self.name}', "
            f"gid={self.number}, "
            f"{self.dn})"
        )

    def __eq__(self, other):
        return self.number == other.number


class IPAIDRangeFix(AdminTool):
    """Tool to analyze and fix IPA ID ranges"""

    command_name = "ipa-idrange-fix"
    log_file_name = "/var/log/ipa-idrange-fix.log"
    usage = "%prog"
    description = "Analyze and fix IPA ID ranges"

    @classmethod
    def add_options(cls, parser, debug_option=False):
        super(IPAIDRangeFix, cls).add_options(parser)
        parser.add_option(
            "--ridoffset",
            dest="ridoffset",
            type=int,
            default=100000,
            metavar=100000,
            help="Offset for a next base RID from previous RID range. \
Needed for future range size expansions. Has to be > 0",
        )
        parser.add_option(
            "--rangegap",
            dest="rangegap",
            type=int,
            default=200000,
            metavar=200000,
            help="Threshold for a gap between outofrange IDs to be considered \
a different range. Has to be > 0",
        )
        parser.add_option(
            "--minrange",
            dest="minrange",
            type=int,
            default=10,
            metavar=10,
            help="Minimal considered range size for outofrange IDs.\
                All ranges lower than this number will be discarded and IDs \
will be listed to be moved. Has to be > 1",
        )
        parser.add_option(
            "--allowunder1000",
            dest="allowunder1000",
            action="store_true",
            default=False,
            help="Allow idranges to start below 1000. Be careful to not \
overlap IPA users/groups with existing system-local ones!",
        )
        parser.add_option(
            "--norounding",
            dest="norounding",
            action="store_true",
            default=False,
            help="Disable IDrange rounding attempt in order to get ranges \
exactly covering just IDs provided",
        )
        parser.add_option(
            "--unattended",
            dest="unattended",
            action="store_true",
            default=False,
            help="Automatically fix all range issues found without asking \
for confirmation",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.realm: str = None
        self.suffix: DN = None
        self.propositions_rid: list[IDRange] = []
        self.propositions_new: list[IDRange] = []
        self.outliers: list[IDentity] = []
        self.under1000: list[IDentity] = []
        self.id_ranges: list[IDRange] = []

    def validate_options(self, needs_root=True):
        # super(IPAIDRangeFix, self).validate_options(needs_root)
        super().validate_options(needs_root)

    def run(self):
        api.bootstrap(in_server=True)
        api.finalize()

        self.realm = api.env.realm
        self.suffix = ipautil.realm_to_suffix(self.realm)
        try:
            api.Backend.ldap2.connect()

            # Reading range data
            self.id_ranges = read_ranges(self.suffix)

            # Evaluating existing ranges, if something is off, exit
            if self.evaluate_ranges() > 0:
                return 1

            # reading out of range IDs
            ids_out_of_range = read_outofrange_identities(
                self.suffix, self.id_ranges
            )

            # Evaluating out of range IDs
            self.evaluate_identities(ids_out_of_range)

            # Print the propositions
            self.print_intentions()

            # If there are no propositions, we have nothing to do, exiting
            if (len(self.propositions_rid) == 0 and
                    len(self.propositions_new) == 0):
                logger.info("\nNo changes proposed, nothing to do.")
                return 0

            print("\nID ranges table after proposed changes:")
            draw_ascii_table(self.id_ranges)

            if self.options.unattended:
                logger.info(
                    "Unattended mode, proceeding with applying changes!"
                )
            else:
                response = ipautil.user_input('Enter "yes" to proceed')
                if response.lower() != "yes":
                    logger.info("Not proceeding.")
                    return 0
                logger.info("Proceeding.")

            # Applying changes
            for id_range in self.propositions_rid:
                apply_ridbases(id_range)

            for id_range in self.propositions_new:
                create_range(id_range)

            logger.info("All changes applied successfully!")

        finally:
            if api.Backend.ldap2.isconnected():
                api.Backend.ldap2.disconnect()

        return 0

    def evaluate_ranges(self) -> int:
        """Function to evaluate existing ID ranges"""
        if len(self.id_ranges) == 0:
            logger.info("No ID ranges found!")
            return 1

        draw_ascii_table(self.id_ranges)

        if not ranges_overlap_check(self.id_ranges):
            logger.error(
                "Ranges overlap detected, cannot proceed! Please adjust \
existing ranges manually."
            )
            return 1

        # Checking RID bases for existing ranges
        id_ranges_nobase = get_ranges_no_base(self.id_ranges)

        if len(id_ranges_nobase) > 0:
            logger.info(
                "Found %s ranges without base RIDs", len(id_ranges_nobase)
            )
            for id_range in id_ranges_nobase:
                logger.debug(
                    "Range %s has rid base %s and secondary rid base %s,",
                    id_range.name,
                    id_range.base_rid,
                    id_range.secondary_base_rid,
                )
            propose_rid_ranges(
                self.id_ranges,
                self.options.ridoffset,
                self.propositions_rid
            )
        else:
            logger.info(
                "All ID ranges have base RIDs set, RID adjustments are \
not needed."
            )
        return 0

    def evaluate_identities(self, ids_out_of_range: list[IDentity]) -> None:
        """Function to evaluate out of range IDs"""
        if len(ids_out_of_range) == 0:
            logger.info("No out of range IDs found!")
        else:
            logger.info(
                "Found overall %s IDs out of already set up ID ranges.",
                len(ids_out_of_range),
            )
            # ruling out IDs under 1000 if flag is not set
            if not self.options.allowunder1000:
                self.under1000, ids_out_of_range = separate_under1000(
                    ids_out_of_range
                )
                if len(self.under1000) > 0:
                    logger.info(
                        "Found IDs under 1000, which is not recommeneded \
(if you definitely need ranges proposed for those, use --allowunder1000):"
                    )
                    for identity in self.under1000:
                        logger.info("%s", identity)

            # Get initial divide of IDs into groups
            groups = group_identities_by_threshold(
                ids_out_of_range, self.options.rangegap
            )

            # Get outliers from too small groups and clean groups for
            # further processing
            self.outliers, cleangroups = separate_ranges_and_outliers(
                groups, self.options.minrange
            )

            # Print the outliers, they have to be moved manually
            if len(self.outliers) > 0:
                print()
                logger.info(
                    "Following identities are too far away from the \
others to get ranges (try adjusting --minrange, or moving them to already \
existing ranges):"
                )
                for identity in self.outliers:
                    logger.info("%s", identity)

            if len(cleangroups) > 0:
                # Get IDrange name base
                basename = get_rangename_base(self.id_ranges)

                # Create propositions for new ranges from groups
                for group in cleangroups:
                    newrange = propose_range(
                        group,
                        self.id_ranges,
                        self.options.ridoffset,
                        basename,
                        self.options.norounding,
                    )
                    if newrange is not None:
                        self.propositions_new.append(newrange)
                        self.id_ranges.append(newrange)
                        self.id_ranges.sort(key=lambda x: x.first_id)
            else:
                print()
                logger.info(
                    "No IDs fit for ID range to propose! Try tuning the \
parameters --minrange or --rangegap!"
                )

    def print_intentions(self) -> None:
        """Function to print out the summary of the proposed changes"""

        print("\n\n")
        logger.info("Summary:")

        if len(self.outliers) > 0:
            logger.info("Outlier IDs that are too far away to get a range:")
            for identity in self.outliers:
                logger.info("%s", identity)

        if self.options.allowunder1000:
            logger.info("IDs under 1000 were treated like normal IDs.")
        else:
            if len(self.under1000) > 0:
                logger.info("IDs under 1000:")
                for identity in self.under1000:
                    logger.info("%s", identity)
            else:
                logger.info("No IDs under 1000 found.")

        if len(self.propositions_rid) > 0:
            logger.info("Proposed changes to existing ranges:")
            for id_range in self.propositions_rid:
                logger.info(
                    "Range %s - base RID: %s, secondary base RID: %s",
                    id_range.name,
                    id_range.base_rid,
                    id_range.secondary_base_rid,
                )
        else:
            logger.info("No changes proposed for existing ranges.")

        if len(self.propositions_new) > 0:
            logger.info("Proposed new ranges:")
            for id_range in self.propositions_new:
                logger.info(
                    "Range %s - start ID: %s, end ID: %s, base RID: %s, \
secondary base RID: %s",
                    id_range.name,
                    id_range.first_id,
                    id_range.last_id,
                    id_range.base_rid,
                    id_range.secondary_base_rid,
                )
        else:
            logger.info("No new ranges proposed.")

# Working with output


# region
def draw_ascii_table(id_ranges: list[IDRange]) -> None:
    """Function to draw a table with ID ranges in ASCII"""
    # Calculate the maximum width required for each column using column names
    max_widths = {
        column: max(
            len(str(column)),
            max(
                (
                    len(str(getattr(id_range, column)))
                    if getattr(id_range, column) is not None
                    else 0
                )
                for id_range in id_ranges
            ),
        )
        for column in [
            "name",
            "type",
            "size",
            "first_id",
            "last_id",
            "base_rid",
            "last_base_rid",
            "secondary_base_rid",
            "last_secondary_rid",
        ]
    }

    # Draw the table header
    header = "| "
    for column, width in max_widths.items():
        header += f"{column.ljust(width)} | "
    horizontal_line = "-" * (len(header) - 1)
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
                # Adding the separator
                row += " " * (width + 1) + "| "
        print(row)
    print(horizontal_line)

# endregion

# Reading from LDAP


# region
def read_ranges(suffix) -> list[IDRange]:
    """Function to read ID ranges from LDAP"""
    try:
        ranges = api.Backend.ldap2.get_entries(
            DN(api.env.container_ranges, suffix),
            ldap.SCOPE_ONELEVEL,
            "(objectclass=ipaIDRange)",
        )
    except errors.NotFound:
        logger.error("LDAPError: No ranges found!")
    except errors.ExecutionError as e:
        logger.error("Exception while reading users: %s", e)
    id_ranges: IDRange = []

    for entry in ranges:
        sv = entry.single_value
        id_range = IDRange()
        id_range.name = sv.get("cn")
        id_range.size = int(sv.get("ipaidrangesize"))
        id_range.first_id = int(sv.get("ipabaseid"))
        id_range.base_rid = (
            int(sv.get("ipabaserid")) if sv.get("ipabaserid") else None
        )
        id_range.secondary_base_rid = (
            int(sv.get("ipasecondarybaserid"))
            if sv.get("ipasecondarybaserid")
            else None
        )
        id_range.suffix = suffix
        id_range.type = sv.get("iparangetype")
        id_range.dn = entry.dn

        id_range.count()
        logger.debug("ID range found: %s", id_range)

        id_ranges.append(id_range)

    id_ranges.sort(key=lambda x: x.first_id)
    return id_ranges


def read_outofrange_identities(suffix, id_ranges) -> list[IDentity]:
    """Function to read out of range users and groups from LDAP"""
    id_entities = []

    ldap_filter = get_outofrange_filter(id_ranges, "account", "uid")
    logger.debug("Searching users with filter: %s", ldap_filter)
    try:
        identities = api.Backend.ldap2.get_entries(
            DN(api.env.container_user, suffix),
            ldap.SCOPE_ONELEVEL,
            ldap_filter,
        )
        logger.info("Out of range users found: %s", len(identities))
        for entry in identities:
            id_entities.append(read_identity(entry, user=True))
    except errors.NotFound:
        logger.info("No out of range users found!")
    except errors.ExecutionError as e:
        logger.error("Exception while reading users: %s", e)

    ldap_filter = get_outofrange_filter(id_ranges, "group", "gid")
    logger.debug("Searching groups with filter: %s", ldap_filter)
    try:
        identities = api.Backend.ldap2.get_entries(
            DN(api.env.container_group, suffix),
            ldap.SCOPE_ONELEVEL,
            ldap_filter,
        )
        logger.info("Out of range groups found: %s", len(identities))
        for entry in identities:
            id_entities.append(read_identity(entry, user=False))
    except errors.NotFound:
        logger.info("No out of range groups found!")
    except errors.ExecutionError as e:
        logger.error("Exception while reading groups: %s", e)

    id_entities.sort(key=lambda x: x.number)

    return id_entities


def read_identity(ldapentry, user: bool = True) -> IDentity:
    """Function to convert LDAP entry to IDentity object"""
    sv = ldapentry.single_value
    id_entity = IDentity()
    id_entity.dn = ldapentry.dn
    id_entity.name = sv.get("cn")
    id_entity.number = (
        int(sv.get("uidNumber")) if user else int(sv.get("gidNumber"))
    )
    id_entity.user = user
    logger.debug("Out of range found: %s", id_entity)
    return id_entity


def get_outofrange_filter(
    id_ranges_all: list[IDRange], object_class: str, attr: str
) -> str:
    """Function to create LDAP filter for out of range users and groups"""
    # we need to look only for ipa-local ranges
    id_ranges = get_ipa_local_ranges(id_ranges_all)

    ldap_filter = f"(&(objectClass=posix{object_class})(|"

    # adding gaps in ranges to the filter
    for i in range(len(id_ranges) + 1):
        if i == 0:
            start_condition = f"({attr}Number>=1)"
        else:
            start_condition = f"({attr}Number>={id_ranges[i-1].last_id + 1})"

        if i < len(id_ranges):
            end_condition = f"({attr}Number<={id_ranges[i].first_id - 1})"
        else:
            end_condition = f"({attr}Number<=2147483647)"

        ldap_filter += f"(&{start_condition}{end_condition})"

    ldap_filter += "))"

    return ldap_filter


# endregion

# Writing to LDAP


# region
def apply_ridbases(id_range: IDRange) -> None:
    """Funtion to apply RID bases to the range in LDAP"""
    try:
        api.Backend.ldap2.modify_s(
            id_range.dn,
            [
                (ldap.MOD_ADD, "ipaBaseRID", str(id_range.base_rid)),
                (
                    ldap.MOD_ADD,
                    "ipaSecondaryBaseRID",
                    str(id_range.secondary_base_rid),
                ),
            ],
        )
        logger.info("RID bases updated for range %s", id_range.name)

    except ldap.CONSTRAINT_VIOLATION as e:
        logger.error("Failed to add RID bases to the range %s.", id_range.name)
        raise RuntimeError("Constraint violation.\n") from e

    except Exception as e:
        logger.error(
            "Exception while updating RID bases for range %s: %s",
            id_range.name,
            e,
        )
        raise RuntimeError("Failed to update RID bases.\n") from e


def create_range(id_range: IDRange) -> None:
    """Function to create a new range in LDAP"""
    try:
        logger.info("Creating range %s...", id_range.name)

        entry = api.Backend.ldap2.make_entry(
            DN(id_range.dn),
            objectclass=["ipaIDRange", "ipaDomainIDRange"],
            ipaidrangesize=[str(id_range.size)],
            ipabaseid=[str(id_range.first_id)],
            ipabaserid=[str(id_range.base_rid)],
            ipasecondarybaserid=[str(id_range.secondary_base_rid)],
            iparangetype=[id_range.type],
        )

        api.Backend.ldap2.add_entry(entry)
        logger.info("Range %s created successfully", id_range.name)
    except Exception as e:
        logger.error("Exception while creating range %s: %s", id_range.name, e)
        raise RuntimeError("Failed to create range.\n") from e


# endregion

# Working with ranges


# region
def get_ipa_local_ranges(id_ranges: list[IDRange]) -> list[IDRange]:
    """Function to get only ipa-local ranges from the list of ranges"""
    ipa_local_ranges = []

    for id_range in id_ranges:
        if id_range.type == "ipa-local":
            ipa_local_ranges.append(id_range)

    return ipa_local_ranges


def range_overlap_check(
    range1_start: int, range1_end: int, range2_start: int, range2_end: int
) -> bool:
    """Function to check if two ranges overlap"""
    return range1_start < range2_end or range1_end > range2_start


def range_overlap_check_idrange(range1: IDRange, range2: IDRange) -> bool:
    """Function to check if two ranges overlap"""
    return range_overlap_check(
        range1.first_id, range1.last_id, range2.first_id, range2.last_id)


def newrange_overlap_check(
    id_ranges: list[IDRange], newrange: IDRange
) -> bool:
    """Function to check if proposed range overlaps with existing ones"""
    for id_range in id_ranges:
        if not range_overlap_check_idrange(id_range, newrange):
            return False
    return True


def ranges_overlap_check(id_ranges: list[IDRange]) -> bool:
    """Function to check if any of the existing ranges overlap"""
    if len(id_ranges) < 2:
        return True
    for i in range(len(id_ranges) - 1):
        for j in range(i + 1, len(id_ranges)):
            if not range_overlap_check_idrange(id_ranges[i], id_ranges[j]):
                logger.error(
                    "Ranges %s and %s overlap!",
                    id_ranges[i].name,
                    id_ranges[j].name,
                )
                return False
    return True


# endregion

# Working with RID bases


# region
def propose_rid_ranges(
    id_ranges: list[IDRange], delta: int, propositions: list[IDRange]
) -> None:
    """
    Function to propose RID bases for ranges that don't have them set.

    - delta repersents for far we start new base off existing range,
    used in order to allow for future expansion of existing ranges up
    to [delta] IDs.
    """
    ipa_local_ranges = get_ipa_local_ranges(id_ranges)

    for id_range in ipa_local_ranges:
        proposed_base_rid = 0
        proposed_secondary_base_rid = 0

        # Calculate proposed base RID and secondary base RID
        if id_range.base_rid is None:
            result, proposed_base_rid = propose_rid_base(
                id_range, ipa_local_ranges, delta, True
            )
            if result:
                id_range.base_rid = proposed_base_rid
                id_range.last_base_rid = proposed_base_rid + id_range.size
            else:
                # if this fails too, we print the warning and abandon the idea
                logger.warning(
                    "Warning: Proposed base RIDs %s for %s both failed, \
please adjust manually",
                    proposed_base_rid,
                    id_range.name,
                )
                continue

        if id_range.secondary_base_rid is None:
            result, proposed_secondary_base_rid = propose_rid_base(
                id_range, ipa_local_ranges, delta, False
            )
            if result:
                id_range.secondary_base_rid = proposed_secondary_base_rid
                id_range.last_secondary_rid = (
                    proposed_secondary_base_rid + id_range.size
                )
            else:
                # if this fails too, we print the warning and abandon the idea
                logger.warning(
                    "Warning: Proposed secondary base RIDs %s for %s failed, \
please adjust manually",
                    proposed_secondary_base_rid,
                    id_range.name,
                )
                continue

        # Add range to the propositions if we changed something successfully
        if proposed_base_rid > 0 or proposed_secondary_base_rid > 0:
            logger.debug(
                "Proposed RIDs for range %s: pri %s, sec %s",
                id_range.name,
                proposed_base_rid,
                proposed_secondary_base_rid,
            )
            propositions.append(id_range)


# Function to propose base RID
def propose_rid_base(
    idrange: IDRange,
    ipa_local_ranges: list[IDRange],
    delta: int,
    primary: bool = True,
) -> tuple[bool, str]:
    """
    Function to propose a base RID for a range, primary or secondary.
    We are getting the biggest base RID + size + delta and try
    if it's a viable option, check same kind first, then the other.
    """
    proposed_base_rid = max_rid(ipa_local_ranges, primary) + delta
    if check_rid_base(ipa_local_ranges, proposed_base_rid, idrange.size):
        return True, proposed_base_rid

    # if we fail, we try the same with biggest of a different kind
    proposed_base_rid_orig = proposed_base_rid
    proposed_base_rid = max_rid(ipa_local_ranges, not primary) + delta
    if check_rid_base(ipa_local_ranges, proposed_base_rid, idrange.size):
        return True, proposed_base_rid

    # if it fails, we return both RID proposals for the range
    return False, f"{proposed_base_rid_orig} and {proposed_base_rid}"


def max_rid(id_ranges: list[IDRange], primary: bool = True) -> int:
    """Function to get maximum RID of primary or secondary RIDs"""
    maximum_rid = 0
    for id_range in id_ranges:

        # looking only for primary RIDs
        if primary:
            if id_range.last_base_rid is not None:
                maximum_rid = max(maximum_rid, id_range.last_base_rid)
        # looking only for secondary RIDs
        else:
            if id_range.last_secondary_rid is not None:
                maximum_rid = max(maximum_rid, id_range.last_secondary_rid)

    return maximum_rid


def check_rid_base(id_ranges: list[IDRange], base: int, size: int) -> bool:
    """Function to check if proposed RID base is viable"""
    end = base + size + 1

    # Checking sanity of RID range
    if base + size > 2147483647:
        return False
    if base < 1000:
        return False

    # Checking RID range overlaps
    for id_range in id_ranges:
        # we are interested only in ipa-local ranges
        if id_range.type != "ipa-local":
            continue

        # if there is no base rid set, there is no secondary base rid set,
        # so nothing to overlap with
        if id_range.base_rid is None:
            continue

        # checking for an overlap
        if not range_overlap_check(
            base, end, id_range.base_rid, id_range.last_base_rid
        ):
            logger.debug(
                "RID check failure: proposed Primary %s + %s, \
intersects with %s-%s from %s",
                base,
                size,
                id_range.base_rid,
                id_range.last_base_rid,
                id_range.name,
            )
            return False

        # if there is no secondary base rid set, nothing to overlap with
        if id_range.secondary_base_rid is None:
            continue

        # if either start of end of the range fails iside existing range,
        # or existing range is inside proposed one, we have an overlap
        if not range_overlap_check(
            base, end, id_range.secondary_base_rid, id_range.last_secondary_rid
        ):
            logger.debug(
                "RID check failure: proposed Secondary %s + %s, \
intersects with %s-%s from %s",
                base,
                size,
                id_range.secondary_base_rid,
                id_range.last_secondary_rid,
                id_range.name,
            )
            return False

    return True


def get_ranges_no_base(id_ranges: list[IDRange]) -> list[IDRange]:
    """Function to get ranges without either of base RIDs set"""
    ipa_local_ranges = get_ipa_local_ranges(id_ranges)
    ranges_no_base = []
    for id_range in ipa_local_ranges:
        if id_range.base_rid is None or id_range.secondary_base_rid is None:
            ranges_no_base.append(id_range)

    return ranges_no_base


# endregion
# Working with IDentities out of range


# region
def group_identities_by_threshold(
    identities: list[IDentity], threshold: int
) -> list[list[IDentity]]:
    """Function to group out of range IDs by threshold"""
    groups: list[list[IDentity]] = []
    currentgroup: list[IDentity] = []
    if len(identities) == 0:
        return groups

    for i in range(len(identities) - 1):
        # add id to current group
        currentgroup.append(identities[i])

        # If the difference with the next one is greater than the threshold,
        # start a new group
        if identities[i + 1].number - identities[i].number > threshold:
            groups.append(currentgroup)
            currentgroup = []

    # Add the last ID number to the last group
    currentgroup.append(identities[-1])
    groups.append(currentgroup)

    return groups


def separate_under1000(
    identities: list[IDentity],
) -> tuple[list[IDentity], list[IDentity]]:
    """Function to separate IDs under 1000, expects sorted list"""
    for i, identity in enumerate(identities):
        if identity.number >= 1000:
            return identities[:i], identities[i:]
    return identities, []


def separate_ranges_and_outliers(
    groups: list[list[IDentity]], minrangesize=int
) -> tuple[list[list[IDentity]], list[list[IDentity]]]:
    """Function to separate IDs into outliers and IDs that can get ranges"""
    outliers = []
    cleangroups = []
    for group in groups:
        # if group is smaller than minrangesize, add it's memebers to ourliers
        if group[-1].number - group[0].number + 1 < minrangesize:
            for identity in group:
                outliers.append(identity)
        # if the group is OK, add it to cleaned groups
        else:
            cleangroups.append(group)

    return outliers, cleangroups


def round_idrange(start: int, end: int) -> tuple[int, int]:
    """Function to round up range margins to look pretty"""
    # calculating power of the size
    sizepower = len(str(end - start + 1))
    # multiplier for the nearest rounded number
    multiplier = 10 ** (sizepower - 1)
    # getting rounded range margins
    rounded_start = (start // multiplier) * multiplier
    rounded_end = ((end + multiplier) // multiplier) * multiplier - 1

    return rounded_start, rounded_end


def get_rangename_base(id_ranges: list[IDRange]) -> str:
    """Function to get a base name for new range proposals"""
    base_name = ""
    # we want to use default range name as a base for new ranges
    for id_range in id_ranges:
        if id_range.base_rid == 1000:
            base_name = id_range.name

    # if we didn't find it, propose generic name
    if base_name == "":
        base_name = "Auto_added_range"

    return base_name


def get_rangename(id_ranges: list[IDRange], basename: str) -> str:
    """
    Function to get a new range name, we add the counter as 3-digit number
    extension and make sure it's unique
    """
    counter = 1
    full_name = f"{basename}_{counter:03}"
    while any(id_range.name == full_name for id_range in id_ranges):
        counter += 1
        full_name = f"{basename}_{counter:03}"
    return full_name


def propose_range(
    group: list[IDentity],
    id_ranges: list[IDRange],
    delta: int,
    basename: str,
    norounding: bool,
) -> IDRange:
    """Function to propose a new range for group of IDs out of ranges"""
    startid = group[0].number
    endid = group[-1].number

    logger.debug(
        "Proposing a range for existing IDs out of ranges with start id %s \
and end id %s...",
        startid,
        endid,
    )

    # creating new range
    newrange = IDRange()
    newrange.type = "ipa-local"
    newrange.name = get_rangename(id_ranges, basename)
    newrange.suffix = id_ranges[0].suffix
    newrange.dn = f"cn={newrange.name},cn=ranges,cn=etc,{newrange.suffix}"

    if norounding:
        newrange.first_id = startid
        newrange.last_id = endid
        newrange.size = newrange.last_id - newrange.first_id + 1
    else:
        # first trying to round up ranges to look pretty
        newrange.first_id, newrange.last_id = round_idrange(startid, endid)
        newrange.size = newrange.last_id - newrange.first_id + 1

    # if this creates an overlap, try without rounding
    if not newrange_overlap_check(id_ranges, newrange):
        newrange.first_id = startid
        newrange.last_id = endid
        newrange.size = newrange.last_id - newrange.first_id + 1
        # if we still failed, abandon idea
        if not newrange_overlap_check(id_ranges, newrange):
            logger.error(
                "ERROR! Failed to create idrange for existing IDs out of \
ranges with start id %s and end id %s, it overlaps with existing range!",
                startid,
                endid,
            )
            return None

    # creating RID bases
    ipa_local_ranges = get_ipa_local_ranges(id_ranges)

    result, proposed_base_rid = propose_rid_base(
        newrange, ipa_local_ranges, delta, True
    )
    if result:
        newrange.base_rid = proposed_base_rid
        newrange.last_base_rid = proposed_base_rid + newrange.size
    else:
        # if this fails we print the warning
        logger.warning(
            "Warning! Proposed base RIDs %s for new range start id %s and \
end id %s both failed, please adjust manually",
            proposed_base_rid,
            newrange.first_id,
            newrange.last_id,
        )

    result, proposed_secondary_base_rid = propose_rid_base(
        newrange, ipa_local_ranges, delta, False
    )
    if result:
        newrange.secondary_base_rid = proposed_secondary_base_rid
        newrange.last_secondary_rid = (
            proposed_secondary_base_rid + newrange.size
        )
    else:
        # if this fails we print the warning
        logger.warning(
            "Warning! Proposed secondary base RIDs %s for new range start id \
%s and end id %s both failed, please adjust manually",
            proposed_secondary_base_rid,
            newrange.first_id,
            newrange.last_id,
        )

    logger.debug("Proposed range: %s", newrange)
    return newrange


# endregion
