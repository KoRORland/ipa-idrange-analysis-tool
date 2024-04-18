import sys
import argparse

# Class for ID Range
class IDRange:

    def __init__(self):
        self.range_name = None
        self.size = None
        self.first_id = None
        self.base_rid = None
        self.secondary_base_rid = None
        self.suffix = None
        self.type = None
        self.last_id = None
        self.last_base_rid = None
        self.last_secondary_rid = None
        self.dn = None
        self.proposed = False

    def count(self):
        self.last_id = self.first_id + self.size - 1
        if self.type == "ipa-local":
            self.last_base_rid = self.base_rid + self.size if self.base_rid is not None else None
            self.last_secondary_rid = self.secondary_base_rid + self.size if self.secondary_base_rid is not None else None

    def __repr__(self):
        return f"IDRange(range_name='{self.range_name}', type={self.type}, size={self.size}, first_id={self.first_id}, " \
               f"base_rid={self.base_rid}, secondary_base_rid={self.secondary_base_rid})"
    
# Class for ID entity 
class IDentity:
    def __init__(self):
        self.dn = None
        self.name = None
        self.user = None
        self.idnumber = None

    def __repr__(self):
        if self.user:
            return f"IDentity:user(username='{self.name}', uid='{self.idnumber}', dn='{self.idnumber}')"
        else:
            return f"IDentity:group(groupname='{self.name}', gid='{self.idnumber}', dn='{self.idnumber}')"

# Function to generate LDAPseach commands
def generate_ldapsearch_commands(id_ranges_all, object_class, id, cn):
    
    # we need to look only for ipa-local ranges
    id_ranges = get_ipa_local_ranges(id_ranges_all)
    
    if len(id_ranges)==0:
        return ("No ipa-local ranges found!")

    # creating command prefix
    suffix = id_ranges[0].suffix
    command = f"# ldapsearch -xLLL -D \"cn=Directory Manager\" -W -b \"cn={cn},cn=accounts,{suffix}\" \"(&(objectClass=posix{object_class})(|"
    filter = ""

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

    # adding command suffix
    command += f"{filter}))\" dn {id}Number >> outofranges.ldif"

    return command

# Function to detect ID range overlaps, expecting ranges sorted by first_id
def detect_range_overlaps(id_ranges):
    temp_id = 1000
    temp_name = "default system local range (IDs lower 1000 are reserved for system and service users and groups)"
    err = False

    for i in range(len(id_ranges)):
        current_range = id_ranges[i]
        if current_range.first_id <= temp_id:
            print("\nWARNING! Range {} overlaps with {}!".format(current_range.range_name, temp_name))
            err = True
        temp_id = current_range.last_id
        temp_name = current_range.range_name
    if (not err):
        print("\nAll ranges seem to be in order.")

# Function to propose RID bases
def propose_rid_ranges(id_ranges, delta=100000):
    # delta repersents for far we start new base off existing range, used in order to allow for future expansion of existing ranges up to [delta] IDs
    ipa_local_ranges = get_ipa_local_ranges(id_ranges)

    for i in range(len(ipa_local_ranges)):
        current_range = ipa_local_ranges[i]
        proposed_base_rid = 0
        proposed_secondary_base_rid = 0

        # Calculate proposed base RID and secondary base RID
        if current_range.base_rid is None:
            # we are getting the biggest primary base RID + size + delta and try if it's a viable option
            proposed_base_rid = max_rid(ipa_local_ranges, True) + delta
            if check_rid_base(ipa_local_ranges, proposed_base_rid, current_range.size):
                current_range.base_rid = proposed_base_rid
                current_range.last_base_rid = proposed_base_rid + current_range.size
            else:
                # if we fail, we try the same with biggest secondary base RID
                proposed_base_rid_orig = proposed_base_rid
                proposed_base_rid = max_rid(ipa_local_ranges, False) + delta
                if check_rid_base(ipa_local_ranges, proposed_base_rid, current_range.size):
                    current_range.base_rid = proposed_base_rid
                    current_range.last_base_rid = proposed_base_rid + current_range.size
                else:
                    # if it fails, we print the warning and abandon the RID proposal for the range
                    print(f"Warning: Proposed base RIDs {proposed_base_rid_orig} and {proposed_base_rid} for {current_range.range_name} \
                        both failed, please adjust manually")
                    continue

        if current_range.secondary_base_rid is None:
            # we are getting the biggest secondary RID + size + delta and try if it's a viable option
            proposed_secondary_base_rid = max_rid(ipa_local_ranges, False) + delta
            if check_rid_base(ipa_local_ranges, proposed_secondary_base_rid, current_range.size):
                current_range.secondary_base_rid = proposed_secondary_base_rid
                current_range.last_secondary_rid = proposed_secondary_base_rid + current_range.size
            else:
                # if it fails, it might be because the base RID we've set up earlier, so we check if changing to primary base RID helps
                proposed_secondary_base_rid_orig = proposed_secondary_base_rid
                proposed_secondary_base_rid = max_rid(ipa_local_ranges, True) + delta
                if check_rid_base(ipa_local_ranges, proposed_secondary_base_rid, current_range.size):
                    current_range.secondary_base_rid = proposed_secondary_base_rid
                    current_range.last_secondary_rid = proposed_secondary_base_rid + current_range.size
                else:
                    # if this fails too, we print the warning and abandon the idea
                    print(f"Warning: Proposed secondary base RIDs {proposed_secondary_base_rid_orig} and {proposed_secondary_base_rid} \
                        for {current_range.range_name} failed, please adjust manually")
                    continue

        # Genertate an LDAP command if we changed something successfully
        if proposed_base_rid > 0 or proposed_secondary_base_rid > 0:
            print(f"\n{current_range.range_name}: proposed values: Base RID = {current_range.base_rid}, Secondary Base RID = {current_range.secondary_base_rid}.")
            print("\nLDAP command to apply would look like: ")
            print(f"~~~\
                  \n# ldapmodify -D \"cn=Directory Manager\" -W -x << EOF\
                  \n{current_range.dn}\
                  \nchangetype: modify\
                  \nadd: ipabaserid\
                  \nipabaserid: {current_range.base_rid}\
                  \n-\
                  \nadd: ipasecondarybaserid\
                  \nipasecondarybaserid: {current_range.secondary_base_rid}\
                  \nEOF\
                  \n~~~")

# Function to get ipa-local ranges only
def get_ipa_local_ranges(id_ranges):
    ipa_local_ranges = []

    for i in range(len(id_ranges)):
        if id_ranges[i].type == "ipa-local":
            ipa_local_ranges.append(id_ranges[i])

    return ipa_local_ranges

# Funtion to get maximum used primary or secondary RID
def max_rid(id_ranges, primary=True):
    max_rid = 0
    for i in range(len(id_ranges)):
        current_range = id_ranges[i]

        # looking only for primary RIDs
        if primary:
            if not current_range.last_base_rid is None:
                if current_range.last_base_rid > max_rid:
                    max_rid = current_range.last_base_rid
        # looking only for secondary RIDs
        else:
            if not current_range.last_secondary_rid is None:
                if current_range.last_secondary_rid > max_rid:
                    max_rid = current_range.last_secondary_rid
            
    return max_rid

# Function to check if proposed RID overlaps with any other RID 'ranges'
def check_rid_base(id_ranges, base, size, debug=False):
    end = base + size + 1

    # Checking sanity of RID range
    if base + size > 2147483647:
        return False
    if base < 1000:
        return False

    # Checking RID range overlaps
    for i in range(len(id_ranges)):
        current_range = id_ranges[i]

        # we are interested only in ipa-local ranges
        if current_range.type != "ipa-local":
            continue
        
        # if there is no base rid set, there is no secondary base rid set, nothing to overlap with
        if current_range.base_rid is None:
            continue

        # if either start of end of the range fails iside existing range, or existing range is inside proposed one, we have an overlap
        if (base >= current_range.base_rid and base <= current_range.last_base_rid) or \
            (end >= current_range.base_rid and end <= current_range.last_base_rid) or \
            (current_range.base_rid > base and current_range.base_rid < end):
            if (debug):
                print(f"RID check failure: proposed pri {base} + {size}, intersects with {current_range.base_rid}-\
                    {current_range.last_base_rid} from {current_range.range_name}")
            return False
        
        # if there is no secondary base rid set, nothing to overlap with
        if current_range.secondary_base_rid is None:
            continue

        # if either start of end of the range fails iside existing range, or existing range is inside proposed one, we have an overlap
        if (base >= current_range.secondary_base_rid and base <= current_range.last_secondary_rid) or \
            (end >= current_range.secondary_base_rid and end <= current_range.last_secondary_rid) or \
            (current_range.secondary_base_rid > base and current_range.secondary_base_rid < end):
            if (debug):
                print(f"RID check failure: proposed sec {base} + {size}, intersects with {current_range.secondary_base_rid}-\
                    {current_range.last_secondary_rid} from {current_range.range_name}")
            return False

    return True

# Function to check if there is any of the RID bases not set
def check_rid_bases(id_ranges):
    ipa_local_ranges = get_ipa_local_ranges(id_ranges)

    for i in range(len(ipa_local_ranges)):
        if ipa_local_ranges[i].base_rid is None or ipa_local_ranges[i].secondary_base_rid is None:
            return True
        
    return False

# Function to parse input data and create IDRange instances
def parse_idrange_input(input_data):
    id_ranges = []
    current_range = None

    for line in input_data.split('\n'):
        line = line.strip()

        if not line:
            continue
        if not ':' in line:
            continue

        if line.startswith("dn:"):
            if current_range:
                id_ranges.append(current_range)
            current_range = IDRange()
            current_range.dn = line

            # Extract the suffix from the DN line
            suffix_start = line.find("dc=")
            if suffix_start != -1:
                current_range.suffix = line[suffix_start:]

        # reading attributes
        else:
            key, value = line.split(": ", 1)
            if key == "cn":
                current_range.range_name = value
            elif key.lower() == "ipabaseid":
                current_range.first_id = int(value)
            elif key.lower() == "ipaidrangesize":
                current_range.size = int(value)
            elif key.lower() == "ipabaserid":
                current_range.base_rid = int(value)
            elif key.lower() == "ipasecondarybaserid":
                current_range.secondary_base_rid = int(value)
            elif key.lower() == "iparangetype":
                current_range.type = value

    if current_range:
        id_ranges.append(current_range)

    return id_ranges

# Function to parse out of range input data and create IDentities instances
def parse_outofrange_input(input_data):
    identities = []
    current_entity = None

    for line in input_data.split('\n'):
        line = line.strip()

        if not line:
            continue
        if not ':' in line:
            continue

        if line.startswith("dn:"):
            if current_entity:
                identities.append(current_entity)
            current_entity = IDentity()
            current_entity.dn = line

            # Extract the name from the DN line
            name_cn = line.split()[1].split(',')[0].split('=')
            current_entity.name = name_cn[1]

            # Set user flag
            if name_cn[0] == 'uid':
                current_entity.user = True
            else:
                current_entity.user = False

        # reading attributes
        else:
            key, value = line.split(": ", 1)
            if key.lower() == "gidnumber":
                current_entity.idnumber = int(value)
            elif key.lower() == "uidnumber":
                current_entity.idnumber = int(value)

    if current_entity:
        identities.append(current_entity)

    return identities

def group_identities_by_threshold(id_numbers, threshold):
    # Sort the list of ID numbers
    id_numbers.sort()

    # Initialize groups
    groups = []
    currentgroup = []
    # Iterate through the sorted list of ID numbers
    for i in range(len(id_numbers) - 1):
        # add id to current group
        currentgroup.append(id_numbers[i])
         
        # If the difference with the next one is greater than the threshold, start a new group
        if id_numbers[i + 1] - id_numbers[i] > threshold:
            groups.append(currentgroup)
            currentgroup = []

    # Add the last ID number to the last group
    currentgroup.append(id_numbers[-1])
    groups.append(currentgroup)

    return groups

# Function to draw a pretty table
def draw_ascii_table(id_ranges):
    # Calculate the maximum width required for each column including column names
    max_widths = {column: max(len(str(column)), max(len(str(getattr(id_range, column))) if getattr(id_range, column) is not None else 0 for id_range in id_ranges)) for column in ["range_name", "type", "size", "first_id", "last_id", "base_rid", "last_base_rid", "secondary_base_rid", "last_secondary_rid"]}

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

# Function to draw output headers
def print_header(text):
    horizontal_line = "-" * 80
    print(f"\n{horizontal_line}")
    print(text)
    print(horizontal_line)          

# function to read IDranges from stdin
def read_input_from_stdin():
    # Read input data from stdin
    input_data = sys.stdin.read()
    return input_data.strip()

# function to read data from file
def read_input_from_file(file_path):
    try:
        # Read input data from the file
        with open(file_path, 'r') as file:
            input_data = file.read()
            return input_data.strip()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to read file '{file_path}'.")
        print(e)
        sys.exit(1)

def main():
    range_data = ''

    # Create argument parser
    parser = argparse.ArgumentParser(description="Tool to process IPA ID ranges data")

    # Add optional arguments
    parser.add_argument('--ranges', type=str, metavar='idranges', \
                        help="Path to file containing ID ranges data - output of `ipa idrange-find --all --raw > idranges`")
    parser.add_argument('--ridoffset', type=int, default=100000, metavar=100000, \
                        help="Offset for a next base RID from previous RID range. Needed for future range size expansions. Have to be > 0")
    parser.add_argument('--outofrange', type=str, metavar='outofranges.ldif', \
                        help="Path to file for out of range users and groups, that we got from ldapsearches provided")
    parser.add_argument('--rangegap', type=int, default=200000, metavar=200000, \
                        help="Threshold for a gap between outofrange IDs to be considered a different range. Have to be > 0")
    parser.add_argument('--minrange', type=int, default=10, metavar=10, \
                        help="Minimal considered range size for outofrange IDs. All ranges lower than this number will be discarded and IDs will be listed to be moved. Have to be > 1")
    
    # Parse the command-line arguments
    args = parser.parse_args()

    # Check sanity of int values:
    if args.ridoffset < 0 or args.rangegap < 0 or args.minrange < 1:
        print ("\nERROR: attribute error!\n")
        parser.print_help()
        sys.exit(1)

    # Check input sources and read data accordingly
    if not sys.stdin.isatty():
        # Data is coming from stdin
        range_data = read_input_from_stdin()
    elif args.ranges is not None:
        # Data is provided via --ranges option
        range_data = read_input_from_file(args.ranges)
    else:
        # No input source provided, show usage instructions
        print ("\nERROR: no range input data found!")
        parser.print_usage()
        sys.exit(1)    

    # Parse the input data and create IDRange instances
    id_ranges = parse_idrange_input(range_data)

    if len(id_ranges) <= 1:
        # No valid range data provided, show usage instructions
        print ("\nERROR: no valid ranges in input data!")
        parser.print_usage()
        sys.exit(1)         

    # calculate all the attributes
    for id_range in id_ranges:
        id_range.count()

    # Sort the list of IDRange instances by the "First ID" attribute
    id_ranges.sort(key=lambda x: x.first_id)

    # Draw the table with current ranges
    draw_ascii_table(id_ranges)

    # Detect if there are any overlaps
    print_header("Range sanity check")
    detect_range_overlaps(id_ranges)

    # Propose RID bases if some are missing
    print_header("RID bases check")
    if (check_rid_bases(id_ranges)):
        print("\nProposition for missing RID bases:")
        propose_rid_ranges(id_ranges, args.ridoffset)
    else:
        print("\nAll RID bases are in order.\n")

    # If outofrange file path provided, read and process it
    if args.outofrange:
        outofrange_data = read_input_from_file(args.outofrange)
        # Process outofrange data
        # Parse the input data and create IDRange instances
        ids_outofrange = parse_outofrange_input(outofrange_data)
        # ids_outofrange.sort(key=lambda x: x.idnumber)

        id_numbers = [int(identity.idnumber) for identity in ids_outofrange]
        groups = group_identities_by_threshold(id_numbers, args.rangegap)

        print_header("IDranges for IDs out of ranges proposal")
        for group in groups:
            if len(group)>0: print (f"range: {group[0]}\t- {group[-1]};\tsize={group[-1]-group[0]+1}")
            else: print("empty group!!")
        print('\n\n')


    # If data is not provided, provide searches how to provide 
    else:
        # Generate LDAP Search commands for out of the ranges
        print_header("LDAP searches to detect IDs out of ranges")
        print("\nLDAP Search Commands for Users outside of ranges:")
        print(generate_ldapsearch_commands(id_ranges, "account", "uid", "users"))
        print("\nLDAP Search Commands for Groups outside of ranges:")
        print(generate_ldapsearch_commands(id_ranges, "group", "gid", "groups"))
        print("\nYou can provide the resulting file as --outofrange option to this tool to get advise on which ranges to create.\n")

if __name__ == "__main__":
    main()

