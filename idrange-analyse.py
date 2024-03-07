import sys

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

    def count(self):
        self.last_id = self.first_id + self.size - 1
        if self.type == "ipa-local":
            self.last_base_rid = self.base_rid + self.size if self.base_rid is not None else None
            self.last_secondary_rid = self.secondary_base_rid + self.size if self.secondary_base_rid is not None else None

    def __repr__(self):
        return f"IDRange(range_name='{self.range_name}', type={self.type}, size={self.size}, first_id={self.first_id}, " \
               f"base_rid={self.base_rid}, secondary_base_rid={self.secondary_base_rid})"

# Function to generate LDAPseach commands
def generate_ldapsearch_commands(id_ranges_all, object_class, id, cn):
    id_ranges = []
    # we need to look only for ipa-local ranges
    for id_range in id_ranges_all:
        if id_range.type == "ipa-local":
            id_ranges.append(id_range)

    if len(id_ranges)==0:
        return ("No ipa-local ranges found!")

    suffix = id_ranges[0].suffix
    command = f"# ldapsearch -xLLL -D \"cn=Directory Manager\" -W -b \"cn={cn},cn=accounts,{suffix}\" \"(&(objectClass=posix{object_class})(|"
    filter = ""

    for i in range(len(id_ranges)+1):
        if i == 0:
            start_condition = f"(uidNumber>=1)"
        else:
            start_condition = f"(uidNumber>={id_ranges[i-1].last_id + 1})"

        if i < len(id_ranges):
            end_condition = f"(uidNumber<={id_ranges[i].first_id - 1})"
        else:
            end_condition = "(uidNumber<=2147483647)"
        
        filter += f"(&{start_condition}{end_condition})"

    command += f"{filter}))\" dn {id}Number"

    return command

# Function to detect ID range overlaps, expecting ranges sorted by first_id
def detect_range_overlaps(id_ranges):
    temp_id = 1000
    temp_name = "default system local range (IDs lower 1000 are reserved for system and service users and groups)"

    for i in range(len(id_ranges)):
        current_range = id_ranges[i]
        if current_range.first_id <= temp_id:
            print("WARNING! Range {} overlaps with {}!".format(current_range.range_name, temp_name))
        temp_id = current_range.last_id
        temp_name = current_range.range_name

def propose_rid_ranges(id_ranges, delta=100000):
    ipa_local_ranges = get_ipa_local_ranges(id_ranges)

    for i in range(len(ipa_local_ranges)):
        current_range = ipa_local_ranges[i]
        proposed_base_rid = 0
        proposed_secondary_base_rid = 0

        # Calculate proposed base RID and secondary base RID
        if current_range.base_rid is None:
            proposed_base_rid = max_rid(ipa_local_ranges, True) + delta
            if check_rid_base(ipa_local_ranges, proposed_base_rid, current_range.size):
                current_range.base_rid = proposed_base_rid
                current_range.last_base_rid = proposed_base_rid + current_range.size
            else:
                print(f"Warning: Proposed base RID = {proposed_base_rid} for {current_range.range_name} failed, please adjust manually")
                continue

        if current_range.secondary_base_rid is None:
            proposed_secondary_base_rid = max_rid(ipa_local_ranges, False) + delta
            if check_rid_base(ipa_local_ranges, proposed_secondary_base_rid, current_range.size):
                current_range.secondary_base_rid = proposed_secondary_base_rid
                current_range.last_secondary_rid = proposed_secondary_base_rid + current_range.size
            else:
                print(f"Warning: Proposed secondary base RID = {proposed_secondary_base_rid} for {current_range.range_name} failed, please adjust manually")
                continue

        # Genertate an LDAP command if we changed something successfully
        if proposed_base_rid > 0 or proposed_secondary_base_rid > 0:
            print(f"\n{current_range.range_name}: proposed values: Base RID = {current_range.base_rid}, Secondary Base RID = {current_range.secondary_base_rid}.")
            print("\nLDAP command to apply would look like: ")
            print(f"~~~\n# ldapmodify -D \"cn=Directory Manager\" -W -x << EOF\n{current_range.dn}\
                  \nchangetype: modify\nadd: ipabaserid\nipabaserid: {current_range.base_rid}\n-\
                  \nadd: ipasecondarybaserid\nipasecondarybaserid: {current_range.secondary_base_rid}\nEOF\n~~~")

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

        if primary:
            if not current_range.last_base_rid is None:
                if current_range.last_base_rid > max_rid:
                    max_rid = current_range.last_base_rid
        else:
            if not current_range.last_secondary_rid is None:
                if current_range.last_secondary_rid > max_rid:
                    max_rid = current_range.last_secondary_rid
            
    return max_rid

# Function to check if proposed RID overlaps with any other RID 'ranges'
def check_rid_base(id_ranges, base, size):
    end = base + size + 1

    # Checking sanity of RID range
    if base + size > 2147483647:
        #print (f"{base} is over the top")
        return False
    if base < 1000:
        #print (f"{base} is too low")
        return False

    # Checking RID range overlaps
    for i in range(len(id_ranges)):
        current_range = id_ranges[i]

        # we are interested only in ipa-local ranges
        if current_range.type != "ipa-local":
            #print ("not ipa-local")
            continue
        
        # if there is no base rid set, there is no secondary base rid set, nothing to overlap with
        if current_range.base_rid is None:
            continue

        # if either start of end of the range fails iside existing range, we have an overlap
        if (base >= current_range.base_rid and base <= current_range.last_base_rid) or \
            (end >= current_range.base_rid and end <= current_range.last_base_rid):
            #print(f"something wrong: proposed pri {base} + {size}, intersects with {current_range.base_rid}-{current_range.last_base_rid} from {current_range.range_name}")
            return False
        
        # if there is no secondary base rid set, nothing to overlap with
        if current_range.secondary_base_rid is None:
            continue

        if (base >= current_range.secondary_base_rid and base <= current_range.last_secondary_rid) or \
            (end >= current_range.secondary_base_rid and end <= current_range.last_secondary_rid):
            #print(f"something wrong: proposed sec {base} + {size}, intersects with {current_range.secondary_base_rid}-{current_range.last_secondary_rid} from {current_range.range_name}")
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
def parse_input(input_data):
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
            elif key == "ipabaseid" or key == "ipaBaseID":
                current_range.first_id = int(value)
            elif key == "ipaidrangesize" or key == "ipaIDRangeSize":
                current_range.size = int(value)
            elif key == "ipabaserid" or key == "ipaBaseRID":
                current_range.base_rid = int(value)
            elif key == "ipasecondarybaserid" or key == "ipaSecondaryBaseRID":
                current_range.secondary_base_rid = int(value)
            elif key == "iparangetype" or key == "ipaRangeType":
                current_range.type = value

    if current_range:
        id_ranges.append(current_range)

    return id_ranges

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

# Read input from stdin if provided, otherwise use the sample input data
if not sys.stdin.isatty():
    input_data = sys.stdin.read()
else:
    print('No data came from STDIN!\nUsage: python3 printranges.py < ipa_idrange-find_--all_--raw_ouput')
    exit(1)

# Parse the input data and create IDRange instances
id_ranges = parse_input(input_data)

# calculate all the attributes
for id_range in id_ranges:
    id_range.count()

# Sort the list of IDRange instances by the "First ID" attribute
id_ranges.sort(key=lambda x: x.first_id)

# Draw the table with current ranges
draw_ascii_table(id_ranges)

# Detect if there are any overlaps
detect_range_overlaps(id_ranges)

# Generate LDAP Search commands for out of the ranges
print("\nLDAP Search Commands for Users outside of ranges:")
print (generate_ldapsearch_commands(id_ranges, "account", "uid", "users"))

print("\nLDAP Search Commands for Groups outside of ranges:")
print(generate_ldapsearch_commands(id_ranges, "group", "gid", "groups"))

if (check_rid_bases(id_ranges)):
    print("\nProposition for missing RID bases:")
    propose_rid_ranges(id_ranges, delta=100000)
else:
    print("\nAll RID bases are in order.")