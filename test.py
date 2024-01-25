import yara
import pefile

def scan_with_yara(file_path, yara_rules):
    # Compile Yara rules
    rules = yara.compile(filepath=yara_rules)

    # Scan the file
    matches = rules.match(file_path)
    
    return matches

def find_pe_section_name(pe, rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.SizeOfRawData:
            return section.Name.decode().rstrip('\x00')
    return None

def main(file_path, yara_rules):
    # Scan the file with Yara
    matches = scan_with_yara(file_path, yara_rules)

    # Parse the file with pefile
    pe = pefile.PE(file_path)

    # For each Yara match, find its PE section name
    for match in matches:
        for m in match.strings:
            for i in m.instances:
                rva = pe.get_rva_from_offset(i.offset)
                section_name = find_pe_section_name(pe, rva)
                print(f"Matched string ({match.rule}/{m.identifier}={i.matched_data})at RVA 0x{rva:02x} is in section {section_name}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <path_to_executable> <path_to_yara_rules>")
    else:
        main(sys.argv[1], sys.argv[2])
