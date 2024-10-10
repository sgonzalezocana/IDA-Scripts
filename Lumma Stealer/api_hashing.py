import idautils
import pefile

def hash_algorithm(api_name: bytes, seed: int) -> int:
    counter = -1
    hash = seed
    api_name_wrap = api_name
    while api_name_wrap[counter + 1] != 0: 
        counter += 1

    val = 0x01000193
    not_val = ~val
    if counter >= 0:  
        for i in range(len(api_name.decode('latin-1'))-1):
            v7 = api_name_wrap[i]  
            op1 = (v7 & hash) & 0xFFFFFFFF
            op2 = hash + v7
            op3 = op1 * 2
            op4 = op2 - op3
            op5 = ~op4 & 0xFFFFFFFF
            op6 = (val & op5) & 0xFFFFFFFF
            op7 = (op4 & not_val) & 0xFFFFFFFF 
            op8 = (op6 * op7) & 0xFFFFFFFF 
            op9 = (val & op4) & 0xFFFFFFFF
            op10 = (val | op4) & 0xFFFFFFFF
            op11 = (op9 * op10) & 0xFFFFFFFF
            hash = (op11 + op8) & 0xFFFFFFFF
    return hash

def resolve_hash(hash_to_search):
    try:
        lib_names = ["ntdll.dll", 'kernel32.dll', 'winhttp.dll', 'user32.dll']
        pe = None
        for lib in lib_names:
            lib_full_path = os.path.join("C:\\Windows\\System32" , lib)
            try:
                pe = pefile.PE(lib_full_path)
            except:
                print(f"Unable to load {lib_full_path}")
            if pe:
                try:
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        try:
                            hashed_name = hash_algorithm(exp.name + b'\x00', seed = 0xFB520141)
                            if hash_to_search == hashed_name:
                                return exp.name
                        except:
                            pass
                except:
                    pass
        return None
    except Exception as err:
        print(str(err))


def main():
    api_hashing_addr = 0x998BE0
    hashes = []
    for xref in idautils.XrefsTo(api_hashing_addr):
        get_push_addr = prev_head(prev_head(xref.frm))
        line_disassembled = generate_disasm_line(get_push_addr, flags=0)
        if "push" in line_disassembled:
            hash = get_operand_value(get_push_addr, 0)
            hashes.append(hash)

    for _hash_ in hashes:
        resolved = None
        resolved = resolve_hash(_hash_)
        if resolved:
            print(str(hex(_hash_)) + ' -> ' + str(resolved.decode('latin-1')))

if __name__ == '__main__':
    main()
