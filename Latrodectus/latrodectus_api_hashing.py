import idautils
import pefile
from arc4 import ARC4

def init_seed():
    final_buff = []
    v2, counter, result = 0,256,0
    while counter > 0:
        result = (v2 << 24) & 0xFFFFFFFF
        v5 = 8
        while v5 > 0:
            is_negative = (result & 0x80000000) != 0
            if not is_negative:
                result = (result * 2) & 0xFFFFFFFF
            else:
                result = ((2 * result) ^ 0x4C11DB7) & 0xFFFFFFFF
            v5 -= 1
        v2 += 1
        counter -= 1
        bytes_obtained = integer_to_bytes(result)
        for i in bytes_obtained:
            final_buff.append(i)
    return final_buff

def api_hash_algorithm(api_name, seed): #CRC 32 Algorithm
    api_name_bytes = api_name.encode('utf-8')
    counter = 0
    eax = 0xFFFFFFFF
    for i in range(len(api_name_bytes)):
        ecx = (eax >> 24)
        ecx = (ecx ^ api_name_bytes[i]) & 0xFF
        eax = (eax << 8) & 0xFFFFFFFF
        value = int.from_bytes(bytes(seed[ecx * 4:ecx * 4 + 4]), byteorder='little')
        eax = (eax ^ value) & 0xFFFFFFFF
        counter += 1
    hash_val = ~eax & 0xFFFFFFFF
    return hash_val

def generate_key(xor_val): 
    v3 = [0]*6
    counter = 0
    v3[0] = 173491804 #Hardcoded values in the sample
    v3[1] = 911791983
    v3[2] = 1618407304
    v3[3] = 3495145762
    v3[4] = 1165994125
    bytes_ = integer_list_to_bytes(v3)
    while counter < 20:
        bytes_[counter] ^= 0xD7
        counter += 1

    counter = 0
    final_key = [0] * 20
    while counter < 20:
        final_key[counter] = bytes_[counter] ^ xor_val
        counter += 1

    return final_key

def transform_hash(buff): 
    current_pos = len(buff) - 2
    counter = len(buff) - 1
    while counter > 0:
        buff[current_pos] = (buff[current_pos] - buff[current_pos + 1]) & 0xFF
        current_pos -= 1
        counter -= 1
    current_pos = 0
    counter = len(buff) - 1
    while counter > 0:
        buff[current_pos] = (buff[current_pos] - buff[current_pos + 1]) & 0xFF
        current_pos += 1
        counter -= 1
    return buff

def transform_decrypted_buff(buff):
    pos = len(buff) - 2
    counter = len(buff) - 1
    while counter > 0:
        buff[pos] = (buff[pos] - buff[pos + 1]) & 0xFF
        pos -= 1
        counter -= 1
    result = 0
    counter = len(buff) - 1
    while counter > 0:
        buff[result] = (buff[result] - buff[result + 1]) & 0xFF
        result += 1
        counter -= 1
    return buff

def integer_to_bytes(integer):
    byte_array = bytearray()
    byte_array.extend(struct.pack('<I', integer))
    return byte_array

def pack_bytes(byte_array):
    packed = struct.pack('>BBBB', *byte_array)
    return int.from_bytes(packed, 'little')

def integer_list_to_bytes(key):
    byte_array = bytearray()
    for dw in key:
        byte_array.extend(integer_to_bytes(dw))
    return list(byte_array)


def get_api_hash(hash_to_search):
    PATH_TO_SEARCH = "C:\\Windows\\System32"
    lib_name = ["ntdll.dll", 'kernel32.dll', 'ws2_32.dll', 'user32.dll', 'advapi32.dll']
    seed = init_seed()
    pe = None
    for d in lib_name:
        path_to_lib = os.path.join(PATH_TO_SEARCH, d)
        try:
            pe = pefile.PE(path_to_lib)
        except:
            print(f"Unable to load {path_to_lib}")

        if pe:
            try:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    try:
                        api_name = exp.name.decode('latin-1')
                        hashed_ = api_hash_algorithm(api_name.lower(), seed)
                        if hash_to_search == hashed_:
                            return api_name, d
                    except:
                        pass
            except:
                pass
    return None, None


def check_prev_values(addr):
    hash = None
    hash_value = None
    xor_val = None
    get_prev_line = addr
    lines_counter = 0
    while lines_counter < 10:
        get_prev_line = prev_head(get_prev_line)
        line_disassembled = generate_disasm_line(get_prev_line, flags=0)
        if "push" in line_disassembled:
            hash = get_operand_value(get_prev_line, 0)
            if hash > 0xFF:
                hash_value = hash
            else:
                xor_val = hash
        if hash_value and xor_val:
            break


    if hash_value and xor_val:
        return hash_value, xor_val
    else:
        return None, None

def main():

    hash_and_xor_val = {}
    rc4_func_addr = 0x00334323 #rc4 func address
    for xref in idautils.XrefsTo(rc4_func_addr):
        hash_val, xor_value = None, None
        hash_val, xor_value = check_prev_values(xref.frm)

        if hash_val and xor_value:
            hash_and_xor_val[hash_val] = xor_value
         
    for hash, xor_val_ in hash_and_xor_val.items():
        resolved, rc4, rc4_key, library = None, None, None, None
        rc4_key= generate_key(xor_val_)
        rc4 = ARC4(bytes(rc4_key))
        transformed_hash = transform_hash(list(integer_to_bytes(hash)))
        decrypted_hash = rc4.decrypt(bytes(transformed_hash))
        transformed_decrypted_hash = transform_decrypted_buff(list(decrypted_hash))
        packed_bytes = pack_bytes(transformed_decrypted_hash)
        resolved, library = get_api_hash(packed_bytes)
        if resolved:
            print(f'{library} : {hex(hash)}  ->  {resolved}')


if __name__ == '__main__':
    main()

