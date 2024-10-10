import base64
import idautils

def decrypt_string(cadena):
    if not cadena:
        return None
    decoded = base64.b64decode(cadena)
    from_the_byte_32 = decoded[32:]
    first_32_bytes_of_decoded = decoded[:32]
    counter = 0
    decrypted_str = ""
    try:
        while(len(decoded)):
            try:
                decrypted_str += chr((first_32_bytes_of_decoded[counter & 31] | from_the_byte_32[counter])
                            & (~first_32_bytes_of_decoded[counter & 31] | ~from_the_byte_32[counter]))
                counter +=1
            except:
                break
        return decrypted_str
    except:
        return None

def main():
    decrypt_strings_fnc_addr = 0x00440160
    encrypted_string_addr = None
    for xref in idautils.XrefsTo(decrypt_strings_fnc_addr):
        get_push_addr = prev_head(xref.frm)
        line_disassembled = generate_disasm_line(get_push_addr, flags=0)
        if "push" in line_disassembled:
            encrypted_string_addr = get_operand_value(get_push_addr, 0)

        index = 0
        if encrypted_string_addr:
            while True:
                string_ptr = idc.get_wide_dword(encrypted_string_addr + index * 4)
    
                if string_ptr == 0:
                    print(f"No more strings available")
                    break
        
                buffer_to_decrypt = idc.get_strlit_contents(string_ptr, -1, idc.STRTYPE_C)
                decrypted_string = decrypt_string(buffer_to_decrypt)
                if decrypted_string:
                    print(str(buffer_to_decrypt.decode('latin-1')) + ' ----> ' + decrypted_string )
                index += 1
            break


if __name__ == '__main__':
    main()
