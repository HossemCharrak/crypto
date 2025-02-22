import re
from typing import List
import subprocess

# Path to the Perl file
perl_file = "gen-collision.pl"

# Run the Perl file and capture the output
out_perl = subprocess.run(["perl", perl_file], input=target, capture_output=True, text=True)

# Check if the Perl script executed successfully
if out_perl.returncode == 0:
    # Capture the output
    output = out_perl.stdout
    print("Perl script output:")
    print(output)
else:
    # Handle errors
    print("Perl script failed with error:")
    print(out_perl.stderr)

def extract_parentheses_numbers(text):
    # Find all numbers inside parentheses
    numbers = re.findall(r'\((\d+)\)', text)
    # Convert to integers
    return list(map(int, numbers))


payloads = extract_parentheses_numbers(out_perl)


def eliminate_common_leftmost_bytes(int_array: List[int]) -> List[str]:
    # Step 1: Convert integers to bytes
    # Determine the maximum number of bytes needed to represent the largest integer
    max_bytes = max((x.bit_length() + 7) // 8 for x in int_array)
    
    # Convert each integer to bytes with the same length (big-endian)
    bytes_array = [x.to_bytes(max_bytes, byteorder='big') for x in int_array]

    # Step 2: Find the longest common prefix (leftmost bytes)
    common_prefix = b""
    for i in range(max_bytes):
        # Get the i-th byte from the first element
        current_byte = bytes_array[0][i]
        
        # Check if all elements have the same byte at this position
        if all(b[i] == current_byte for b in bytes_array):
            common_prefix += bytes([current_byte])
        else:
            break

    # Step 3: Eliminate the common prefix from each bytes object
    result_bytes = [b[len(common_prefix):] for b in bytes_array]

    # Step 4: Convert the resulting bytes to hex strings
    result_hex = [b.hex() for b in result_bytes]

    return result_hex



result = eliminate_common_leftmost_bytes(payloads)
print(result)
