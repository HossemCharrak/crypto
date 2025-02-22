import re
from typing import List
import subprocess
from pwn import remote  # Install with: pip install pwntools

# Connect to the server
server = remote("hashes.ctf.ingeniums.club", 1337, ssl=True)

# Retrieve the target
target = server.recvline().decode().strip()
print(f"Target: {target}")

# Path to the Perl file
perl_file = "gen-collision.pl"

# Run the Perl file with the target as input and capture the output
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
    exit(1)

# Extract payloads from the Perl script's output
def extract_parentheses_numbers(text):
    # Find all numbers inside parentheses
    numbers = re.findall(r'\((\d+)\)', text)
    # Convert to integers
    return list(map(int, numbers))

payloads = extract_parentheses_numbers(output)
print(f"Payloads: {payloads}")

# Eliminate common leftmost bytes and convert to hex
def eliminate_common_leftmost_bytes(int_array: List[int]) -> List[str]:
    # Step 1: Convert integers to bytes
    max_bytes = max((x.bit_length() + 7) // 8 for x in int_array)
    bytes_array = [x.to_bytes(max_bytes, byteorder='big') for x in int_array]

    # Step 2: Find the longest common prefix (leftmost bytes)
    common_prefix = b""
    for i in range(max_bytes):
        current_byte = bytes_array[0][i]
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
print(f"Processed payloads: {result}")

# Submit payloads to the server
for payload in result:
    server.sendlineafter(b"Enter a payload as hex (q to exit):", payload.encode())
    print(f"Sent payload: {payload}")

# Send 'q' to finish
server.sendlineafter(b"Enter a payload as hex (q to exit):", b"q")

# Receive the flag
flag = server.recvall().decode()
print(f"Flag: {flag}")