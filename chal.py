from functools import reduce
import re
from typing import List
import subprocess
import hashlib
from pwn import remote  # Install with: pip install pwntools
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Connect to the server
server = remote("hashes.ctf.ingeniums.club", 1337, ssl=True)

# Retrieve the target SHA-256 hash of the secret
target = server.recvline().decode().strip()
print(f"Target: {target}")

# Path to the Perl file
perl_file = "gen-collision.pl"

# Run the Perl file with the target as a command-line argument
out_perl = subprocess.run(["perl", perl_file, target], capture_output=True, text=True)

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
result = reduce(xor, payloadsy)
print(f"Result: {result}")

# Function to extract valid s values without byte loss
def extract_all_s_values(int_array: List[int], target_hash: str) -> List[str]:
    s_values = []

    for number in int_array:
        # Convert number to bytes (ensure leading zeros are kept)
        max_bytes = (number.bit_length() + 7) // 8
        a_bytes = number.to_bytes(max_bytes, 'big')

        # Ensure secret is exactly 16 bytes
        if len(a_bytes) < 16:
            continue  # Ignore invalid cases

        secret_guess = a_bytes[:16]  # First 16 bytes
        s_guess = a_bytes[16:]       # Remaining bytes (could be empty)

        # Compute SHA-256 hash of extracted secret
        computed_hash = hashlib.sha256(secret_guess).hexdigest()

        # Verify if the extracted secret matches the known SHA-256 hash
        if computed_hash == target_hash:
            print(f"Valid secret found: {secret_guess.hex()}")
            print(f"Extracted s: {s_guess.hex() if s_guess else 'empty'}")
            s_values.append(s_guess.hex())  # Store s as hex

    return s_values

# Get all valid s values
s_list = extract_all_s_values(payloads, target)
print(f"Extracted s values: {s_list}")

# Submit payloads to the server
for payload in s_list:
    if payload:  # Skip empty payloads
        server.sendlineafter(b"Enter a payload as hex (q to exit):", payload.encode())
        print(f"Sent payload: {payload}")

# Send 'q' to finish
server.sendlineafter(b"Enter a payload as hex (q to exit):", b"q")

# Receive the flag
flag = server.recvall().decode()
print(f"Flag: {flag}")
