import re

# Load file content
with open("/mnt/data/free_flags.txt", "r") as file:
    content = file.read()

# Regex to match the valid flag pattern
pattern = r'flag\{[0-9a-f]{32}\}'
valid_flags = re.findall(pattern, content)

valid_flags
