import os

# - 16-byte hex string such as 03adc37285fc61e0253ad6dfa8ab4df2 (but like don't use that obviously)
# - make like this:
#
# import os
# print(os.urandom(16).hex())
TOKEN = bytes.fromhex(os.environ["AUTH_TOKEN"])
