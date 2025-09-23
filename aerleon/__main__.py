import sys

from aerleon import aclgen

rc = 1
try:
    aclgen.EntryPoint()
    rc = 0
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
sys.exit(rc)
