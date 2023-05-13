import sys

from aerleon import aclgen

rc = 1
try:
    aclgen.EntryPoint()
    rc = 0
except Exception as e:
    print('Error: %s' % e, file=sys.stderr)
sys.exit(rc)
