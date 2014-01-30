from auditdParse import auditdParse
import sys

test = auditdParse()
test.parse(str(sys.argv[1]))
