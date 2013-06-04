#!/usr/bin/python -u

import sys
import os

print "Content-type: text/plain\n\n";
for param in os.environ.keys():
  print "%20s %s" % (param,os.environ[param])


length = int(os.environ['CONTENT_LENGTH'])

#query = self.rfile.read(length)


#sys.stdin.close()

a = sys.stdin.read(length)

print a


print "done\n";



