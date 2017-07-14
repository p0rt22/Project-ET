#!/usr/bin/python
import os, sys

if os.getuid() != 0:
	print 'Run install.py as root'
	sys.exit()

else:
	pass

try:
	import pip

except ImportError:
	os.system('sudo apt-get install python-pip')
	import pip

pip.main(['install', '--upgrade', 'pip'])
pip.main(['install', '-r', 'required.txt'])
sys.exit()