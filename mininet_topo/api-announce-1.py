#!/usr/bin/env python

import sys
import time

messages = [
	'announce route 1.1.0.0/24 next-hop 101.1.101.1',
	'announce route 1.1.0.0/25 next-hop 101.1.101.1',
	'withdraw route 1.1.0.0/24',
	'withdraw route 1.1.0.0/25 next-hop 0.0.0.0',
]

while messages:
	message = messages.pop(0)
	sys.stdout.write(message + '\n')
	sys.stdout.flush()
	time.sleep(3)

try:
	now = time.time()
	while True and time.time() < now + 5:
		line = sys.stdin.readline().strip()
		if not line or 'shutdown' in line:
			break
		time.sleep(1)
except IOError:
	pass
