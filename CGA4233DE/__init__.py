import calendar
import hashlib
import sys
import time
from requests import Session

LOGIN = '/api/v1/session/login'
LOGOUT = '/api/v1/session/logout'
SESSION_INIT = '/api/v1/session/menu'
FIREWALL = '/api/v1/firewall'
GET_CALLS = '/api/v1/phone_calllog/1,2/CallTbl'
CSRF_TOKEN = '/api/v1/wifi/1/SSIDEnable'
GET_CONNECTED_DEVICES = '/api/v1/sta_lan_status'

class CGA4233DE:
	def __init__(self, addr, username, password):
		self.addr = addr
		self.username = username
		self.password = password
		self.headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-CSRF-TOKEN': '', 'X-Requested-With': 'XMLHttpRequest', 'Referer': addr}

	def get(self, endpoint, timestamp = False):
		if(timestamp):
			now = calendar.timegm(time.gmtime())
			return self.session.get(self.addr + endpoint + '?_=' + str(now), headers=self.headers).json()
		else:
			return self.session.get(self.addr + endpoint, headers=self.headers).json()

	def post(self, endpoint, data = {}, csrf = True):
		if(csrf):
			self.get_csrf_token()
		return self.session.post(self.addr + endpoint, headers=self.headers, data=data)

	def login(self):
		self.session = Session()
		response = self.post(LOGIN, data={'username': self.username, 'password': 'seeksalthash'}, csrf=False).json()
		if(response['error'] != 'ok'):
			if(response['message'] == 'MSG_LOGIN_150'):
				print("Another user is currently signed in. Retrying ...")
				response = self.post(LOGIN, data={'username': self.username, 'password': 'seeksalthash', 'logout': 'true'}, csrf=False).json()
			else:
				if(response['error'] == 'error'):
					if(response['message'] == 'MSG_LOGIN_1'):
						print('Invalid username')
					else:
						print('Unknown error.')
						print(response)
					sys.exit(1)

		a = hashlib.pbkdf2_hmac('sha256', bytes(self.password, 'utf-8'), bytes(response['salt'], 'utf-8'), 1000).hex()[:32]
		b = hashlib.pbkdf2_hmac('sha256', bytes(a, 'utf-8'), bytes(response['saltwebui'], 'utf-8'), 1000).hex()[:32]

		response = self.post(LOGIN, data={'username': self.username, 'password': b}, csrf = False).json()
		if(response['error'] == 'error'):
			if(response['message'] == 'MSG_LOGIN_2'):
				print('Invalid password')
			else:
				print('Unknown error.')
				print(response)
			sys.exit(1)

		response = self.get(SESSION_INIT, timestamp=True)
		assert(response['error'] == 'ok')

	def logout(self):
		self.post(LOGOUT)

	def get_csrf_token(self):
		response = self.get(CSRF_TOKEN, timestamp=True)
		if 'error' in response and response['error'] == 'error':
			print("CSRF response: {}".format(response['message']))
			sys.exit(1)
		else:
			self.headers['X-CSRF-TOKEN'] = response['token']
		return self.headers['X-CSRF-TOKEN']

	def get_firewall(self):
		req = self.get(FIREWALL, True)
		return req['data']['FirewallLevel'] == 'on'

	def set_firewall(self, turn_on):
		if(turn_on):
			self.post(FIREWALL, data={'FirewallLevel': 'on', 'FirewallLevelV6': 'on'})
		else:
			self.post(FIREWALL, data={'FirewallLevel': 'off', 'FirewallLevelV6': 'off'})

	def get_calls(self):
		return self.get(GET_CALLS, timestamp=True)['0']['data']['CallTbl']

	def get_connected_devices(self):
		return self.get(GET_CONNECTED_DEVICES)['data']['dhcpTbl']
