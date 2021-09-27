#!/usr/bin/env python3
from CGA4233DE import CGA4233DE
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-a', '--address', type=str, default='http://192.168.0.1')
parser.add_argument('-u', '--user', type=str, default='admin')
parser.add_argument('password', type=str)
args = parser.parse_args()

router = CGA4233DE(args.address, args.user, args.password)
router.login()

router.set_firewall(False)
print("Firewall active: " + str(router.get_firewall()))

router.logout()
