#!/usr/bin/env python2

import os
import sys
import argparse
import json
from socket import gethostname
from pygtail import Pygtail
from time import sleep
from IPy import IP

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from common import *
from dxlclient.message import Message, Event

config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)
client = DxlClient(config)
client.connect()

def sendData(data):
  try:
    v = IP(data).version()
  except Exception as e:
    print("Error in '%s': %s" % (data, str(e)))
    return
  if v == 4:
    evt = Event('/feed/bad/ipv4')
  if v == 6:
    evt = Event('/feed/bad/ipv6')
  evt.payload = str(data).encode()
  client.send_event(evt)

def procLine(line):
  sendData(str(line).rstrip())

if __name__ == '__main__':

  parser = argparse.ArgumentParser(description='Honeypot log tailer script')
  parser.add_argument('-f', '--filename', dest='filename', default='', help='File to follow')
  args = parser.parse_args()

  if not os.access(args.filename, os.R_OK):
    print("Error: file '%s' is not accessible" % (args.filename))
    sys.exit(1)

  try:
    while 1:
      for line in Pygtail(args.filename, paranoid=True):
        procLine(line)
      sleep(0.1)
  except (KeyboardInterrupt, SystemExit):
      print("Abort tailing of %s" % args.filename)
      sys.exit(0)
