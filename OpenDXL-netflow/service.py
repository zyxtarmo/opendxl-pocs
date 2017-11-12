#!/usr/bin/env python2

import os
import sys
import datetime
import time
import re
import nfdump

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.callbacks import EventCallback
from common import *

clientPath = os.path.dirname(os.path.realpath(__file__))


def netflowV4CB(ip4):


def netflowV6CB(ip6):


class firewallV4CB(EventCallback):

  def on_event(self, event):
    print(event.destination_topic, event.source_client_id, event.source_broker_id, event.message_type, re.sub(r"(?m)[\x00\n\r]+", "", event.payload.decode()))
    return


class firewallV6CB(EventCallback):

  def on_event(self, event):
    print(event.destination_topic, event.source_client_id, event.source_broker_id, event.message_type, re.sub(r"(?m)[\x00\n\r]+", "", event.payload.decode()))
    return

if __name__ == '__main__':

  config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

  with DxlClient(config) as client:      
    client.connect()
    client.add_event_callback("feed/ipv4/bad", netflowV4CB())
    client.add_event_callback("feed/ipv6/bad", netflowV6CB())

    try:
      while 1:
        time.sleep(0.1)
    except (KeyboardInterrupt, EOFError) as e:
      sys.exit(0)
