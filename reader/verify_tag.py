'''
Verifies the tag
'''

import argparse
import json
import struct
import traceback
import pickle

from Tag import Tag
from protocols.Tracker import Tracker
from protocols.StepAuth import StepAuth
from protocols.Baseline import Baseline
from protocols.RFChain import RFChain

parser = argparse.ArgumentParser(description='Updates the tag secret')
parser.add_argument('-f', dest='keyfile', type=str, nargs=1,
                    help='Keyfile', required=True)
parser.add_argument('-s', dest='scheme', type=str, nargs=1,
                    help='Select scheme', choices=["tracker", "baseline", "stepauth", "rfchain"], required=True)
parser.add_argument('-r', dest='reader', type=int, nargs=1,
                    help='Specify a reader', required=False)
parser.add_argument('-t', dest='tag', type=int, nargs=1,
                    help='Specify a tag', required=True)

args = parser.parse_args()
keyfile = args.keyfile[0]
scheme = args.scheme[0]
tag = args.tag[0]

try:
    data = json.load(open(keyfile))
    with open("%s/%d.tag" % (data["dir"], tag), 'rb') as tagfile:    
        tag = pickle.load(tagfile)
        # StepAuth
        if scheme == "stepauth":
            reader = args.reader[0]
            StepAuth.verify_tag(reader, tag, data)
        # AES encrypted tag secret baseline
        elif scheme == "baseline":
            Baseline.verify_tag(tag, data)
        # Tracker
        elif scheme == "tracker":
            Tracker.verify_tag(tag, data)
        # RF-chain
        elif scheme == "rfchain":
            RFChain.verify_tag(tag, data)
            None
        else:
            raise(ValueError('Mode not supported!'))
except FileNotFoundError as e:
    print("File not found! Make sure that the parent directory exists: %s" % (e))
except json.JSONDecodeError as e:
    print("File is not in JSON format! Error: %s" % e)
except pickle.PickleError as e:
    print("Could not unpickle tag object!\nError: %s" % (e))
except Exception as e:
    print("Unknown exception: %s" % (e))
    traceback.print_exc()
