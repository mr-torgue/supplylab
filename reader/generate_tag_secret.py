'''
python generate_tag_secret.py [-f "keyfile"] [-m mode] [-p path]
generates n configuration files and headers according to mode m
'''
import argparse
import json
import traceback

from protocols.Tracker import Tracker
from protocols.StepAuth import StepAuth
from protocols.Baseline import Baseline
from protocols.RFChain import RFChain\


parser = argparse.ArgumentParser(description='Generates a tag secret')
parser.add_argument('-f', dest='keyfile', type=str, nargs=1,
                    help='Keyfile', required=True)
parser.add_argument('-s', dest='scheme', type=str, nargs=1,
                    help='Select scheme', choices=["tracker", "baseline", "stepauth", "rfchain"], required=True)
parser.add_argument('-p', dest='path', type=int, nargs="+",
                    help='Specify a path', required=False)
parser.add_argument('-t', dest='tag', type=int, nargs=1,
                    help='Tag identifier', required=True)
parser.add_argument('-r', dest='reader', type=int, nargs=1,
                    help='Specify a reader', required=False)

args = parser.parse_args()
keyfile = args.keyfile[0]
scheme = args.scheme[0]
path = args.path
tag = args.tag[0]

try:
    data = json.load(open(keyfile))

    # check if a path is provided
    if path:
        for reader in path:
            if reader >= len(data["readers"]) or reader < 0:
                print("Reader %d does not exist! Only specify numbers between 0 and %d!\nExiting." % (reader, len(data["readers"])))
                exit(0)
        print("Generating secret for path %s using keyfile %s in scheme %s" % (path, keyfile, scheme))
    elif scheme == "stepauth":
        print("StepAuth needs a path!\nExiting.")
        exit()
    else:
        print("Generating secret using keyfile %s in scheme %s" % (keyfile, scheme))

    # StepAuth
    if scheme == "stepauth":
        StepAuth.generate_tag_secret(tag, path, data)
    # AES encrypted tag secret baseline
    elif scheme == "baseline":
        Baseline.generate_tag_secret(tag, data)
    # Tracker
    elif scheme == "tracker":
        Tracker.generate_tag_secret(tag, data)
    # RF-chain
    elif scheme == "rfchain":
        try:
            reader = args.reader[0]
        except Exception as e:
            print("RF-Chain needs a reader ID to initialize the tag: %s" % (e))
        RFChain.generate_tag_secret(reader, tag, data)
    else:
        raise(ValueError('Mode not supported!'))
except FileNotFoundError as e:
    print("File not found! Make sure that the parent directory exists: %s" % (e))
except json.JSONDecodeError as e:
    print("File is not in JSON format! Error: %s" % e)
except Exception as e:
    print("Unknown exception: %s" % (e))
    traceback.print_exc()