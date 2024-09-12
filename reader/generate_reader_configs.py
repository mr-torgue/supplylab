'''
python generate_reader_configs.py [-n curveSizeBytesber of readers] [-m mode] [-d dir] [-p pathfile]
generates n configuration files and headers according to mode m
pathfile describes the set of valid paths:
* 1 valid path per line
* using indices [0..n>

TODO: 
1) Better checks for valid paths
2) Reader ID
'''

import argparse
import os
import shutil

from protocols.Tracker import Tracker
from protocols.StepAuth import StepAuth
from protocols.Baseline import Baseline
from protocols.RFChain import RFChain

parser = argparse.ArgumentParser(description='Generate keys and header files')
parser.add_argument('-n', dest='nr_readers', type=int, nargs=1,
                    help='Number of readers', required=True)
parser.add_argument('-s', dest='scheme', type=str, nargs=1,
                    help='Select scheme', choices=["tracker", "baseline", "stepauth", "rfchain"], required=True)
parser.add_argument('-d', dest='dir', type=str, nargs=1,
                    help='Output directory', required=True)
parser.add_argument('-p', dest='pathfile', type=str, nargs=1,
                    help='Pathfile with valid paths', required=False)

args = parser.parse_args()
nr_readers = args.nr_readers[0]
scheme  = args.scheme[0]
dir = args.dir[0]

# determine valid paths, if available
valid_paths = []
try:
    with open(args.pathfile[0]) as file:
        for line in file:
            readers = re.findall(r'\d+', line)
            path = []
            for reader in readers:
                if int(reader) < 0 or int(reader) >= nr_readers:
                    raise ValueError("Paths can only use readers in range 0..nr_readers")
                path.append(int(reader))
            valid_paths.append(path)
except Exception as e:
    if scheme == "tracker":
        print("A path file is required for tracker!\nExiting.")
        exit()

try:
    if os.path.exists(dir):
        shutil.rmtree(dir)
    os.mkdir(dir)
    print("Generating %d secrets for scheme %s" % (nr_readers, scheme))
    # StepAuth
    if scheme == "stepauth":
       StepAuth.generate_reader_configs(nr_readers, valid_paths, dir)
    # AES encrypted tag secret baseline
    elif scheme == "baseline":
        Baseline.generate_reader_configs(nr_readers, valid_paths, dir)
    # Tracker
    elif scheme == "tracker":
        Tracker.generate_reader_configs(nr_readers, valid_paths, dir)
    # RF-chain
    elif scheme == "rfchain":
        RFChain.generate_reader_configs(nr_readers, valid_paths, dir)
    else:
        raise(ValueError('Mode not supported!'))
except FileExistsError:
    print("Directory already exists: %s" % (e))
except FileNotFoundError as e:
    print("File not found! Make sure that the parent directory exists: %s" % (e))