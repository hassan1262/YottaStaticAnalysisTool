import sys
import argparse
from detection import *

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', action='store', dest='dir', help="Directory to analyse")
    parser.add_argument('--plain', action='store_true', dest='plain', help="No color in output")
    results = parser.parse_args()

    if results.dir is not None:
        
        sys.setrecursionlimit(1000000)

        print("\n{}Analyzing '{}' source code{}".format('' if results.plain else '\033[1m', results.dir, '' if results.plain else '\033[0m'))

        if os.path.isfile(results.dir):
            analysis(results.dir, results.plain)
        else:
            recursive(results.dir, 0, results.plain)
        scanresults()

    else:
        parser.print_help()