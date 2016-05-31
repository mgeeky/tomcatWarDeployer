#!/usr/bin/python

import mechanize
import os
import sys
import optparse




def options():
    usage = '%prog [options]'
    parser = optparse.OptionParser(usage=usage)

    return parser

def main():
    parser = options()
    opts, args = parser.parse_args()

if __name__ == '__main__':
    main()
