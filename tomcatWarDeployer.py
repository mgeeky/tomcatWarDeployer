#!/usr/bin/python

import mechanize
import os
import sys
import optparse




def options():
    print '\nApache Tomcat auto WAR deploy & launch tool\nMariusz B. / MGeeky \'16\n' 

    usage = '%prog [options] server'
    parser = optparse.OptionParser(usage=usage)

    general = optparse.OptionGroup(parser, 'General options')
    general.add_option('-v', '--verbose', dest='verbose', help='Verbose mode.')
    general.add_option('-U', '--user', metavar='USER', dest='user', default='tomcat', help='Tomcat Manager Web Application HTTP Auth username. Default="tomcat"')
    general.add_option('-P', '--pass', metavar='PASS', dest='pass', default='tomcat', help='Tomcat Manager Web Application HTTP Auth password. Default="tomcat"')
    parser.add_option_group(general)

    payload = optparse.OptionGroup(parser, 'Payload options')
    payload.add_option('-H', '--host', metavar='RHOST', dest='host', default='0.0.0.0', help='Remote host for reverse tcp payload connection. When specified, RPORT must be specified too. Otherwise, bind tcp payload will be deployed, binded to 0.0.0.0 on target server.')
    payload.add_option('-p', '--port', metavar='RPORT', dest='port', default='4444', help='Remote port for the reverse tcp payload. When specified, RHOST must be specified too. Otherwise, bind tcp payload will be deployed, listening on port 4444')
    payload.add_option('-u', '--url', metavar='URL', dest='url', default='/manager/', help='Apache Tomcat management console URL. Default: /manager/')
    parser.add_option('-f', '--file', metavar='WARFILE', dest='file', help='Custom WAR file to deploy. By default the script will generate own WAR file on-the-fly.')


    return parser

def main():
    parser = options()
    opts, args = parser.parse_args()

if __name__ == '__main__':
    main()
