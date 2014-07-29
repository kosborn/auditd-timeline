import sqlite3, re, sys, os, yaml, binascii, logging



class auditdParse:
    def __init__(self):

        # include /etc/passwd and /etc/group
        self.importUsers = True

        # include ./commands.yaml for whitelist/blacklist commands
        self.addCommands = False

        # For debugging or general verbosity
        # ERROR = almost no output
        # WARN = simple error (such as undefined message type)
        # DEBUG = detailed messages with those errors
        self.log = logging.getLogger('simple_example')
        logging.basicConfig(format='%(levelname)s %(message)s')
        self.log.setLevel(logging.WARNING)


        self.prepData()


    def prepData(self):
        # Here is where we defined expected database & dictionary parameters
        # We define these and merge the actual messages just
        # in case they do not contain one of the parameters
        # It must be (expected[n] + message) or it will overwrite
        # Defined in yaml config file
        typeConf = open(os.path.dirname(__file__)+'/types.yaml','r').read()
        typeList = yaml.load(typeConf)
        self.expected, self.createDB, self.insertDB = {},{},{}

        for i in typeList['auditd'].keys():
            self.expected[i] = {k: None for k in typeList['auditd'][i]['parameters']}
            self.createDB[i] = 'CREATE TABLE '+str(i)+'('+', '.join(list(' '.join([key,value]) for key,value in typeList['auditd'][i]['parameters'].items()))+');'
            self.insertDB[i] = 'INSERT INTO '+str(i)+' VALUES(:'+', :'.join(typeList['auditd'][i]['parameters'].keys())+');'

        # Check to see if the sqlite db exists, create it otherwise
        if os.path.isfile('audit.db'):
            self.con = sqlite3.connect('audit.db')
            self.cur = self.con.cursor()
        else:
            self.con = sqlite3.connect('audit.db')
            self.cur = self.con.cursor()
            # thanks to code above, tables are dynamically generated from the yaml config
            self.cur.executescript(' '.join(self.createDB.values()))
            self.con.commit()

        # import user/group IDs
        if self.importUsers:
            try:
                users = [dict(items.groupdict().items()+{'list':'0'}.items()) for items in re.finditer(r'^(?P<name>\w+):[^:]*:(?P<uid>\w+):',open('/etc/passwd','r').read(),re.M)]
                self.cur.executemany(self.insertDB['users'],users)
            except Exception as message:
                self.log.debug(users)
                self.log.debug(self.insertDB['users'])
                self.log.debug("Error! %s",message)
            try:
                groups = [dict(items.groupdict().items()+{'list':'0'}.items()) for items in re.finditer(r'^(?P<name>\w+):[^:]*:(?P<gid>\w+):',open('/etc/group','r').read(),re.M)]
                self.cur.executemany(self.insertDB['groups'],groups)
            except Exception as message:
                self.log.debug(groups)
                self.log.debug(self.insertDB['groups'])
                self.log.debug("Error! %s",message)

        if self.addCommands:
            try:
                # Create command list 
                commandConf = open('commands.yaml','r').read()
                commandList = yaml.load(commandConf)
                for catname in commandList['commands']:
                    for subname in commandList['commands'][catname]:
                        commandInsert = commandList['commands'][catname][subname]
                        commandInsert.update({catname:subname})
                        commandInsert = dict({'username':None,'groupname':None}.items()+commandInsert.items())
                        if catname == 'username':
                            cat = 'users'
                        elif catname == 'groupname':
                            cat = 'groups'
                        updateUser = 'UPDATE '+cat+' SET list = :type WHERE name = :subname'
                        obj = []
                        for exe in commandInsert['exe']:
                            t = commandInsert
                            t['exe'] = exe
                            obj.append(t)
                        self.cur.executemany(self.insertDB['commands'],obj)
                        self.cur.execute(updateUser,{'type':commandInsert['type'],'subname':subname})
            except Exception as error:
                self.log.critical('Failed to create command list. %s',error)

    def parse(self,auditFile):
        for line in open(auditFile,'r').readlines():
            message = self.parseLine(line)
            if message:
                self.insertType(message)

        self.con.commit()
        self.con.close()


    def parseLine(self, line):
        if line.strip():
            try:
                message={x: y for(x, y) in re.findall('([a-z0-9]+)=([^ ]+)+',line)}
                # Normalize strings/quotes
                for attrs in message:
                    if re.match(r'a[0-9]+',attrs) and message['type'] == 'EXECVE' and not re.match(r'^"[^"]*"$',message[attrs]):
                        message[attrs] = binascii.unhexlify(message[attrs].strip())
                    elif re.match(r'^"[^"]*"$',message[attrs]):
                        message[attrs] =  re.match(r'^"(.+)"\n?$',message[attrs]).groups()[0]
                
                if message['type'] in self.expected.keys():
                    message['aid'] = re.match('audit\([^:]+:([^)]+)\)',message['msg']).groups()[0]
                    message['timestamp'] = re.match('audit\(([^.]+).+\)',message['msg']).groups()[0]
                else:
                    # Since this is likely to happen a lot, don't print this message by default
                    self.log.debug("Unknown type: %s",message['type'])
            except Exception as error:
                self.log.critical("Parsing error: %s",error)

            return message
        else:
            return False

    def insertType(self,message):
        atype = False
        try:
            atype = message['type']
            message = dict(self.expected[atype].items()+message.items())
        except:
            self.log.debug("Could not set type on message: %s", message)
            return False

        # Since EXECVE contains items we want (parameters) in a0, a1, a2, etc
        # formatted, we must group them into a single string to avoid creating
        # many columns in the SQL database
        if atype == "EXECVE":
            # for some reason sometimes argc can be NoneType
            argc = int(message['argc']) if message['argc'] is not None else 0
            tmp={}
            counter=0
            # Merge all a[0-9] together. We could probably regex this isntead
            try:
                while counter < argc:
                    # Sometimes an argument is missing or on the next line
                    # We need to handle this if it's on the next line somehow
                    try:
                        tmp[counter] = message['a'+str(counter)]
                    except Exception as error:
                        # Sometimes we receive multiple EXECVE
                        # with varying argc, which throws an error
                        # http://www.redhat.com/archives/linux-audit/2009-March/msg00026.html
                        # it is safe to ignore
                        self.log.debug("Duplicate EXECVE records - safe to ignore. %s",error)

                    counter += 1
                message['string'] = ' '.join(tmp.values())
                message['argdata'] = str(tmp)
                message['bin'] = tmp[0]
            except Exception as error:
                self.log.critical("Failed to import execve. %s",error)

        try:
            self.cur.execute(self.insertDB[atype],message) 
        except Exception as error:
            self.log.critical("Could not save to database. %s",error)



"""
    def commandList(self):
        if os.path.isfile(os.path.dirname(__file__)+'/commands.yaml'):
            commandList = open(os.path.dirname(__file__)+'/commands.yaml','r').read()
            commandList = yaml.load(typeConf)

"""

