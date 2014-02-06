import sqlite3, re, sys, os, yaml, binascii



class auditdParse:
	def __init__(self):
		# For debugging or general verbosity
		# 0 = almost no output
		# 1 = simple error (such as undefined message type)
		# 2 = detailed messages with those errors
		self.verboseLevel=0

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
		try:
			users = [dict(items.groupdict().items()+{'list':'0'}.items()) for items in re.finditer(r'^(?P<name>\w+):[^:]*:(?P<uid>\w+):',open('/etc/passwd','r').read(),re.M)]
			print users
			self.cur.executemany(self.insertDB['users'],users)
		except Exception as message:
			print users
			print self.insertDB['users']
			self.loud("Error!",message,0)
		try:
			groups = [dict(items.groupdict().items()+{'list':'0'}.items()) for items in re.finditer(r'^(?P<name>\w+):[^:]*:(?P<gid>\w+):',open('/etc/group','r').read(),re.M)]
			print groups
			self.cur.executemany(self.insertDB['groups'],groups)
		except Exception as message:
			print groups
			print self.insertDB['groups']
			self.loud("Error!",message,0)

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
				print updateUser
				print {'type':commandInsert['type'],'subname':subname}



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
				if message['type'] in self.expected.keys():
					message['aid'] = re.match('audit\([^:]+:([^)]+)\)',message['msg']).groups()[0]
					message['timestamp'] = re.match('audit\(([^.]+).+\)',message['msg']).groups()[0]
				else:
					return False
			except Exception as error:
				self.loud("Error!",message,0)
				self.loud("Some error occured",error.message,0)

			return message
		else:
			return False

	def insertType(self,message):
		atype = message['type']
		message = dict(self.expected[atype].items()+message.items())

		# Since EXECVE contains items we want (parameters) in a0, a1, a2, etc
		# format, we must group them into a single string to avoid creating
		# many columns in the SQL database
		if atype == "EXECVE":
			argc = int(message['argc']) if message['argc'] is not None else 0
			tmp={}
			counter=0
			# Merge all a[0-9] together. We could probably regex this isntead
			try:
				while counter < argc:
					# Sometimes an argument is missing or on the next line
					# We need to handle this if it's on the next line somehow
					try:
						if not re.match(r'^"[^"]*"$',message['a'+str(counter)]):
							message['a'+str(counter)] = '"'+binascii.unhexlify(message['a'+str(counter)].strip())+'"'
						tmp[counter] = message['a'+str(counter)]
					except Exception as error:
						# Sometimes we receive multiple EXECVE
						# with varying argc, which throws an error
						# http://www.redhat.com/archives/linux-audit/2009-March/msg00026.html
						# it is safe to ignore
						self.loud("Error!",message,2)
						self.loud("Some error occured",error.message,2)
						tmp[counter]=None

					counter = counter+1
				message['argdata'] = str(tmp)
			except Exception as error:
				self.loud("Error!",message,0)
				self.loud("Some error occured",error.message,0)
		else:
			# Since this is likely to happen a lot, don't print this message by default
			self.loud("Unknown type",atype)
			self.loud("Message",message,2)

		self.cur.execute(self.insertDB[atype],message) 


	def loud(self,note,item,level=1):
		if level <= self.verboseLevel:
			print note+": "+str(item)


	def commandList(self):
		if os.path.isfile(os.path.dirname(__file__)+'/commands.yaml'):
			commandList = open(os.path.dirname(__file__)+'/commands.yaml','r').read()
			commandList = yaml.load(typeConf)



