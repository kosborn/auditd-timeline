import sqlite3, re, sys, os, yaml



class auditdParse:
	def __init__(self,auditFile):
		typeConf = open('types.yaml','r').read()
		typeList = yaml.load(typeConf)

		# Here is where we defined expected database & dictionary parameters
		# We define these and merge the actual messages just
		# in case they do not contain one of the parameters
		# It must be (expected[n] + message) or it will overwrite
		# Defined in yaml config file

		self.expected = {}
		self.createDB = {}
		for i in typeList['auditd'].keys():
			self.expected[i] = {k: None for k in typeList['auditd'][i]['parameters']}
			self.createDB[i] = 'CREATE TABLE '+str(i)+'('+', '.join(list(' '.join([key,value]) for key,value in typeList['auditd'][i]['parameters'].items()))+');'

		self.log = open(auditFile,'r').readlines()
		if os.path.isfile('audit.db'):
			self.con = sqlite2.connect('audit.db')
			self.cur = self.con.cursor()
		else:
			self.con = sqlite3.connect('audit.db')
			self.cur = self.con.cursor()
			#sqlSchema = open(os.path.dirname(__file__)+'/audit.sql','r').read()
			self.cur.executescript(' '.join(self.createDB.values()))
			self.con.commit()


		for i in self.log:
			message = self.parseLine(i)
			if message:
				self.insertType(message)
		self.con.commit()
		self.con.close()


	def parseLine(self, line):
	 	if line.strip():
			try:
				message={x: y for(x, y) in re.findall('([a-z0-9]+)=([^ ]+)+',line)}
				message['aid'] = re.match('audit\([^:]+:([^)]+)\)',message['msg']).groups()[0]
				message['timestamp'] = re.match('audit\(([^.]+).+\)',message['msg']).groups()[0]
			except Exception as error:
				print "Some error occured: "+error.message

			return message
		else:
			return False

	def insertType(self,message):
		atype = message['type']
		if atype == "SYSCALL":
			message = dict(self.expected[atype].items()+message.items())
			query = "INSERT INTO SYSCALL VALUES(:aid,:timestamp,:syscall,:success,:exit,:items,:ppid,:pid,:auid,:uid,:gid,:euid,:suid,:fsuid,:egid,:sgid,:fsgid,:tty,:ses,:comm,:exe)";
		elif atype == "EXECVE":
			message = dict(self.expected[atype].items()+message.items())
			argc = int(message['argc'])
			tmp={}
			counter=0
			try:
				while counter < argc:
					tmp[counter] = message['a'+str(counter)]
					counter = counter+1
				message['argdata'] = str(tmp)
			except Exception as error:
				print message
				print "error: "+str(error)
			query = "INSERT INTO EXECVE VALUES(:aid,:timestamp,:argc,:argdata);"
		elif atype == "CWD":
			message = dict(self.expected[atype].items()+message.items())
			query = "INSERT INTO CWD VALUES(:aid,:timestamp,:cwd);"
		elif atype == "PATH":
			message = dict(self.expected[atype].items()+message.items())
			query = "INSERT INTO PATH VALUES(:aid,:timestamp,:item,:name,:inode,:dev,:mode,:ouid,:ogid);"
		else:
			#print "Unknown type: "+str(atype)
			query = "";
			#sys.exit()

		self.cur.execute(query,message) 



doit = auditdParse('/tmp/audit.log')
