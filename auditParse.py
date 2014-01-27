import sqlite3, re, sys, os



class auditdParse:
	def __init__(self,auditFile):

		self.log = open(auditFile,'r').readlines()
		if os.path.isfile('audit.db'):
			self.con = sqlite3.connect('audit.db')
			self.cur = self.con.cursor()
		else:
			self.con = sqlite3.connect('audit.db')
			self.cur = self.con.cursor()
			sqlSchema = open('audit.sql','r').read()
			self.cur.executescript(sqlSchema)
			self.con.commit()

		# Here is what the database expects. 
		# We define these and merge the actual messages just
		# in case they do not contain one of the parameters
		# It must be (expected[n] + message) or it will overwrite

		self.expected = {}
		self.expected['SYSCALL'] = {'aid':None,'timestamp':None,'syscall':None,'success':None,'exit':None,'items':None,'ppid':None,'pid':None,'auid':None,'uid':None,'gid':None,'euid':None,'suid':None,'fsuid':None,'egid':None,'sgid':None,'fsgid':None,'tty':None,'ses':None,'comm':None,'exe':None,'exe':None}
		self.expected['EXECVE'] = {'aid':None,'timestamp':None,'argc':None,'argdata':None}
		self.expected['CWD'] = {'aid':None,'timestamp':None,'cwd':None}
		self.expected['PATH'] = {'aid':None,'timestamp':None,'item':None,'name':None,'inode':None,'dev':None,'mode':None,'ouid':None,'ogid':None}
		
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
