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
		
		for i in self.log:
			message = self.parseLine(i)
			if message:
				self.insertType(message)
		self.con.commit()
		self.con.close()

	def parseLine(self, line):
	 	if line.strip():
			try:
				message={x: y for(x, y) in re.findall('([^ ]+)=([^ ]+)+',line)}
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
			query = "INSERT INTO SYSCALL VALUES(:aid,:timestamp,:syscall,:success,:exit,:items,:ppid,:pid,:auid,:uid,:gid,:euid,:suid,:fsuid,:egid,:sgid,:fsgid,:tty,:ses,:comm,:exe)";
		elif atype == "EXECVE":
			argc = int(message['argc'])-1
			message['argdata'] = {}
			tmp={}
			while argc > 0:
				tmp[argc] = message['a'+str(argc)]
				argc = argc-1 
			message['argdata'] = str(tmp)
			query = "INSERT INTO EXECVE VALUES(:aid,:timestamp,:argc,:argdata);"
		elif atype == "CWD":
			query = "INSERT INTO CWD VALUES(:aid,:timestamp,:cwd);"
		elif atype == "PATH":
			query = "INSERT INTO PATH VALUES(:aid,:timestamp,:item,:name,:inode,:dev,:mode,:ouid,:ogid);"
		else:
			print "Unknown type: "+str(atype)
			sys.exit()

		self.cur.execute(query,message) 


doit = auditdParse('testData/simple')
