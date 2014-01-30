import sqlite3, re, sys, os, yaml



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
						tmp[counter] = message['a'+str(counter)]
					except:
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


