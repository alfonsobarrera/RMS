import base64
import requests
import json
from threading import Thread
import time
import datetime
from time import gmtime, strftime

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def getCredentials():
	connect='mab0217:SHINGA'
	connect=base64.b64encode(connect.encode('ascii'))
	connect='Basic '+connect
	return connect

def run(connect, projects, projectid):
	"""Login to Fortify"""
	#connect=sys.argv[1]

	summary={}
	
	for x, projectname in enumerate(projects):
	
		resp=search_application(connect,projectname) #Look up for project name
		if resp['status']==200:
			print 'application found'
			issues=getProject_issues(connect, projectname, resp['data'])  #Retrieve project's issues
			summary[x]={'project':projectname, 'defects':issues}
		else:
			print "Error response, code: {}. Message: {}".format(resp['status'], resp['error'])
	return summary
	#ids=[]
	#if issues is not False and len(issues)>0:
	#	for issue in issues:
	#		ids.append(issue[4])
	#	addFortifyDefectsToProject(connect,ids,projectid,fortifyname, appname)
	#	return True					
	#else:
	#	return False
	
def search_application(credentials, name):
	headers = {'Content-Type': 'application/json','Accept': 'application/json','Authorization':credentials}	
	if name is not None and name!='':
		name=name.lstrip().rstrip().lower()
		url = 'https://fortify-ssc.homedepot.com/ssc/api/v1/projectVersions?start=0&limit=20000&q=project.name:"'+name+'"'
		flag=0
		try:
			r = requests.get(url, headers=headers,verify=False)
			data=json.loads(r.text)
			if r.status_code==200:
				return {'status':r.status_code, 'data':data}
			else:
				return {'status':r.status_code, 'error':r.reason }
		except Exception as e:
			return {'status':0, 'error:':str(e) }

def getProject_issues(credentials, name, data):
	for index in data['data']:
		if name in index['project']['name'].lower():						
			appver = str(index['id'])
			url="https://fortify-ssc.homedepot.com/ssc/api/v1/projectVersions/{}/issues?&limit=9000&orderby=%2Bfriority&start=0".format(appver)
			
			headers = {'Content-Type': 'application/json','Accept': 'application/json','Authorization':credentials}	
			issues={}

			try:
				
				r = requests.get(url, headers=headers,verify=False)
				data=json.loads(r.text)
				if r.status_code==200:
					if data['count']>0:
						for i in data['data']:
								
							issues[str(i['id'])]={	'name':i['issueName'],
													'location':i['primaryLocation'],
													'lineNumber': str(i['lineNumber']),
													'risk':i['friority'],
													'appversion':appver
													}
					return issues
				else:
					return issues
			except Exception as e:
				print ( e )
				return {}		


		
def addFortifyDefectsToProject(connect,ids,projectid,fortifyname, appname):
	print "Accessing addFortifyDefectsToProject(connect,ids,projectid,fortifyname, appname)"
	try:
		thread.start_new_thread( evilfortify.getIssueInfo, (connect, ids,projectid,session['name'],fortifyname, appname) )
	#return "This may take a while, we are getting info for "+str(len)
	except Exception as e:
		print str(e)
		pass	
		
def getDefect_Information(connect, issue):

	headers = {'Content-Type': 'application/json','Accept': 'application/json','Authorization':connect}	
	
	try:
		url="https://fortify-ssc.homedepot.com/ssc/api/v1/issueDetails/{}".format(issue)
		r = requests.get(url, headers=headers,verify=False)
		data=json.loads(r.text)
		
		if r.status_code==200:

			triageAnalysis="Not Analyzed"
			primaryTag=data['data']['primaryTag']
			if primaryTag is not None and len(primaryTag)>0:
				if 'tagValue' in primaryTag:
					triageAnalysis = primaryTag['tagValue']
			else:
				print False
			
			bug={
					'name':  data['data']['issueName'],
					'brief':  data['data']['brief'],
					'detail':data['data']['detail'],
					'state': data['data']['issueState'],
					'recommendation':data['data']['recommendation'],
					'references':data['data']['references'],
					'analysis':triageAnalysis,
					'shortFileName':data['data']['shortFileName'],
					'lineNumber':data['data']['lineNumber'],
					'risk':data['data']['friority']
			}
			return bug
		else:
			return False
	except Exception as e:
		return False
			

	
def month_string_to_number(string):
	m = {'jan': 1,'feb': 2,'mar': 3,'apr':4, 'may':5, 'jun':6, 'jul':7, 'aug':8, 'sep':9, 'oct':10,'nov':11,'dec':12}
	s = string.strip()[:3].lower()
	try:
		out = m[s]
		return out
	except:
		raise ValueError('Not a month')	

def validateDate(input):
	if input is None:
		input=""
	if input=="":
		year=str(datetime.date.today().strftime("%Y"))
		month=str(month_string_to_number(datetime.date.today().strftime("%B")))
		day=str(datetime.date.today().strftime("%d"))
		input=year+"-"+month+"-"+day
	else:
		input=input.strip()
	return input