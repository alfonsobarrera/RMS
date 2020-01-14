__statusName__={0:'Draft',1:'Started',2:'Closed',3:'Reopened'}
__labelName__={0:'Start the Project',1:'Close the Project',2:'Reopen the Project',3:'Close the Project'}
		
	
def getStatusName(status):
		return __statusName__[status]
		
def getLabelName(status):
		return __labelName__[status]
		
def updateStatus(current):
	current=int(current)
	if current<3:
		current=current+1
		print current
		return current
	else:
		current=2
		return current
		