#!/usr/bin/python

from xml.dom.minidom import parse
import xml.dom.minidom
import time

# Open XML document using minidom parser
DOMTree = xml.dom.minidom.parse("1008.xml")
collection = DOMTree.documentElement


def getText(nodelist):
	rc = []
	try:
		for node in nodelist:
			if node.nodeType == node.TEXT_NODE:
				rc.append(node.data)
		return ''.join(rc)
	except:
		return ''

	
if collection.hasAttribute("Name"):
	print "Name: %s" % collection.getAttribute("Name")
	print "Version: %s" % collection.getAttribute("Version")
	print "Date: %s" % collection.getAttribute("Date")

# Get all the movies in the collection
weaknesses = collection.getElementsByTagName("Weakness")
print len(weaknesses)

# Print detail of each movie.
for weak in weaknesses:
	time.sleep(5)
	print "---------------------------------------"
	if weak.hasAttribute("Name"):
		print weak.getAttribute("Name")
	if weak.hasAttribute("ID"):
		print weak.getAttribute("ID")
	if weak.hasAttribute("Abstraction"):
		print weak.getAttribute("Abstraction")
	if weak.hasAttribute("Structure"):
		print weak.getAttribute("Structure")
	if weak.hasAttribute("Status"):
		print weak.getAttribute("Status")
	
	try:
		Description = weak.getElementsByTagName('Description')[0]
		print 'Description:', getText(Description.childNodes)
	except:
		pass
	try:
		Extended_Description= weak.getElementsByTagName('Extended_Description')[0]
		print 'Extended Description:', getText(Extended_Description.childNodes)
	except:
		pass
	try:
		Related_Weaknesses= weak.getElementsByTagName('Related_Weaknesses')[0]
		print 'Related_Weaknesses Object: ',Related_Weaknesses
		print 'Related_Weaknesses Child Nodes: ',Related_Weaknesses.childNodes
		for child in Related_Weaknesses.childNodes:
			print child.getAttribute("CWE_ID")
		Related_Weakness.getElementsByTagName("Related_Weakness")
		print 'CWE_ID', Related_Weakness.getAttribute("CWE_ID")
		#print 'Related Weaknesses:', getText(Related_Weaknesses.childNodes)
	except Exception as e:
		print 'Exception:',e
		pass
	try:
		Applicable_Platforms= weak.getElementsByTagName('Applicable_Platforms')[0]
		print 'Applicable_Platforms:', getText(Applicable_Platforms.childNodes)
	except:
		pass
	try:
		Modes_Of_Introduction= weak.getElementsByTagName('Modes_Of_Introduction')[0]
		print 'Modes Of Introduction:', getText(Modes_Of_Introduction.childNodes)
	except:
		pass		
	try:
		Common_Consequences= weak.getElementsByTagName('Common_Consequences')[0]
		print 'Common Consequences:', getText(Common_Consequences.childNodes)
	except:
		pass	
	try:
		Potential_Mitigations= weak.getElementsByTagName('Potential_Mitigations')[0]
		print 'Potential Mitigations:', getText(Potential_Mitigations.childNodes)
	except:
		pass	
	try:
		Demonstrative_Examples= weak.getElementsByTagName('Demonstrative_Examples')[0]
		print 'Demonstrative_Examples:', getText(Demonstrative_Examples.childNodes)
	except:
		pass
	try:
		Affected_Resources= weak.getElementsByTagName('Affected_Resources')[0]
		print 'Affected Resources:', getText(Affected_Resources.childNodes)
	except:
		pass
	try:
		Taxonomy_Mappings= weak.getElementsByTagName('Taxonomy_Mappings')[0]
		print 'Taxonomy Mappings:', getText(Taxonomy_Mappings.childNodes)
	except:
		pass
	try:
		Related_Attack_Patterns= weak.getElementsByTagName('Related_Attack_Patterns')[0]
		print 'Related Attack Patterns:', getText(Related_Attack_Patterns.childNodes)
	except:
		pass
	
	
	
	
	
	

	
