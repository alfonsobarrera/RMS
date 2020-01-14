import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def buildURL(url, cwe=''):
	url='https://cwe.mitre.org{}{}'.format(url, str(cwe))
	return url

def executeRequest(url):
	r=requests.get(url, verify=False)
	if r.status_code==200:
		return r.text
	else:
		return False


		
def getCWEInfo(cwe):
	url=buildURL('/cgi-bin/jumpmenu.cgi?id=', cwe)
	a=executeRequest(url)
	if a!=False  and not('error' in a):
		soup = BeautifulSoup(a, "html.parser")
		tag=soup.meta
		url=soup.meta['content'].split('=')[1]
		url=buildURL(url)
		b=executeRequest(url)
		soup2=BeautifulSoup(b, "html.parser")
		return soup2.prettify()


	else:
		return 'Invalid CWE'