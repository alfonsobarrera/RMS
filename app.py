from flask import Flask,request,jsonify, abort, send_file, escape, render_template, session, redirect, url_for, flash, Markup
import sqlite3
import json
from collections import Counter
import six
from HTMLParser import HTMLParser
import os
from flask_sqlalchemy import SQLAlchemy

import base64
import libraries.crypto as crypto
import libraries.cweSite as cwesite
import libraries.PIntStatus as projectIntStatus
import libraries.cweDic as cweDic
import libraries.evilfortify as evilfortify




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rms.sqlite3'
app.config['SECRET_KEY'] = "random string"
db = SQLAlchemy(app)

#SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:xoxoincubus@127.0.0.1/rms'
#app.config['SQLALCHEMY_DATABASE_URI'] =SQLALCHEMY_DATABASE_URI

class MemberStatus:
	Active='Active'
	Inactive='Inactive'
class MemberRole:
	Admin='Admin'
	General='General'
	Guest='Guest'

class Members(db.Model):
	id = db.Column('member_id', db.Integer, primary_key = True)
	name = db.Column(db.String(100))
	username = db.Column(db.String(50), unique=True)
	password = db.Column(db.String(200)) 
	role= db.Column(db.String(50))
	status=db.Column(db.String(50))
	trackerkey = db.Column(db.Integer())

class Application(db.Model):
	id=db.Column('application_id', db.Integer, primary_key=True)
	sap_id = db.Column(db.String(100))
	experience=db.Column(db.String(100))
	subexperience=db.Column(db.String(100))
	name=db.Column(db.String(200) , unique=True)
	
class ProjectStatus(db.Model):
	id=db.Column('status_id', db.Integer, primary_key=True)
	projectid = db.Column(db.String(10))
	subject=db.Column(db.String(100))
	object=db.Column(db.String(100))
	date=db.Column(db.String(200))	

class Vulnerability(db.Model):
	id=db.Column('vulnid', db.Integer, primary_key=True)
	cwe=db.Column(db.Integer)
	name = db.Column(db.String(1000))
	description=db.Column(db.String(12000))
	recommendation=db.Column(db.String(12000))
	
class Defect(db.Model):
	#Control
	id=db.Column('defect_id', db.Integer, primary_key=True)
	projectid = db.Column(db.Integer)
	cwe = db.Column(db.String(20))
	#Common Data
	name = db.Column(db.String(8000))
	risk = db.Column(db.String(8000))
	source = db.Column(db.String(8000))
	#Dynamic Block
	url = db.Column(db.String(8000))
	parameter = db.Column(db.String(8000))
	payload = db.Column(db.String(8000))
	wostcase = db.Column(db.String(8000))
	steps = db.Column(db.String(8000))
	recommendation = db.Column(db.String(8000))
	#Static Blocl
	github = db.Column(db.String(8000))
	filename = db.Column(db.String(8000))
	line = db.Column(db.String(8))
	taggedFortify = db.Column(db.String(20))
	
class FortifyDefect(db.Model):
	#Control
	id=db.Column('defect_id', db.Integer, primary_key=True)
	projectid = db.Column(db.Integer)
	fproject= db.Column(db.String(1000))
	name = db.Column(db.String(8000))
	#Common Data
	brief = db.Column(db.String(8000))
	detail = db.Column(db.String(8000))
	state = db.Column(db.String(8000))
	#Dynamic Block
	recommendation = db.Column(db.String(8000))
	references = db.Column(db.String(8000))
	analysis = db.Column(db.String(8000))
	shortFileName = db.Column(db.String(8000))
	lineNumber = db.Column(db.String(8000))
	risk = db.Column(db.String(8000))

	
class ProjectInternalStatus:
	state={0:'Draft',1:'Started',2:'Closed',3:'Reopened'}
	label={0:'Start the Project',1:'Close the Project',2:'Reopen the Project',3:'Close the Project'}
	current=0

class Project(db.Model):
	id=db.Column('project_id', db.Integer, primary_key=True)
	appid = db.Column(db.String(15))
	name=db.Column(db.String(200))
	description = db.Column(db.String(8000))
	scope = db.Column(db.String(8000))
	assessment_id = db.Column(db.String(15))
	tracker_id = db.Column(db.String(15))
	urls = db.Column(db.String(8000))
	githubs = db.Column(db.String(8000))
	fortifys = db.Column(db.String(8000))
	priority = db.Column(db.String(10))
	type = db.Column(db.String(20))
	engineer = db.Column(db.Integer)
	deadline = db.Column(db.String(30))
	status= db.Column(db.Integer)
	pci= db.Column(db.String(2))
	
	
class cwes(db.Model):
	id=db.Column('CWE-ID', db.Integer, primary_key=True)
	Name= db.Column(db.String(8000))
	WeaknessAbstraction= db.Column(db.String(8000))
	Status= db.Column(db.String(8000))
	Description= db.Column(db.String(8000))
	ExtendedDescription= db.Column(db.String(8000))
	RelatedWeaknesses= db.Column(db.String(8000))
	WeaknessOrdinalities= db.Column(db.String(8000))
	ApplicablePlatforms= db.Column(db.String(8000))
	BackgroundDetails= db.Column(db.String(8000))
	AlternateTerms= db.Column(db.String(8000))
	ModesOfIntroduction= db.Column(db.String(8000))
	ExploitationFactors= db.Column(db.String(8000))
	LikelihoodofExploit= db.Column(db.String(8000))
	CommonConsequences= db.Column(db.String(8000))
	DetectionMethods= db.Column(db.String(8000))
	PotentialMitigations= db.Column(db.String(8000))
	ObservedExamples= db.Column(db.String(8000))
	FunctionalAreas= db.Column(db.String(8000))
	AffectedResources= db.Column(db.String(8000))
	TaxonomyMappings= db.Column(db.String(8000))
	RelatedAttackPatterns= db.Column(db.String(8000))
	Notes= db.Column(db.String(8000))
	
def register():
    bpy.utils.register_module(__name__)

def unregister():
    bpy.utils.unregister_module(__name__)

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404
	
@app.after_request
def add_header(response):
	response.cache_control.no_store = True
	if 'Cache-Control' not in response.headers:
		response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
		response.headers["Pragma"] = "no-cache"
		response.headers["Expires"] = "0"
		response.headers['Cache-Control'] = 'public, max-age=0'
	return response
	
@app.route('/', methods=['GET', 'POST'])
def login():
	
	if request.method=='GET':
		return render_template('login.html')
	if request.method=='POST':
		if not request.form['username'] or not request.form['password']:
			flash('Please enter all the fields to Log in', 'error')
		else:#data
			user=request.form['username']
			members=Members()
			
			if members.query.filter_by(username=user).all()==False:
				flash('You are not registered.', 'error')
#				logger.WARNING("Fail logging attemtp: INVALID USER= {}".format(user))
				return redirect(url_for('/'))
			else:
				for member in members.query.filter_by(username=user).all():
					if member:
						if member.password == crypto.Security(request.form['password']).hash() and member.status==MemberStatus.Active:
							session['name']=member.name
							session['username']=member.username
							session['userid']=member.id
							session['role']=member.role
							session['status']=member.status
							session['logged_in']=True
							return redirect(url_for('projects'))
						else:
							session['logged_in']=False
							flash('Wrong Password or Account Inactive.', 'error')
			

	return render_template('login.html')

@app.route('/home', methods=['GET'])
def home():
	if session.get('logged_in'):
		
		return render_template('home.html')
	else:
		return redirect(url_for('login'))
		
@app.route('/terms', methods=['GET'])
def terms():
		return render_template('terms.html')
	
@app.route('/SignUp', methods=['GET', 'POST'])
def SignUp():
	
	if request.method=='POST':
		if not request.form['name'] or not request.form['username'] or not request.form['password']:
			flash('Please enter all the fields to Sign Up', 'error')
			return redirect(url_for('login'))
		else: #Verify is the user exists
			user=request.form['username']
			members=Members()
			
			if members.query.filter_by(username=user).all():
				flash('User registered already', 'error')
				return redirect(url_for('login'))	
			else: 
				members.name = request.form['name']  
				members.username = request.form['username']
				members.password = crypto.Security(request.form['password']).hash()
				members.trackerkey = request.form['trackerkey']
				members.role=MemberRole.Guest
				members.status=MemberStatus.Inactive
				
				db.session.add(members)
				db.session.commit()
				flash('User Registration Successfully', 'error')
				return redirect(url_for('login'))
			
	else:
		return redirect(url_for('login'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
	if session.get('logged_in'):
		session.pop('userid', None)
		session.pop('name', None)
		session.pop('username', None)
		session.pop('role', None)
		session.pop('status', None)
		session.pop('logged_in', False)
	return redirect(url_for('login'))
		
		
@app.route('/exploreCWEs', methods=['GET'])
def exploreCWE():
	if session.get('logged_in'):
		cwes=cweDic.number
		return render_template('exploreCWEs.html', cwes=cwes)
	else:
		return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
	if session.get('logged_in'):
		if session['role']==MemberRole.Admin or session['username']=='alfonso':
			members=Members()
			users=members.query.all()
			return render_template('admin.html',users=users)
		else:
			return redirect(url_for('home'))
	else:
		return redirect(url_for('login'))

@app.route('/admin/update/user/<userid>', methods=['GET', 'POST'])
def update_user(userid):
	if session.get('logged_in'):
		if request.method=='GET':
			if session['role']==MemberRole.Admin or session['username']=='alfonso':
				members=Members()
				user=members.query.filter_by(id=userid).first()
				return render_template('admin-update-user.html',user=user, MemberRole=MemberRole(), MemberStatus=MemberStatus())
			else:
				return redirect(url_for('home'))
				
		if request.method=='POST':
			if session['role']==MemberRole.Admin or session['username']=='alfonso':
				member=db.session.query(Members).get(userid)
				member.name = request.form['name']  
				member.username = request.form['username']
				#member.password = crypto.Security(request.form['password']).hash()
				member.trackerkey = request.form['trackerkey']
				member.role = request.form['role']
				member.status = request.form['status']
				db.session.commit()
				print session['username']
				if session['username']==request.form['username']:
					session['role']=request.form['role']
					session['status']=request.form['status']
				return redirect(url_for('admin'))
			else:
				return redirect(url_for('home'))
	else:
		return redirect(url_for('login'))
		
@app.route('/admin/update/password/<userid>', methods=['GET', 'POST'])
def update_user_password(userid):
	if session.get('logged_in'):
		if request.method=='GET':
			if session['role']==MemberRole.Admin or session['username']=='alfonso':
				return render_template('admin-update-user-password.html',userid=userid)
			else:
				return redirect(url_for('home'))
	
		if request.method=='POST':

			if session['role']==MemberRole.Admin or session['username']=='alfonso':
				try:
					member=db.session.query(Members).get(userid)
					member.password = crypto.Security(request.form['password']).hash()
					db.session.commit()
					return 'The password has been updated.'
				except Exception as e:
					print e
					return 'Error updating the password' 
			else:
				return redirect(url_for('home'))
		else:
			return redirect(url_for('home'))
	else:
		return redirect(url_for('login'))
		
@app.route('/profile/user/<userid>', methods=['GET', 'POST'])
def update_profile(userid):
	userid=int(userid)
	if session.get('logged_in'):
		if request.method=='GET':
			if session['userid']==userid: #Check if the same user is trying to update his own session
				members=Members()
				user=members.query.filter_by(id=userid).first()
				return render_template('profile-update-user.html',user=user, MemberRole=MemberRole(), MemberStatus=MemberStatus())
			else:
				return redirect(url_for('update_profile', userid=session['userid']))
		if request.method=='POST':
			
			member=db.session.query(Members).get(userid)
			member.name = request.form['name']  
			member.username = request.form['username']
			member.password = crypto.Security(request.form['password']).hash()
			member.trackerkey = request.form['trackerkey']
			db.session.commit()
			if session['username']==request.form['username']:
				session['username']=request.form['username']
				session['name']=request.form['name']
			return redirect(url_for('admin'))			
		

@app.route('/projects', methods=['GET', 'POST'])
def projects():
	if session.get('logged_in'):
		project=Project()
		projects=project.query.all()
		member=Members()
		members=member.query.all()
		
		userdic={}
		for mem in members:
			userdic[str(mem.id)]=str(mem.name)

		newusers=0
		for m in members:
			if m.status==MemberStatus.Inactive:
				newusers=newusers+1
		
		return render_template('projects.html', projects=projects, newusers=newusers, userdic=userdic)
	else:
		return redirect(url_for('login'))
		
@app.route('/projectDashboard/projectid/<projectid>', methods=['GET', 'POST'])
def projectDashboard(projectid):
	if session.get('logged_in'):
		if request.method=='GET':	
			try:
				project=Project()
				project=project.query.filter_by(id=projectid).first()
				
				return render_template('projectDashboard.html',project=project)
			except Exception as e:
				print (e)
				raise
		if request.method=='POST':
			print ('POST METHOD in projectDashboard on project {}'.format(projectid))
			return 'POST METHOD in projectDashboard on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))
		
		
@app.route('/project_add_defect/projectid/<projectid>', methods=['GET', 'POST'])
def project_add_defect(projectid):
	if session.get('logged_in'):
		if request.method=='GET':	
			return render_template('project_add_defect.html', projectid=projectid)
		if request.method=='POST':
			draftname=''
			cwe=request.form['cwe']
			
			cwenum=int(cwe)
			
			cweobj=cwes()
			cweInfo=cweobj.query.filter_by(id=cwenum).first()
			draftname=cweInfo.Name
			
			if draftname==None or draftname==False:
				name=''
			else:
				name=draftname
			
			description=''
			recommendation=''
			#Adding the Vulnerability
			try:
				vuln=Vulnerability()
				vuln.cwe=int(cwe)
				vuln.name=name
				vuln.description=''
				vuln.recommendation=''
				db.session.add(vuln)
				db.session.commit()
			except:
				raise
			try:
				defect=Defect()
				defect.projectid=projectid
				defect.name=name
				defect.risk=request.form['risk']
				defect.cwe=cwe
				defect.source=request.form['source']
				defect.url=request.form['url']
				defect.parameter =request.form['parameter']
				defect.payload =request.form['payload']
				defect.wostcase =request.form['scenario']
				defect.steps =request.form['reproductionSteps']
				defect.recommendation =request.form['recommendation']
				defect.github =request.form['repository']
				defect.filename =request.form['filename']
				defect.line =request.form['linenumber']
				defect.taggedFortify='Exploitable'
				db.session.add(defect)
				db.session.commit()	

			except:
				raise
			
			return redirect(url_for('projectDashboard', projectid=projectid))
		
	else:
		return redirect(url_for('login'))
		
@app.route('/project_add_defect/verifycwe/<cwe>', methods=['GET'])
def project_add_defect_verifycwe(cwe):
	if session.get('logged_in'):
		if request.method=='GET':
			cwenum=int(cwe)
			if cwenum>0 and cwenum<=2000:
				cwe=cwes()
				cweInfo=cwe.query.filter_by(id=cwenum).first()
				if cweInfo is None or cweInfo is False:
					return 'Invalid CWE'
				else:
					return cweInfo.Name
					
			else:
				return 'Invalid CWE'
				
@app.route('/explorecwe/<cwe>', methods=['GET'])
def explorecweFetchInfo(cwe):
	if session.get('logged_in'):
		if request.method=='GET':
			cwenum=int(cwe)
			if cwenum>0 and cwenum<=2000:
				try:
					cwe=cwes()
					cweInfo=cwe.query.filter_by(id=cwenum).first()
					return json.dumps({
						'Name':'{} - {}'.format(cweInfo.id,cweInfo.Name),
						'Abstraction':cweInfo.WeaknessAbstraction,
						'Status':cweInfo.Status,
						'Description':cweInfo.Description,
						'Extended Description':cweInfo.ExtendedDescription,
						'Related Weaknesses':cweInfo.RelatedWeaknesses,
						'Applicable Platforms':cweInfo.ApplicablePlatforms,
						'Background Details':cweInfo.BackgroundDetails,
						'Modes Of Introduction':cweInfo.ModesOfIntroduction,
						'Exploitation Factors':cweInfo.ExploitationFactors,
						'Likelihood of Exploit':cweInfo.LikelihoodofExploit,
						'Potential Mitigations':cweInfo.PotentialMitigations,
						'Observed Examples':cweInfo.ObservedExamples,
						'Affected Resources':cweInfo.AffectedResources,
						'Related AttackPatterns':cweInfo.RelatedAttackPatterns,
						'Notes':cweInfo.Notes
					})
				except:
					return json.dumps({
						'Name':'The chosen CWE is a category.',
						'Abstraction':'Please visit the link for more information: <a href="https://cwe.mitre.org/data/definitions/{}" blank="_blank">CWE-{}</a>'.format(cwenum, cwenum),
						'Status':None,
						'Description':None,
						'Extended Description':None,
						'Related Weaknesses':None,
						'Applicable Platforms':None,
						'Background Details':None,
						'Modes Of Introduction':None,
						'Exploitation Factors':None,
						'Likelihood of Exploit':None,
						'Potential Mitigations':None,
						'Observed Examples':None,
						'Affected Resources':None,
						'Related AttackPatterns':None,
						'Notes':None
					})
			else:
				return 'Invalid CWE'
		
@app.route('/project_import_45_defects/projectid/<projectid>', methods=['GET', 'POST'])
def project_import_45_defects(projectid):
	if session.get('logged_in'):
		if request.method=='GET':	
			project=Project()
			project=project.query.filter_by(id=projectid).first()
			project.fortifys
			return render_template('project_import_fortify_defects.html', projectid=projectid, fprojects=project.fortifys)
		if request.method=='POST':
			print ('POST METHOD in project_import_45_defects on project {}'.format(projectid))
			return 'POST METHOD in project_import_45_defects on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))
		
@app.route('/preselectFortifyDefects/projectid/<projectid>', methods=['GET', 'POST'])
def preselectFortifyDefects(projectid):
	if session.get('logged_in'):
		if request.method=='GET' or request.method=='POST':
			try:
				fprojects=request.form['fprojects']
				fprojects=fprojects.split(',')
				auth=evilfortify.getCredentials()
				defects=evilfortify.run(auth, fprojects, projectid)
			
				return render_template('FortifyDefectsPreview.html', projectid=projectid, defects=defects)
			except:
				return render_template('FortifyDefectsPreview - Error.html', fprojects=fprojects)

	else:
		return redirect(url_for('login'))
		
@app.route('/addSelected_FortifyDefect/projectid/<projectid>/defectid/<defectid>/fproject/<fproject>', methods=['GET', 'POST'])
def addSelected_FortifyDefect(projectid, defectid, fproject):
	if session.get('logged_in'):
		if request.method=='GET' or request.method=='POST':
			auth=evilfortify.getCredentials()
			defect=evilfortify.getDefect_Information(auth, defectid)
			
			fdefect=FortifyDefect()
			
			fdefect.projectid = int(projectid)
			fdefect.fproject= fproject
			fdefect.name = defect['name']
			fdefect.brief = defect['brief']
			fdefect.detail = defect['detail']
			fdefect.state = defect['state']
			fdefect.recommendation = defect['recommendation']
			fdefect.references = defect['references']
			fdefect.analysis = defect['analysis']
			fdefect.shortFileName = defect['shortFileName']
			fdefect.lineNumber = defect['lineNumber']
			fdefect.risk = defect['risk']
			db.session.add(fdefect)
			db.session.commit()	
			
			return "The defect has been added: {}".format(defectid)

	else:
		return redirect(url_for('login'))

		
		
@app.route('/project_manage_defects/projectid/<projectid>', methods=['GET', 'POST'])
def project_manage_defects(projectid):
	if session.get('logged_in'):
		if request.method=='GET':
			try:
				defect=Defect()
				defects=defect.query.all()
				
				fdefects=FortifyDefect()
				
				fdefects=fdefects.query.all()
				
				print 'Defect:',fdefects
				
				return render_template('project_manage_defects.html', projectid=projectid, projectidInt=int(projectid), defects=defects, fdefects=fdefects)
			except Exception as e:
				raise
				print e
				return redirect(url_for('projectDashboard', projectid=projectid))
				
		if request.method=='POST':
			print ('POST METHOD in project_import_45_defects on project {}'.format(projectid))
			return 'POST METHOD in project_import_45_defects on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))

#View Defects
@app.route('/project_manage_defects/projectid/<projectid>/view/<id>', methods=['GET', 'POST'])
def viewDefect(projectid, id):
	if session.get('logged_in'):
		if request.method=='GET':
			try:
				defect=db.session.query(Defect).get(id)
				return render_template('defect_view.html', projectid=projectid, projectidInt=int(projectid), defect=defect)
			except Exception as e:
				raise
				return redirect(url_for('projectDashboard', projectid=projectid))
		if request.method=='POST':
			print ('POST METHOD in project_import_45_defects on project {}'.format(projectid))
			return 'POST METHOD in project_import_45_defects on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))
		
#Edit Defects
@app.route('/project_manage_defects/projectid/<projectid>/edit/<id>', methods=['GET', 'POST'])
def editDefect(projectid, id):
	if session.get('logged_in'):
		if request.method=='GET':
			try:
				defect=db.session.query(Defect).get(id)
				return render_template('defect_edit.html', projectid=projectid, projectidInt=int(projectid), defect=defect)
			except Exception as e:
				raise
				return redirect(url_for('projectDashboard', projectid=projectid))
		if request.method=='POST':
			try:
				defect=db.session.query(Defect).get(id)
				defect.risk=request.form['risk']
				defect.source=request.form['source']
				if defect.source=='Manual' or defect.source=='DAST':
					defect.url=request.form['url']
					defect.parameter =request.form['parameter']
					defect.payload =request.form['payload']
				if defect.source=='Code' or defect.source=='Fortify':
					defect.github = request.form['github']
					defect.filename =request.form['filename']
					defect.line =request.form['line']
					defect.taggedFortify= request.form['taggedFortify']
				
				defect.wostcase =request.form['wostcase']
				defect.steps =request.form['steps']
				defect.recommendation =request.form['recommendation']

				db.session.commit()
				return "<!DOCTYPE html><html><body onload='windowClose()'><script>function windowClose(){window.open('','_parent','');window.close();}</script></body></html>"
				
			except Exception as e:
				raise
				return redirect(url_for('projectDashboard', projectid=projectid))
	else:
		return redirect(url_for('login'))

#Delete Defects
@app.route('/project_manage_defects/projectid/<projectid>/remove/<id>', methods=['GET', 'POST'])
def removeDefect(projectid, id):
	if session.get('logged_in'):
		if request.method=='GET':
			try:
				defect=db.session.query(Defect).get(id)
				db.session.delete(defect)
				db.session.commit()
				defects=defect.query.all()
				
				return "The manual defect ID:{} has been removed.".format(str(id))
			except Exception as e:
				raise
				return redirect(url_for('projectDashboard', projectid=projectid))
		if request.method=='POST':
			print ('POST METHOD in project_import_45_defects on project {}'.format(projectid))
			return 'POST METHOD in project_import_45_defects on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))
		
#Delete Fortify Defects
#project_manage_defects
@app.route('/pmd/pi/<projectid>/r/f/<id>', methods=['GET', 'POST'])
def removeFortifyDefect(projectid, id):
	if session.get('logged_in'):
		if request.method=='GET':
			try:
				print 'Accessing pmd'
				defect=db.session.query(FortifyDefect).get(id)
				db.session.delete(defect)
				db.session.commit()
				defects=defect.query.all()
				
				return "The Fortify defect ID:{} has been removed.".format(str(id))
			except Exception as e:
				raise
				return redirect(url_for('projectDashboard', projectid=projectid))
		if request.method=='POST':
			print ('POST METHOD in project_import_45_defects on project {}'.format(projectid))
			return 'POST METHOD in project_import_45_defects on project {}'.format(projectid)
	else:
		return redirect(url_for('login'))	


@app.route('/project_update_status/projectid/<projectid>/status/<status>', methods=['GET', 'POST'])
def project_update_status(projectid, status):
		print projectid, status
		project=db.session.query(Project).get(projectid)
		
		project.status=projectIntStatus.updateStatus(project.status)
		db.session.commit()
		
		return redirect(url_for('projectDashboard', projectid=projectid))
		
		
@app.route('/securityReport/create/<projectid>', methods=['GET', 'POST'])
def project_create_sec_report(projectid):
		return render_template('appSecurityReport.html',project=project)
		
		
@app.route('/project_delete/projectid/<projectid>', methods=['GET', 'POST'])
def project_delete(projectid):
	if session.get('logged_in'):
		project=db.session.query(Project).get(projectid)
		db.session.delete(project)
		db.session.commit()
		return redirect(url_for('projects'))
	else:
		return redirect(url_for('login'))
        
@app.route('/applications', methods=['GET', 'POST'])
def applications(message=''):
	if session.get('logged_in'):
		try:
			applications=Application()
			applications=applications.query.all()
		except Exception as e:
			print e
			raise
				
		return render_template('applications.html', applications=applications, message=message)
	else:
		return redirect(url_for('login'))
		
@app.route('/addNewApplication', methods=['GET', 'POST'])
def addNewApplication():
    if session.get('logged_in'):
        if request.method=='POST':
            try:
				sap_id=request.form['sap_id']
				experience=request.form['experience']
				subexperience=request.form['sub_experience']
				name=request.form['name']
				
				application=Application()
				application.sap_id=str(sap_id)
				application.experience=experience
				application.subexperience=subexperience
				application.name=name
				
				db.session.add(application)
				db.session.commit()

				return redirect(url_for('applications'))
            except Exception as e:
                print e
                raise
            
        else:
            return redirect(url_for('applications'))
    else:
        return redirect(url_for('login'))

@app.route("/rmsapplication/application/add", methods=['GET','POST'])
def rmsapplication_app_add():
	"""
	Retrieve, update or delete note instances.
	"""
	if request.method == 'POST':
		try:
			data= request.get_json(silent=True)
			app=data['data']

			application=Application()
			appsearch=application.query.filter_by(name=app['name']).first()
			if appsearch is None or appsearch is False:
				application.sap_id=app['sap_id']
				application.experience=app['experience']
				application.subexperience=app['subexperience']
				application.name=app['name']
					
				db.session.add(application)
				#db.session.flush()
				db.session.commit()
				return jsonify({'appid':str(application.id)})
			else:
				return jsonify({'appid':str(appsearch.id)})
		except Exception as e:
			print e
			return jsonify({'appid':'-1'})
			
@app.route("/rmsapplication/project/add", methods=['GET','POST'])
def rmsapplication_project_add():
	"""
	Retrieve, update or delete note instances.
	"""
	if request.method == 'POST':
		try:

			data = request.get_json(silent=True)
		
			app=data['data']
			
			project=Project()
			projectsearch=project.query.filter_by(assessment_id=app['assessment_id']).first()
			
			
			if projectsearch is None or projectsearch is False:

				project.appid = app['appid']
				project.name = app['name']
				project.description = app['description']
				project.scope = app['scope']
				project.assessment_id = app['assessment_id']
				project.tracker_id = app['tracker_id']
				project.urls = app['urls']
				project.githubs = app['githubs']
				project.fortifys = app['fortifys']
				project.priority = app['priority']
				project.type = app['type']
				project.engineer = 0
				project.pci = 0
				project.deadline = app['deadline']
				project.status = 0
				
				db.session.add(project)
				db.session.commit()				

				return jsonify({'projectid':str(project.id)})
			else:
				return jsonify({'projectid':str(projectsearch.id)})
		except Exception as e:
			print e
			return jsonify({'projectid':'-1','error':str(e)})
			
@app.route("/rmsapplication/project/search/<projectid>", methods=['GET','POST'])
def rmsapplication_project_search(projectid):
	"""
	Retrieve, update or delete note instances.
	"""
	if request.method == 'GET':
		try:

			project=Project()
			project=project.query.filter_by(id=projectid).first()
			
			if project!=None or projectsearch!=False:

				return jsonify({"project":{
				"id":project.id,
				"appid":project.appid,
				"name":project.name,
				"description":project.description,
				"scope":project.scope,
				"assessment_id":project.assessment_id, 
				"tracker_id":project.tracker_id, 
				"urls":project.urls, 
				"githubs":project.githubs, 
				"fortifys":project.fortifys, 
				"priority":project.priority, 
				"type":project.type, 
				"engineer":project.engineer, 
				"pci":project.pci, 
				"deadline":project.deadline,
				"status":project.status}})		

			else:
				return jsonify({'project':False})
		except Exception as e:
			print e
			return jsonify({'project':'-1','error':str(e)})
			
		
	
@app.route('/addNewProject/appid/<appid>', methods=['GET', 'POST'])
def addNewProject(appid):
    if session.get('logged_in'):
        if request.method=='GET':
            try:
				application=db.session.query(Application).get(appid)
				members=Members()
				users=members.query.all()
				return render_template('createNewProject.html', application=application, users=users)
            except Exception as e:
                print e
                raise
            
        if request.method=='POST':
			project = Project()
			project.appid = appid
			project.name = request.form['name']
			project.description = request.form['description']
			project.scope = request.form['scope']
			project.assessment_id = request.form['assessment_id']
			project.tracker_id = request.form['tracker_id']
			project.urls = request.form['urls']
			project.githubs = request.form['githubs']
			project.fortifys = request.form['fortifys']
			project.priority = request.form['priority']
			project.type = request.form['type']
			project.engineer = request.form['engineer']
			project.pci = request.form['pci']
			project.deadline = 'Undefined'
			project.status = 0
			
			db.session.add(project)
			db.session.commit()
			
			return redirect(url_for('projects'))

    else:
        return redirect(url_for('login'))
		
@app.route('/delApp/appid/<appid>', methods=['GET', 'POST'])
def delete_application(appid):
    if session.get('logged_in'):
        if request.method=='GET':
            try:

				cnter=db.session.query(Project).filter_by(appid=appid).count()
				if cnter>0:
					message="There are {} projects depending on the selected application. You don't have privileges to delete it.".format(str(cnter)) 
					return applications(message)
				else:
					return redirect(url_for('applications'))
            except Exception as e:
                raise
            
        if request.method=='POST':			
			return redirect(url_for('applications'))

    else:
        return redirect(url_for('login'))		

#Update and existing project
@app.route('/updateProject/projectid/<projectid>', methods=['GET', 'POST'])
def project_update(projectid):
    if session.get('logged_in'):
        if request.method=='GET':
            try:
				project=db.session.query(Project).get(projectid)

				return render_template('project-update-information.html', project=project)
            except Exception as e:
				raise
				return redirect(url_for('projectDashboard', projectid=projectid))
                
            
        if request.method=='POST':
			try:
				project=db.session.query(Project).get(projectid)
				project.name = request.form['name']
				project.description = request.form['description']
				project.scope = request.form['scope']
				project.assessment_id = request.form['assessment_id']
				project.tracker_id = request.form['tracker_id']
				project.urls = request.form['urls']
				project.githubs = request.form['githubs']
				project.fortifys = request.form['fortifys']
				project.priority = request.form['priority']
				project.type = request.form['type']
				project.engineer = request.form['engineer']
				project.pci = request.form['pci']
				
				db.session.commit()
				
				return redirect(url_for('projectDashboard', projectid=projectid))
			except:
				return redirect(url_for('projectDashboard', projectid=projectid))

    else:
        return redirect(url_for('login'))




if __name__=="__main__":
	#app.secret_key=os.urandom(32) #Needed for HTTPS
	db.create_all()
	app.run(host='0.0.0.0', debug=True, port=6666)
	#app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)
