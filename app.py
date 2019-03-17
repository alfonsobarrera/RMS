from flask import Flask,request, abort, send_file, escape, render_template, session, redirect, url_for, flash, Markup
import sqlite3
import json
from collections import Counter
import six
from HTMLParser import HTMLParser
import os
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO


#from wtforms.validators import DataRequired, Email
from wtforms import validators, ValidationError

from flask_bootstrap import Bootstrap

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rms.sqlite3'
app.config['SECRET_KEY'] = "random string"
db = SQLAlchemy(app)
socketio = SocketIO(app)

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

def __init__(self):
	self.id = None
	self.name = None
	self.username = None
	self.password = None
	self.role=MemberRole.Guest
	self.status=MemberStatus.Inactive
	self.trackerkey=0

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
				return redirect(url_for('/'))
			else:
				for member in members.query.filter_by(username=user).all():
					if member:
						if member.password == request.form['password'] and member.status==MemberStatus.Active:
							session['name']=member.name
							session['username']=member.username
							session['userid']=member.id
							session['role']=member.role
							session['status']=member.status
							session['logged_in']=True
							return redirect(url_for('home'))
						else:
							session['logged_in']=False
							flash('Wrong Password or Account Inactive.', 'error')
		
				
	return render_template('login.html')
	
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
				members.password = request.form['password']
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
		
		
@app.route('/home', methods=['GET', 'POST'])
def home():
	if session.get('logged_in'):
	
		return render_template('home.html')
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
				member.password = request.form['password']
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
			member.password = request.form['password']
			member.trackerkey = request.form['trackerkey']
			db.session.commit()
			if session['username']==request.form['username']:
				session['username']=request.form['username']
				session['name']=request.form['name']
			return redirect(url_for('admin'))			
		

@app.route('/projects', methods=['GET', 'POST'])
def projects():
	if session.get('logged_in'):
		return render_template('projects.html')
	else:
		return redirect(url_for('login'))
		
@app.route('/bot')
def bot():
	if session['logged_in'] and (session['role']==MemberRole.General or session['role']==MemberRole.Admin):
		return render_template('bot.html')
	
def messageReceived(methods=['GET', 'POST']):
    print('message was received!!!')

@socketio.on('my event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received my event: ' + str(json))
    socketio.emit('my response', json, callback=messageReceived)

	
	
	
if __name__=="__main__":
	#app.secret_key=os.urandom(32) #Needed for HTTPS
	db.create_all()
	app.run(debug = True)
	socketio.run(app, debug=True)
	#app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)
