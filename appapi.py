from flask import request, url_for
from flask_api import FlaskAPI, status, exceptions
import json

app = FlaskAPI(__name__)




@app.route("/", methods=['GET', 'POST'])
def notes_list():
	"""
	List or create notes.
	"""
	return status.HTTP_200_OK


@app.route("/rmsapplication", methods=['GET', 'PUT', 'DELETE'])
def rmsapplication():
	"""
	Retrieve, update or delete note instances.
	"""
	if request.method == 'PUT':
		note = str(request.data.get('data', ''))
		print note
		return '', status.HTTP_200_OK
		

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=5002 ,debug = True)