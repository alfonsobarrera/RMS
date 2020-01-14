import base64
import hashlib, binascii
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from Crypto import Random

class Security:
	key=None
	nonce=None
	def __init__(self,input):
		self.key=input
		self.nonce=Random.new().read(16)
		
	def hash(self):
		b = self.key.encode('utf-8')
		dk = hashlib.pbkdf2_hmac('sha256', b, b, 100000)
		return binascii.hexlify(dk)
		
	def hashNewRoot(self, newRoot):
		b = newRoot.encode('utf-8')
		dk = hashlib.pbkdf2_hmac('sha256', b, b, 100000)
		return binascii.hexlify(dk)
 
	def rc4Encrypt(self, raw): 
		key=self.key
		key=key.ljust(16)
		tempkey = SHA.new(key).digest()
		cipher = ARC4.new(tempkey)
		msg = self.nonce + cipher.encrypt(raw)
		return base64.b64encode(msg)
	
	def aesEncrypt(self, raw):
		ekey=self.key
		ekey=ekey.ljust(16)
		encryption_suite=AES.new(ekey,AES.MODE_CBC, ekey)
		raw=raw.ljust(32)
		cipher_text=encryption_suite.encrypt(raw)
		return base64.b64encode(cipher_text)
		#return binascii.hexlify(cipher_text)
		
	def aesDecrypt(self, enc):
		ekey=self.key
		ekey=ekey.ljust(16)
		decryption_suite = AES.new(ekey,AES.MODE_CBC, ekey)
		cipher_text=base64.b64decode(enc)
		plain_text = decryption_suite.decrypt(cipher_text)
		return plain_text

def testing():
	tempKey='a'
	rawText='4152313174018593ADMINF'
	encObj=Security(tempKey)
	print 'AES'
	encText= encObj.aesEncrypt(rawText)
	print encText
	print encObj.aesDecrypt(encText)

	print 'RC4'
	encText= encObj.rc4Encrypt(rawText) 
	print encText
testing()
	
