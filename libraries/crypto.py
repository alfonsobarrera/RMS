import base64
import bcrypt


class Security:

    def getHash(self, password, salt=None):
        pword=password.encode("utf-8")
        if not salt:
            salt=bcrypt.gensalt(14)
            salt=salt.encode("utf-8")
            print "Salt is none"
        else:
            print "Salt is not none", salt
            salt=salt.encode("utf-8")
        hashed = bcrypt.hashpw(pword, salt)
        return hashed,salt

    def checkHash(self, inputParam, hashed, salt):
        tbcHash, tbcSalt= self.getHash(inputParam, salt)
        if tbcHash==hashed:
            return True
        else:
            return False
    

def testFunction():
    ahash,salt=Security().getHash("xoxoincubus")
    print ahash,salt
    r=Security().checkHash("xoxoincubus", ahash, salt)
    print r
#testFunction()
