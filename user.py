from datetime import datetime


class User:
    def __init__(self, name, pwd, pwd2):
        self.name = name
        self.pwd = pwd
        self.pwd2 = pwd2
        self.connectionSuccess=[]
        self.connectionFailed=[]
        self.IPAddressUsed=[]
        self.browserUsed=[]

    """Method called for a new connection
    Return True if the credential are correct False otherwise
    Add new entry in the connection recap"""
    def new_connection(self,name,pwd):
        if self.name==name and self.pwd==pwd:
            self.connectionSuccess.append(datetime.now)
            return True
        else:
            self.connectionFailed.append(datetime.now)
            return False
