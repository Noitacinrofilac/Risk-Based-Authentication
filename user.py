from datetime import datetime

"""Class used to define an user
    Could be represented in a DB"""
class User:
    def __init__(self, name, pwd, pwd2):
        self.name = name
        self.pwd = pwd
        self.pwd2 = pwd2
        self.connectionSuccess=[]
        self.connectionFailed=[]
        self.IPAddressUsed=[]
        self.browserUsed=[]

    """Methods called for a new connection
    Return True if the credential are correct False otherwise
    Add new entry in the connection recap"""
    def light_connection(self,name,pwd):
        if self.name==name and self.pwd==pwd:
            self.connectionSuccess.append(datetime.now)
            return True
        else:
            self.connectionFailed.append(datetime.now)
            return False

    def medium_connection(self,name,pwd,pwd2):
        if self.name==name and self.pwd==pwd and self.pwd2==pwd2:
            self.connectionSuccess.append(datetime.now)
            return True
        else:
            self.connectionFailed.append(datetime.now)
            return False

    """Once the credentials are verified
        Call this method to add user_agent and remote_addr"""
    def add_connection(self,ip,browser):
        ipFound = False
        bFound = False
        for v in self.IPAddressUsed:
            if v == ip:
                ipFound=True
        if not ipFound:
            self.IPAddressUsed.append(ip)

        for v in self.browserUsed:
            if v == browser:
                bFound=True
        if not bFound:
            self.browserUsed.append(str(browser))