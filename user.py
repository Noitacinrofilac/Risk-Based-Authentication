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
    def light_connection(self,form,ipaddr,ua):
        if self.name==form['name'] and self.pwd==form['pwd']:
            self.connectionSuccess.append(datetime.now)
            self.add_connection(ipaddr, ua)
            return True
        else:
            self.connectionFailed.append(datetime.now)
            return False

    def medium_connection(self,form,ipaddr,ua):
        if self.name==form['name'] and self.pwd==form['pwd'] and self.pwd2==form['pwd2']:
            self.connectionSuccess.append(datetime.now)
            self.add_connection(ipaddr,ua)
            return True
        else:
            self.connectionFailed.append(datetime.now)
            return False

    """Once the credentials are verified
        Call this method to add user_agent and remote_addr"""
    def add_connection(self,ip,ua):
        if not ip in self.IPAddressUsed:
            self.IPAddressUsed.append(ip)
        if not ua in self.browserUsed:
            self.browserUsed.append(ua)

