from user import User

class AuthenticationService:
    def __init__(self):
        self.maxSecurityLevel = 4
        self.failedConnection = 0
        #Should be replaced by the db
        self.users_dict = {"azer":User("azer", "azer","azer2"),"hadrien":User("hadrien", "h","h2")}


    """Represent the RiskEval service
    It will check if the user, its IP and browser are known
    Return an int that match the security (0 light, 4 demands high security)"""
    def eval_user_risk(self, uName, user_agent, remote_addr):
        securityLevel = 0
        if not uName in self.users_dict:
            return self.maxSecurityLevel
        u = self.users_dict[uName]
        if not remote_addr in u.IPAddressUsed:
            securityLevel+=1
        if not user_agent in u.browserUsed:
            securityLevel+=1
        # Here we can add more security checks
        # IPInternal / lastFailedLoginDate / ...
        return securityLevel


    """login is the auth service
    it checks using User class if the credential are correct
    it adds a new connection """
    def authentication_service(self, request):
        if (not request.form['name'] in self.users_dict) or (int(request.form['sl']) >= self.maxSecurityLevel):
            self.failedConnection += 1
            return False
        u = self.users_dict.get(request.form['name'])
        if int(request.form['sl']) < 2:
            if not u.light_connection(request.form,request.remote_addr,request.user_agent):
                self.failedConnection +=1
                return False
        elif int(request.form['sl']) < self.maxSecurityLevel:
            if not u.medium_connection(request.form, request.remote_addr, request.user_agent):
                self.failedConnection += 1
                return False
        return True
