from user import User

class AuthenticationService:
    def __init__(self):
        self.maxSecurityLevel = 4
        self.failedConnection = 0
        #Should be replaced by the db
        self.users = [User("azer", "azer","azer2"), User("hadrien", "h","h2")]

    """Represent the RiskEval service
    It will check if the user, its IP and browser are known
    Return an int that match the security (0 light, 4 demands high security)"""
    def eval_user_risk(self, uName, user_agent, remote_addr):
        securityLevel = 0
        userKnown = False
        ipFound = False
        browserFound = False
        # Check if user exists and evaluate the risk
        # Here we can add more security checks
        # IPInternal / lastFailedLoginDate / ...
        for u in self.users:
            if u.name == uName:
                userKnown = True
                for ipa in u.IPAddressUsed:
                    if ipa == remote_addr:
                        ipFound = True
                if not ipFound:
                    securityLevel += 1

                for b in u.browserUsed:
                    if b == str(user_agent):
                        browserFound = True
                if not browserFound:
                    securityLevel += 1
        if userKnown:
            return securityLevel
        else:
            return self.maxSecurityLevel

    """login is the auth service
    it checks using User class if the credential are correct
    it adds a new connection """
    def authentication_service(self, request):
        for u in self.users:
            if u.name == request.form['name']:
                if int(request.form['sl']) < 2:
                    if u.light_connection(request.form['name'], request.form['pwd']):
                        #add the environment variable to the user if success
                        u.add_connection(request.remote_addr, request.user_agent)
                        return True
                elif int(request.form['sl']) < self.maxSecurityLevel:
                    if u.medium_connection(request.form['name'], request.form['pwd'], request.form['pwd2']):
                        #add the environment variable to the user if success
                        u.add_connection(request.remote_addr, request.user_agent)
                        return True
        #User not found
        #Or wrong credential
        self.failedConnection += 1
        return False