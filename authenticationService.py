from user import User

class AuthenticationService:
    def __init__(self):
        self.maxSecurityLevel = 4
        self.failedConnection = 0
        self.users = [User("azer", "azer","azer2"), User("hadrien", "h","h2")]

    """Represent the RiskEval service
    It will check if the user, its IP and browser are known
    Return an int that match the security (0 light, 4 demands high security)"""
    def eval_user_risk(self, request): #uName, httpUserAgent, ip):
        securityLevel = 0
        userKnown = False
        ipFound = False
        browserFound = False
        # go trhough the registered users and check if user exists
        # Then evaluate the risks
        for u in self.users:
            if u.name == request.form["name"]:
                userKnown = True
                for ipa in u.IPAddressUsed:
                    if ipa == request.remote_addr:
                        ipFound = True
                if not ipFound:
                    securityLevel += 1

                for b in u.browserUsed:
                    if b == str(request.user_agent):
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
                if u.new_connection(request.form['name'], request.form['pwd']):
                    #add the environment variable to the user if success
                    u.add_connection( request.remote_addr, request.user_agent)
                    return True
        #User not found
        #Or wrong credential
        self.failedConnection += 1
        return False