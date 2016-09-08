from flask import Flask, render_template,request,redirect,url_for
from user import User
"""Definition of the global variables"""
app = Flask(__name__)
maxSecurityLevel = 4
users = [User("azer", "azer","azer2"), User("hadrien", "h","h2")]

#Index page route
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method=="GET":
        return render_template("index.html")
    else:
        #Check informations about the requesting agent
        sLevel = check_user(request.form["name"], request.environ['HTTP_USER_AGENT'], request.remote_addr)
        #And send to the appropriate login page
        return redirect_login(request.form["name"],sLevel)

"""Check user represent the RiskEval service
It will check if the user, its IP and browser are known
Return an int that match the security (0 light, 4 demands high security)"""
def check_user(uName,httpUserAgent,ip):
    securityLevel = 0
    userKnown=False
    ipFound = False
    browserFound = False
    #go trhough the registered users and check if user exists
    #Then evaluate the risks
    for u in users:
        if u.name == uName:
            userKnown = True
            for ipa in u.IPAddressUsed:
                if ipa == ip:
                    ipFound=True
            if not ipFound:
                securityLevel +=1

            for b in u.browserUsed:
                if b == httpUserAgent:
                    browserFound = True
            if not browserFound:
                securityLevel+=1
    if userKnown:
        return securityLevel
    else:
        return maxSecurityLevel

def redirect_login(uName, securityLevel):
    print "Security level = ",securityLevel
    if securityLevel < maxSecurityLevel:
        #sent in GET => easily avoided => need POST
        return redirect(url_for("login", sl=securityLevel, name=uName))

    else:
        return redirect(url_for("denied"))


@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == "GET":
        if int(request.args['sl']) == 0:
            params = {"name":request.args['name'],"pwd2":"False","sms":"False","SecurityLevel":request.args['sl']}
        elif int(request.args['sl']) == 1 or int(request.args['sl']) == 2:
            params = {"name":request.args['name'], "pwd2":"True","sms":"False", "SecurityLevel":request.args['sl']}
        else:
            params = {"name":request.args['name'], "pwd2":"True","sms":"True", "SecurityLevel":request.args['sl']}
        return render_template("login.html", param=params)
    elif request.method == "POST":
        print "TODO"
        #check the credential
        #add the environment variable to the user if success
    else:
        return redirect(url_for("home"))


@app.route('/denied', methods=["GET", "POST"])
def denied():
    if request.method=="GET":
        return render_template("denied.html")
    else:
        return redirect(url_for("home"))

if __name__ == "__main__":
    app.run()
