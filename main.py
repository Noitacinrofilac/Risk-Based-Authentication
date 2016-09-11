from flask import Flask, render_template,request,redirect,url_for
from authenticationService import AuthenticationService

"""Definition of the global variables"""
app = Flask(__name__)
service = AuthenticationService()

"""Home page
    The user write its name to access the login page"""
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method=="GET":
        return render_template("index.html")
    else:
        #Check informations about the requesting agent
        sLevel = service.eval_user_risk(request.form['name'],request.user_agent,request.remote_addr)
        #And send to the appropriate login page
        return redirect_login(request.form["name"],sLevel)


def redirect_login(uName, securityLevel):
    print "Security level = ",securityLevel
    if securityLevel < service.maxSecurityLevel:
        #sent in GET => easily avoided => need POST
        return redirect(url_for("login", sl=securityLevel, name=uName))
    else:
        return redirect(url_for("denied"))

"""Login page
    The user enter its credential according to the security level"""
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        if int(request.args['sl']) == 0:
            params = {"name":request.args['name'],"pwd2":"False","sms":"False","securityLevel":request.args['sl']}
        elif int(request.args['sl']) == 1 or int(request.args['sl']) == 2:
            params = {"name":request.args['name'], "pwd2":"True","sms":"False", "securityLevel":request.args['sl']}
        else:
            params = {"name":request.args['name'], "pwd2":"True","sms":"True", "securityLevel":request.args['sl']}
        return render_template("login.html", param=params)

    elif request.method == "POST":
        if service.authentication_service(request):
            return redirect(url_for("checkLogs"))
        else:
            return redirect(url_for("home"))
    else:
        return redirect(url_for("home"))

"""The user can check the information about an user using GET request"""
@app.route('/logs', methods=["GET", "POST"])
def checkLogs():
    info = []
    if request.args:
        # retrieve the information asked
        if request.args["name"]:
            info.append(request.args["name"])
            for u in service.users:
                if u.name == request.args['name']:
                    info.append(u.browserUsed)
                    info.append(u.IPAddressUsed)
        print "logs = ", info
    return render_template("logs.html", failed=service.failedConnection, data=info)

"""Denied route
    If a step in the login is wrong the user is redirected here"""
@app.route('/denied', methods=["GET", "POST"])
def denied():
    if request.method=="GET":
        return render_template("denied.html")
    else:
        return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host='0.0.0.0')
