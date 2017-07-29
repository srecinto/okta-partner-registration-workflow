import os
import config

from flask import Flask, request, send_from_directory, redirect, make_response, render_template
from utils.rest import OktaUtil
from utils.db import PartnerDB

"""
GLOBAL VARIABLES ########################################################################################################
"""
app = Flask(__name__)
app.secret_key = "6w_#w*~AVts3!*yd&C]jP0(x_1ssd]MVgzfAw8%fF+c@|ih0s1H&yZQC&-u~O[--"  # For the session


"""
UTILS ###################################################################################################################
"""


def get_oauth_token(oauth_code):
    print "get_oauth_token()"
    okta_util = OktaUtil(request.headers, config.okta)

    oauth_token_response_json = okta_util.get_oauth_token(oauth_code, config.okta["redirect_uri"])
    print "oauth_token_response_json: {0}".format(oauth_token_response_json)

    return oauth_token_response_json["access_token"]


def get_session_token(username, password):
    print "get_session_token()"
    okta_util = OktaUtil(request.headers, config.okta)
    session_token = None

    authn_reponse_json = okta_util.get_session_token(username, password)
    if "sessionToken" in authn_reponse_json:
        session_token = authn_reponse_json["sessionToken"]

    return session_token


def handle_login(form_data):
    print "handle_login()"

    # Authenticate via Okta API to get Session Token
    user = form_data["username"]
    password = form_data["password"]
    session_token = None
    try:
        session_token = get_session_token(username=user, password=password)
    except ValueError as err:
        print(err.args)

    print "session_token: {0}".format(session_token)

    # Use Session Token to generatet OIDC Auth Code URL
    if(session_token):
        okta_util = OktaUtil(request.headers, config.okta)
        oidc_auth_code_url = okta_util.create_oidc_auth_code_url(
            session_token,
            config.okta["oidc_client_id"],
            config.okta["redirect_uri"])

        print "url: {0}".format(oidc_auth_code_url)
        # redirect to User Auth Code URL to Get OIDC Code
        return redirect(oidc_auth_code_url)

    else:
        user = None
        current_token_info = get_current_user_token()
        error_list = {
            "messages": [{"message": "Bad user name and/or password"}]
        }
        response = make_response(render_template("index.html",
            current_token_info={},
            user=user,
            error_list=error_list
        ))
        return response # make_response(redirect("/"))


def handle_logout():
    print "handle_logout()"
    redirect_url = "{host}/login/signout?fromURI={redirect_path}".format(
        host=config.okta["org_host"],
        redirect_path=config.okta["app_host"]
    )

    print "redirect_url: {0}".format(redirect_url)

    response = make_response(redirect(redirect_url))
    response.set_cookie('token', "")

    return response


# Checks if form entries are valid
# Creates the user in Okta
# Puts a record in the DB Approval Queue
# Emails the respective group/partner admin for approval
# Displays the success screen to the end user
def handle_register(form_data):
    print "handle_logout()"
    okta_util = OktaUtil(request.headers, config.okta)
    is_registration_completed = False
    partner_groups = okta_util.search_groups(config.okta["partner_group_filter_prefix"], config.okta["group_query_limit"])

    first_name = form_data["firstName"]
    last_name = form_data["lastName"]
    email = form_data["email"]
    password = form_data["password"]

    # Checks if form entries are valid
    #
    #
    #
    error_list = {
        "messages": [
            {"message": "Error message 1"},
            {"message": "Something about an error message 2"}
        ]
    }
    if False:  #Everything passes
        is_registration_completed = True

            # Creates the user in Okta
        user = {
            "profile": {
                "lastName": last_name,
                "firstName": first_name,
                "email": email,
                "login": email,
            },
            "credentials": {
                "password": { "value": password }
            }
        }

        created_user = okta_util.create_user(user)
        print "created_user: {0}".format(created_user)

        # Puts a record in the DB Approval Queue
        # Emails the respective group/partner admin for approval
        group_name = ""
        group_id = ""
        subject = "A User is requesting access to {group_name}".format(group_name=group_name)
        message = (
            "A person by the name of {first_name} {last_name} is requesting access to "
            "the Partner Portal {group_name} <br />"
            "Click <a href='/admin/partner_approval_queue/{group_id}'>Here</a> to see the approval queue for this Partner"
        ).format(
            first_name=first_name,
            last_name=last_name,
            group_name=group_name,
            group_id=group_id
        )

        admin_email_list = {}

        mail_results = okta_util.send_mail(subject, message, admin_email_list)
        print "mail_results: {0}".format(mail_results)



    # Prepare response
    response = make_response(render_template(
        "user_registration.html",
        is_registration_completed=is_registration_completed,
        partner_groups=partner_groups,
        error_list=error_list
    ))

    """
    activation_url = "{app_host}/{activation_token}".format(
        app_host=config.okta["app_host"],
        activation_token=created_user["id"]
    )

    print "activation_url: {0}".format(activation_url)

    # Email Activation link to user

    """

    return response


def get_current_user_token():
    print "get_current_user_token()"
    user_results_json = None
    okta_util = OktaUtil(request.headers, config.okta)

    if("token" in request.cookies):
        introspection_results_json = okta_util.introspect_oauth_token(request.cookies.get("token"))

        if("active" in introspection_results_json):
            if(introspection_results_json["active"]):
                print "Has active token"
                user_results_json = {
                    "active": introspection_results_json["active"],
                    "username": introspection_results_json["username"],
                    "uid": introspection_results_json["uid"]
                }
            else:
                print "Has inactive token"
        else:
            print "has inactive token error"
            check_okta_session_url = okta_util.create_oidc_auth_code_url(None, config.okta["oidc_client_id"], config.okta["redirect_uri"])
            user_results_json = {
                "active": False,
                "redirect_url": check_okta_session_url
            }
    else:
        print "has no token"
        check_okta_session_url = okta_util.create_oidc_auth_code_url(None, config.okta["oidc_client_id"], config.okta["redirect_uri"])
        user_results_json = {
            "active": False,
            "redirect_url": check_okta_session_url
        }

    if(not user_results_json):
        print "has no token default"
        user_results_json = {
            "active": False
        }

    return user_results_json


def get_current_user(user_token_data):
    print "get_current_user()"
    current_user = None

    if "uid" in user_token_data:
        user_id = user_token_data["uid"]
        print "Looking up user by id: {0}".format(user_id)
        okta_util = OktaUtil(request.headers, config.okta)
        current_user = okta_util.get_user(user_id)

    return current_user


"""
ROUTES ##################################################################################################################
"""


@app.route('/<path:filename>')
def serve_static_html(filename):
    print "serve_static_html('{0}')".format(filename)
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static'), filename)


@app.route("/", methods=["GET"])
def root():
    print "root()"

    user = None
    current_token_info = get_current_user_token()
    print "current_token_info: {0}".format(current_token_info)
    if current_token_info["active"]:
        user = get_current_user(current_token_info)
        print "user: {0}".format(user)
    # SR: Removed this to allow for client side checking of an Okta session
    # This will do a full screen redirect
    # elif "redirect_url" in current_token_info:
    #    return redirect(current_token_info["redirect_url"])

    response = make_response(render_template("index.html",
        current_token_info=current_token_info,
        user=user,
        error_list={} # No errors by default
    ))
    if "token" in request.cookies:
        if request.cookies["token"] == "NO_TOKEN":
            response.set_cookie('token', "")

    partner_db = PartnerDB(config.okta["db_file_name"])
    partner_db.test()

    return response


@app.route("/login", methods=["POST"])
def login():
    print "login()"
    print request.form

    return handle_login(request.form)


@app.route("/logout", methods=["GET"])
def logout():
    print "logout()"

    return handle_logout()


@app.route("/oidc", methods=["POST"])
def oidc():
    print "oidc()"
    print request.form

    redirect_url = ""

    if("error" in request.form):
        oauth_token = "NO_TOKEN"
        redirect_url = config.okta["app_host"]
    else:
        oidc_code = request.form["code"]
        print "oidc_code: {0}".format(oidc_code)
        oauth_token = get_oauth_token(oidc_code)
        redirect_url = config.okta["post_oidc_redirect"]

    response = make_response(redirect(redirect_url))
    response.set_cookie('token', oauth_token)
    return response


@app.route("/user_registration", methods=["GET"])
def user_registration():
    print "user_registration()"

    okta_util = OktaUtil(request.headers, config.okta)

    is_registration_completed = False
    partner_groups = okta_util.search_groups(config.okta["partner_group_filter_prefix"], config.okta["group_query_limit"])

    response = make_response(render_template("user_registration.html",
        is_registration_completed=is_registration_completed,
        partner_groups=partner_groups,
        error_list={} # No errors by default
    ))

    return response

@app.route("/register", methods=["POST"])
def register():
    print "register()"
    print request.form

    return handle_register(request.form)


"""
MAIN ##################################################################################################################
"""
if __name__ == "__main__":
    # This is to run on c9.io.. you may need to change or make your own runner
    print "okta_config: {0}".format(config.okta)
    app.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)))
