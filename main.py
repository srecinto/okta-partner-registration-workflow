import os
import config
import re
import test_init_config

from flask import Flask, request, send_from_directory, redirect, make_response, render_template
from utils.rest import OktaUtil
from utils.db import PartnerDB

"""
GLOBAL VARIABLES ########################################################################################################
"""
app = Flask(__name__)
app.secret_key = "6w_#w*~AVts3!*yd&C]jP0(x_1ssd]MVgzfAw8%fF+c@|ih0s1H&yZQC&-u~O[--"  # For the session

EMAIL_REGEX = re.compile(r"[^@\s]+@[^@\s]+\.[a-zA-Z0-9]+$")


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
        error_list = {
            "messages": [{"message": "Bad user name and/or password"}]
        }
        response = make_response(
            render_template(
                "index.html",
                current_token_info={},
                user={},
                error_list=error_list
            )
        )
        return response


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
    print "handle_register()"
    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])
    is_registration_completed = False
    partner_groups = okta_util.search_groups(config.okta["partner_group_filter_prefix"], config.okta["group_query_limit"])

    # Checks if form entries are valid
    error_list, is_registration_completed = validate_registration(form_data)

    if is_registration_completed:  # No errors
        # Creates the user in Okta
        created_user = create_user(form_data)

        # Puts a record in the DB Approval Queue
        # Emails the respective group/partner admin for approval
        mail_results = email_partner_admins_with_new_registration(form_data)

        print "mail_results: {0}".format(mail_results)

        # Add user to approval queue
        partner_db.create_partner_approval_queue(created_user["id"], form_data["partner"])

    # Prepare response
    response = make_response(render_template(
        "user_registration.html",
        is_registration_completed=is_registration_completed,
        partner_groups=partner_groups,
        error_list=error_list,
        form_data=form_data
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


def handle_admin_partner_approval_queue(group_id):
    print "admin_partner_approval_queue()"
    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])

    group = okta_util.get_group(group_id)
    approval_queue_rows = partner_db.get_partner_approval_queue_by_group(group_id)
    # print "user_ids: {0}".format(user_ids)
    user_id_list = []
    for row in approval_queue_rows:
        user_id_list.append(row["okta_user_id"])

    user_list = okta_util.find_all_users_by_id(user_id_list)

    response = make_response(
        render_template(
            "admin_partner_approval_queue.html",
            group=group,
            user_list=user_list
        )
    )

    return response


def handle_init_test():
    print "handle_init_test()"
    okta_util = OktaUtil(request.headers, config.okta)

    # Create Partner Portal Groups
    print "Creating Partner Portal Groups"
    for group in test_init_config.partner_portal["groups"]:
        group_name = group["profile"]["name"]
        found_group = okta_util.search_groups(group_name, 1)
        if len(found_group) == 0:
            created_group = okta_util.create_group(group)
            print "Created group: {0}".format(created_group["profile"]["name"])
        else:
            print "Group {0} already exsists".format(group_name)

    # Create Partner Portal Admin Users
    print "Creating Partner Portal Admin Users"
    for user in test_init_config.partner_portal["admin_users"]:
        login = user["profile"]["login"]
        found_user = okta_util.find_users_by_login(login)
        if "id" not in found_user:
            okta_util.create_user(user, True)
            print "Created User {0}".format(login)
        else:
            print "User {0} already exsists".format(login)

    # Assign admin roles in DB
    print "Partner Portal Admin Assignments"
    for assignment in test_init_config.partner_portal["admin_group_assignments"]:
        partner_db = PartnerDB(config.okta["db_file_name"])
        login = assignment["login"]
        group_name = assignment["group"]

        found_user = okta_util.find_users_by_login(login)[0]
        found_group = okta_util.search_groups(group_name, 1)[0]

        user_id = found_user["id"]
        group_id = found_group["id"]

        partner_db.delete_user_partner_role(user_id, group_id, "ADMIN")
        result = partner_db.create_user_partner_role(user_id, group_id, "ADMIN")

        okta_util.assign_user_to_group(user_id, group_id)

        print "assignment: {0}".format(result)

    return "done!"


def email_partner_admins_with_new_registration(form_data):
    print "email_partner_admins_with_new_registration()"

    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])

    subject = "A User is requesting access to {group_name}".format(group_name=form_data["partnerName"])
    message = (
        "A person by the name of {first_name} {last_name} is requesting access to "
        "the Partner Portal {group_name} <br />"
        "Click <a href=\"{app_host}/admin/partner_approval_queue/{group_id}\">Here</a> to see the approval queue for this Partner"
    ).format(
        first_name=form_data["firstName"],
        last_name=form_data["lastName"],
        group_name=form_data["partnerName"],
        app_host=config.okta["app_host"],
        group_id=form_data["partner"]
    )

    assignments = partner_db.get_user_partner_role_by_group(form_data["partner"])
    admin_email_list = []

    for assignment in assignments:
        print "assignment: {0}".format(assignment)
        user_id = assignment["okta_user_id"]
        admin_user = okta_util.get_user(user_id)
        print admin_user
        admin_email_list.append({"address": admin_user["profile"]["email"]})

    return okta_util.send_mail(subject, message, admin_email_list)


def create_user(form_data):
    okta_util = OktaUtil(request.headers, config.okta)
    user = {
        "profile": {
            "lastName": form_data["lastName"],
            "firstName": form_data["firstName"],
            "email": form_data["email"],
            "login": form_data["email"],
        },
        "credentials": {
            "password": {"value": form_data["password"]}
        }
    }

    created_user = okta_util.create_user(user)
    print "created_user: {0}".format(created_user)

    return created_user


def validate_registration(form_data):
    print "validate_registration()"
    is_registration_completed = False
    okta_util = OktaUtil(request.headers, config.okta)

    email = form_data["email"]
    password = form_data["password"]
    confirm_password = form_data["confirmPassword"]

    user = okta_util.find_users_by_login(email)

    error_list = {
        "messages": []
    }

    if confirm_password != password:
        error_list["messages"].append(
            {"message": "Confirm Password does not match password"}
        )

    if not EMAIL_REGEX.match(email):
        error_list["messages"].append(
            {"message": "Email is invalid"}
        )

    if len(user) != 0:
        error_list["messages"].append(
            {"message": "User already exsists"}
        )

    if len(error_list["messages"]) == 0:
        is_registration_completed = True

    return error_list, is_registration_completed


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

    response = make_response(
        render_template(
            "index.html",
            current_token_info=current_token_info,
            user=user,
            error_list={}  # No errors by default
        )
    )

    if "token" in request.cookies:
        if request.cookies["token"] == "NO_TOKEN":
            response.set_cookie('token', "")

    # partner_db = PartnerDB(config.okta["db_file_name"])
    # partner_db.test()

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

    response = make_response(
        render_template(
            "user_registration.html",
            is_registration_completed=is_registration_completed,
            partner_groups=partner_groups,
            error_list={},  # No errors by default
            form_data={}
        )
    )

    return response


@app.route("/register", methods=["POST"])
def register():
    print "register()"
    print request.form

    return handle_register(request.form)


@app.route("/admin/partner_approval_queue/<group_id>", methods=["GET"])
def admin_partner_approval_queue(group_id):
    print "admin_partner_approval_queue()"

    return handle_admin_partner_approval_queue(group_id)


# This method is responsible for creating the test users and groups in Okta as well as the DB
@app.route("/init_test", methods=["GET"])
def init_test():
    print "init_test()"

    return handle_init_test()


"""
MAIN ##################################################################################################################
"""
if __name__ == "__main__":
    # This is to run on c9.io.. you may need to change or make your own runner
    print "okta_config: {0}".format(config.okta)
    app.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)))
