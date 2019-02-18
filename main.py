import os
import config
import re
import test_init_config
import json
import base64

from functools import wraps
from flask import Flask, request, send_from_directory, redirect, make_response, render_template, abort
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

def decode_base64(data):
    print "decode_base64()"
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)
    return json.loads(base64.b64decode(data))


def get_user_info_from_token(token):
    print "get_token_data()"
    print "token: {0}".format(token)
    broke_token = token.split(".")
    print "broke_token: {0}".format(broke_token[1])
    user_info = decode_base64(broke_token[1])
    return user_info


def authorize_partner(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        print "authorize_partner check()"
        is_admin = False
        if not "token" in request.cookies:
           return make_response(redirect("{0}/show_login".format(config.okta["app_host"])))

        user_token = None
        try:
            user_token = get_current_user_token()
            if user_token["active"]:
                token = request.cookies.get("token")
                user_info = get_user_info_from_token(token)
                print user_info
                # Bacsic admin check.  YOu can add more robust checks here
                if "groups" in user_info:
                    for group in user_info["groups"]:
                        print "group: {0}".format(group)
                        if (
                            (
                                group.find(config.okta["partner_group_filter_prefix"]) != -1 and
                                group.find(config.okta["partner_group_filter_suffix"]) != -1
                            ) or (
                                group == config.okta["admin_okta_group_name"] != -1
                            )
                        ):
                            is_admin = True
                            break

                if "admin_group" in user_info:
                    for group in user_info["admin_group"]:
                        if  group == config.okta["admin_okta_group_name"] != -1:
                            is_admin = True
                            break
            else:
                return make_response(redirect("{0}/show_login".format(config.okta["app_host"])))

        except:
            abort(401)

        if not is_admin:
            abort(401)

        return f(*args, **kws)
    return decorated_function


def authorize_admin(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        print "authorize_admin check()"
        is_admin = False
        if not "token" in request.cookies:
           return make_response(redirect("{0}/show_login".format(config.okta["app_host"])))

        user_token = None
        try:
            user_token = get_current_user_token()
            if user_token["active"]:
                token = request.cookies.get("token")
                user_info = get_user_info_from_token(token)
                print user_info
                # Bacsic admin check.  YOu can add more robust checks here
                if "admin_group" in user_info:
                    for group in user_info["admin_group"]:
                        print "group: {0}".format(group)
                        if group == config.okta["admin_okta_group_name"] != -1:
                            is_admin = True
                else:
                    abort(401)
            else:
                return make_response(redirect("{0}/show_login".format(config.okta["app_host"])))

        except:
            abort(401)

        if not is_admin:
            abort(401)

        return f(*args, **kws)
    return decorated_function


def authenticated(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        print "authenticated()"
        user = get_current_user()

        if not user:
            return make_response(redirect("{0}/show_login".format(config.okta["app_host"])))

        return f(*args, **kws)
    return decorated_function


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
    okta_util = OktaUtil(request.headers, config.okta)

    # Authenticate via Okta API to get Session Token
    session_token = None
    try:
        if "auth_token" in form_data:
            session_token = okta_util.authenticate_via_activation_token(form_data["auth_token"])
        else:
            session_token = get_session_token(username=form_data["username"], password=form_data["password"])
    except ValueError as err:
        print(err.args)

    print "session_token: {0}".format(session_token)

    # Use Session Token to generatet OIDC Auth Code URL
    if(session_token):
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
                "login.html",
                user={},
                error_list=error_list,
                form_data={},
                okta_config=config.okta,
                is_admin=False
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
    print form_data
    is_registration_completed = False
    okta_util = OktaUtil(request.headers, config.okta)
    partner_groups = okta_util.search_groups(config.okta["partner_group_filter_prefix"], config.okta["group_query_limit"])
    partner_db = PartnerDB(config.okta["db_file_name"])
    roles = partner_db.get_roles()

    # Checks if form entries are valid
    error_list, is_registration_completed = validate_registration(form_data)

    if is_registration_completed:  # No errors
        is_registration_completed = True
        # Creates the user in Okta
        created_user = create_user(form_data)

        email_activation_link_to_user(form_data, created_user["id"])

        login_data = {
            "username": form_data["email"],
            "password": form_data["password"]
        }

        # Add user to webiste group for access
        okta_util.assign_user_to_group(created_user["id"], config.okta["app_okta_group_id"])

        # Puts a record in the DB Approval Queue
        # Emails the respective group/partner admin for approval

        partner_admin_group_name = None
        partner_admin_group_id = None
        for group in partner_groups:
            if group["id"] == form_data["partner"]:
                partner_admin_group_name = "{0}{1}".format(group["profile"]["name"], config.okta["partner_group_filter_suffix"])
                break

        print "partner_admin_group_name: {0}".format(partner_admin_group_name)

        for group in partner_groups:
            if group["profile"]["name"] == partner_admin_group_name:
                partner_admin_group_id = group["id"]

        print "partner_admin_group_id: {0}".format(partner_admin_group_id)

        json = {
            "user_id": created_user["id"],
            "group_id": form_data["partner"],
            "partner_admin_group_id": partner_admin_group_id
        }
        if "ADMIN" == form_data["role"]:
            handle_partner_admin_request(json)
        else:
            handle_partner_user_request(json)


    # Prepare response
    response = make_response(render_template(
        "register.html",
        is_registration_completed=is_registration_completed,
        partner_groups=partner_groups,
        error_list=error_list,
        form_data=form_data,
        roles_list=roles,
        okta_config=config.okta
    ))

    return response

def handle_partner_admin_request(post_json):
    print "handle_partner_admin_request()"
    print post_json
    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])
    user = okta_util.get_user(post_json["user_id"])
    group = okta_util.get_group(post_json["group_id"])
    admin_group = okta_util.get_group(config.okta["admin_okta_group_id"])
    dealer_admin_group = None
    dealer_admin_search_results = okta_util.search_groups("{0}{1}".format(group["profile"]["name"], config.okta["partner_group_filter_suffix"]), 1)
    if(len(dealer_admin_search_results) != 0):
        dealer_admin_group = dealer_admin_search_results[0]

    if(dealer_admin_group):
        partner_db.create_partner_admin_approval_queue(post_json["user_id"], dealer_admin_group["id"])
    else:
        partner_db.create_partner_admin_approval_queue(post_json["user_id"], group["id"])

    subject = "The user {first_name} {last_name} is requesting ADMIN access to {group_name}".format(
            first_name=user["profile"]["firstName"],
            last_name=user["profile"]["lastName"],
            group_name=group["profile"]["name"]
        )
    message = (
        "The user {first_name} {last_name} is requesting ADMIN access to {group_name}. <br />"
        "Click <a href='{app_host}/admin/admin_approval_queue/'>here</a> to manage the Admin approval queue."
    ).format(
        first_name=user["profile"]["firstName"],
        last_name=user["profile"]["lastName"],
        app_host=config.okta["app_host"],
        group_name=post_json["group_id"]
    )
    admin_user_list = okta_util.get_group_users(admin_group["id"])
    admin_email_list = []

    for admin_user in admin_user_list:
        admin_email_list.append({"address": admin_user["profile"]["email"]})

    okta_util.send_mail(subject, message, admin_email_list)

    return "SUCCESS"

def handle_partner_user_request(post_json):
    print "handle_partner_user_request()"
    print post_json
    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])
    user = okta_util.get_user(post_json["user_id"])
    group = okta_util.get_group(post_json["group_id"])
    admin_group = okta_util.get_group(post_json["partner_admin_group_id"])

    partner_db.create_partner_approval_queue(post_json["user_id"], post_json["group_id"])

    subject = "The user {first_name} {last_name} is requesting USER access to {group_name}".format(
            first_name=user["profile"]["firstName"],
            last_name=user["profile"]["lastName"],
            group_name=group["profile"]["name"]
        )
    message = (
        "The user {first_name} {last_name} is requesting USER access to {group_name}. <br />"
        "Click <a href='{app_host}/admin/partner_approval_queue/{group_id}'>here</a> to manage the Admin approval queue."
    ).format(
        first_name=user["profile"]["firstName"],
        last_name=user["profile"]["lastName"],
        app_host=config.okta["app_host"],
        group_name=group["profile"]["name"],
        group_id=post_json["group_id"]
    )
    admin_user_list = okta_util.get_group_users(admin_group["id"])
    admin_email_list = []

    for admin_user in admin_user_list:
        admin_email_list.append({"address": admin_user["profile"]["email"]})

    okta_util.send_mail(subject, message, admin_email_list)

    return "SUCCESS"

def handle_admin():
    print "handle_admin"
    okta_util = OktaUtil(request.headers, config.okta)
    is_admin = False
    is_partner_admin = False
    user = get_current_user(add_groups=True)
    group = {}
    #is_admin(user)
    #is_current_partner_admin(user, user["profile"]["current_dlr"])

    print "user: {0}".format(user["profile"])
    if "current_dlr" in user["profile"]:
        group = okta_util.get_group(user["profile"]["current_dlr"])
        is_partner_admin = True
        if group["profile"]["name"] == config.okta["admin_okta_group_name"] != -1:
            is_admin = True
    else:
        groups = okta_util.get_user_groups(user["id"])
        for group in groups:
            if group["profile"]["name"] == config.okta["admin_okta_group_name"] != -1:
                is_admin = True
                break

    response = make_response(render_template(
        "admin.html",
        okta_config=config.okta,
        user=user,
        group=group,
        is_admin=is_admin,
        is_partner_admin=is_partner_admin
    ))

    return response

def handle_admin_application_request(post_json):
    print "handle_admin_application_request()"
    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])
    user = okta_util.get_user(post_json["user_id"])
    group = okta_util.get_group(post_json["group_id"])
    app_list = okta_util.find_all_apps_by_id(post_json["app_ids"])

    for app_id in post_json["app_ids"]:
        partner_db.create_application_approval_queue(post_json["user_id"], post_json["group_id"], app_id)

    subject = "The user {first_name} {last_name} is requesting access to some apps".format(
            first_name=user["profile"]["firstName"],
            last_name=user["profile"]["lastName"]
        )
    message = (
        "The user {first_name} {last_name} is requesting access to some apps. <br />"
        "Click <a href='{app_host}/admin/application_approval_queue/{group_id}'>here</a> to manage the Application approval queue."
    ).format(
        first_name=user["profile"]["firstName"],
        last_name=user["profile"]["lastName"],
        app_host=config.okta["app_host"],
        group_id=post_json["group_id"]
    )
    admin_group_name = "{0}{1}".format(group["profile"]["name"], config.okta["partner_group_filter_suffix"])
    admin_group_list = okta_util.search_groups(admin_group_name, 1)
    admin_user_list = okta_util.get_group_users(admin_group_list[0]["id"])
    admin_email_list = []

    for admin_user in admin_user_list:
        admin_email_list.append({"address": admin_user["profile"]["email"]})

    okta_util.send_mail(subject, message, admin_email_list)

    return "SUCCESS"


def handle_admin_approval_queue():
    print "handle_admin_approval_queue()"

    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])

    is_admin = False
    is_partner_admin = False
    user = get_current_user(add_groups=True)
    users_approval_list = partner_db.get_partner_admin_approval_queue()

    user_group = {
        "list": []
    }

    for user_approval in users_approval_list:
        user = okta_util.get_user(user_approval["okta_user_id"])
        print "Get Group by Id: {0}".format(user_approval["okta_group_id"])
        group = okta_util.get_group(user_approval["okta_group_id"])
        user_group["list"].append({ "user":  user, "group": group})

    # print "user_group_list: {0}".format(user_group_list)
    # print "user_group[list].group: {0}".format(json.dumps(user_group["list"][0]["group"], indent=4, sort_keys=True))
    response = make_response(render_template(
        "admin_approval_queue.html",
        okta_config=config.okta,
        user_group=user_group,
        user=user,
        is_admin=is_admin,
        is_partner_admin=is_partner_admin
    ))

    return response


def handle_admin_application_approval_queue(group_id):
    print "handle_admin_application_approval_queue()"
    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])
    current_user = get_current_user(add_groups=True)

    group = okta_util.get_group(group_id)
    approval_queue_rows = partner_db.get_application_approval_queue_by_group(group_id)
    # print "user_ids: {0}".format(user_ids)
    app_list = []
    for row in approval_queue_rows:
        user = okta_util.get_user(row["okta_user_id"])
        app = okta_util.get_application(row["okta_app_id"])
        app_response = {
            "id": app["id"],
            "label": app["label"],
            "user": {
                "id": user["id"],
                "profile": {
                    "firstName": user["profile"]["firstName"],
                    "lastName": user["profile"]["lastName"],
                    "email": user["profile"]["email"]
                }
            }
        }

        print "app_response: {0}".format(app_response)
        app_list.append(app_response)

    # print "current_user: {0}".format(json.dumps(current_user, indent=4, sort_keys=True))

    response = make_response(
        render_template(
            "admin_application_approval_queue.html",
            user=current_user,
            group=group,
            app_list=app_list,
            okta_config=config.okta
        )
    )

    return response


def handle_admin_partner_approval_queue(group_id):
    print "admin_partner_approval_queue()"
    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])

    is_admin = False
    is_partner_admin = False
    user = get_current_user(add_groups=True)

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
            user=user,
            user_list=user_list,
            okta_config=config.okta,
            is_admin=is_admin,
            is_partner_admin=is_partner_admin
        )
    )

    return response


def handle_admin_approve_partner_access(group_id, user_id):
    print "handle_admin_approve_partner_access()"
    okta_util = OktaUtil(request.headers, config.okta)
    user = okta_util.get_user(user_id)
    group = okta_util.get_group(group_id)

    # Check Primary Partner If non, add this to primary
    if "primary_dlr" not in user["profile"]:
        user["profile"]["primary_dlr"] = group["id"]
        user["profile"]["current_dlr"] = group["id"]
        okta_util.update_user(user)

    # Add to Partner List
    # Grant Group Acess
    okta_util.assign_user_to_group(user["id"], group["id"])

    # Update user profile to add user to the group
    if config.okta["user_group_access_list"] not in user["profile"]:
        user["profile"][config.okta["user_group_access_list"]] = []


    user["profile"][config.okta["user_group_access_list"]].append(group["profile"]["description"].replace(config.okta["user_current_group_desc_mapping_prefix"], ""))
    okta_util.update_user(user)

    # Remove request record from db
    partner_db = PartnerDB(config.okta["db_file_name"])
    partner_db.delete_partner_approval_queue(user["id"], group["id"])

    # Email acceptance
    subject = "Your access to {group_name} has been approved!".format(group_name=group["profile"]["name"])
    message = "Your access to {group_name} has been approved!".format(group_name=group["profile"]["name"])
    recipients = [{"address": user["profile"]["email"]}]
    okta_util.send_mail(subject, message, recipients)

    return make_response(redirect("{app_host}/admin/partner_approval_queue/{group_id}".format(app_host=config.okta["app_host"], group_id=group["id"])))


def handle_admin_approve_partner_admin_access(group_id, user_id):
    print "handle_admin_approve_partner_admin_access()"
    okta_util = OktaUtil(request.headers, config.okta)
    user = okta_util.get_user(user_id)
    admin_group = okta_util.get_group(group_id)
    dealer_group = okta_util.search_groups(admin_group["profile"]["name"].replace(config.okta["partner_group_filter_suffix"],""), 1)[0]

    # Check Primary Partner If non, add this to primary
    if "primary_dlr" not in user["profile"]:
        user["profile"]["primary_dlr"] = dealer_group["id"]
        user["profile"]["current_dlr"] = dealer_group["id"]
        okta_util.update_user(user)

    # Add to Partner List
    # Grant Group Acess
    okta_util.assign_user_to_group(user["id"], admin_group["id"])
    okta_util.assign_user_to_group(user["id"], dealer_group["id"])

    # Remove request record from db
    partner_db = PartnerDB(config.okta["db_file_name"])
    partner_db.delete_partner_admin_approval_queue(user["id"], admin_group["id"])

    # Email acceptance
    subject = "Your ADMIN access to {group_name} has been approved!".format(group_name=admin_group["profile"]["name"])
    message = "Your ADMIN access to {group_name} has been approved!".format(group_name=admin_group["profile"]["name"])
    recipients = [{"address": user["profile"]["email"]}]
    okta_util.send_mail(subject, message, recipients)

    return make_response(redirect("{app_host}/admin/admin_approval_queue".format(app_host=config.okta["app_host"])))


def handle_admin_approve_application_access(group_id, user_id, app_id):
    print "handle_admin_approve_application_access()"
    okta_util = OktaUtil(request.headers, config.okta)
    user = okta_util.get_user(user_id)
    group = okta_util.get_group(group_id)
    app = okta_util.get_application(app_id)

    # Add to Partner List
    # Grant App Acess

    # HACK need to fix before comitting into github
    if app["id"] == "0oaxtkqtmiEzP1qNR2p5":
        okta_util.assign_user_to_group(user["id"], "00g1a6tb6UIKbxm1Q2p6") #SalesForceChatter group in okta
    else:
        okta_util.assign_user_to_app(user["id"], app["id"])

    # Remove request record from db
    partner_db = PartnerDB(config.okta["db_file_name"])
    partner_db.delete_application_approval_queue(user["id"], group["id"], app["id"])

    # Email acceptance
    subject = "Your access to {app_name} has been approved!".format(app_name=app["label"])
    message = "Your access to {app_name} for {group_name} has been approved!".format(
        app_name=app["label"],
        group_name=group["profile"]["name"]
    )
    recipients = [{"address": user["profile"]["email"]}]
    okta_util.send_mail(subject, message, recipients)

    return make_response(redirect("{app_host}/admin/application_approval_queue/{group_id}".format(app_host=config.okta["app_host"], group_id=group_id)))


def handle_admin_deny_partner_access(group_id, user_id):
    print "handle_admin_deny_partner_access()"
    okta_util = OktaUtil(request.headers, config.okta)
    user = okta_util.get_user(user_id)
    group = okta_util.get_group(group_id)
    # Email Denial

    subject = "Your request to access {group_name} has been rejected".format(group_name=group["profile"]["name"])
    message = "We are sorry to inform you that your request for access to {group_name} was rejected.".format(group_name=group["profile"]["name"])
    recipients = [{"address": user["profile"]["email"]}]
    okta_util.send_mail(subject, message, recipients)

    # Remove request record from db
    partner_db = PartnerDB(config.okta["db_file_name"])
    partner_db.delete_partner_approval_queue(user["id"], group["id"])

    return make_response(redirect("{app_host}/admin/partner_approval_queue/{group_id}".format(app_host=config.okta["app_host"], group_id=group["id"])))

def handle_admin_deny_partner_admin_access(group_id, user_id):
    print "handle_admin_deny_partner_admin_access()"
    okta_util = OktaUtil(request.headers, config.okta)
    user = okta_util.get_user(user_id)
    group = okta_util.get_group(group_id)
    # Email Denial

    subject = "Your request to access {group_name} has been rejected".format(group_name=group["profile"]["name"])
    message = "We are sorry to inform you that your request for access to {group_name} was rejected.".format(group_name=group["profile"]["name"])
    recipients = [{"address": user["profile"]["email"]}]
    okta_util.send_mail(subject, message, recipients)

    # Remove request record from db
    partner_db = PartnerDB(config.okta["db_file_name"])
    partner_db.delete_partner_admin_approval_queue(user["id"], group["id"])

    return make_response(redirect("{app_host}/admin/admin_approval_queue".format(app_host=config.okta["app_host"])))

def handle_admin_deny_application_access(group_id, user_id, app_id):
    print "handle_admin_deny_application_access()"
    okta_util = OktaUtil(request.headers, config.okta)
    user = okta_util.get_user(user_id)
    group = okta_util.get_group(group_id)
    app = okta_util.get_application(app_id)
    # Email Denial

    subject = "Your request to access {app_name} has been rejected".format(app_name=app["label"])
    message = "We are sorry to inform you that your request for access {app_name} for {group_name} was rejected.".format(
        app_name=app["label"],
        group_name=group["profile"]["name"]
    )
    recipients = [{"address": user["profile"]["email"]}]
    okta_util.send_mail(subject, message, recipients)

    # Remove request record from db
    partner_db = PartnerDB(config.okta["db_file_name"])
    partner_db.delete_application_approval_queue(user["id"], group["id"], app["id"])

    return make_response(redirect("{app_host}/admin/application_approval_queue/{group_id}".format(app_host=config.okta["app_host"], group_id=group["id"])))


def handle_activate(user_id):
    print "handle_activate()"

    okta_util = OktaUtil(request.headers, config.okta)
    activate_response = okta_util.activate_user(user_id)
    print "activate_response: {0}".format(activate_response)

    if "activationToken" in activate_response:
        activation_token = activate_response["activationToken"]
        print "activation_token: {0}".format(activation_token)

    # Took this out because the MFA Enroll status was breaking the auto login
    # handle_login({ "auth_token": activation_token })

    #return make_response(redirect(config.okta["app_host"]))
    return make_response(redirect("{0}/show_login".format(config.okta["app_host"])))


def handle_activate_all():
    print "handle_activate_all()"

    okta_util = OktaUtil(request.headers, config.okta)
    staged_users = okta_util.find_users_by_status("STAGED")

    print "Staged User Count: {0}".format(len(staged_users))

    for user in staged_users:
        email_activation_link_to_user({"email": user["profile"]["email"]}, user["id"])
        # handle_activate(user["id"])

    return make_response(redirect("{0}/show_login".format(config.okta["app_host"])))


def handle_init_test():
    print "handle_init_test()"
    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])

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

        found_group_db_data = partner_db.get_partner_profile_by_group(group_name)

        if found_group_db_data == None:
            if "zip" in group["profile"]:
                print "Group Profile: {0} not in DB"
                result = partner_db.create_partner_profile(group_name, group["profile"]["zip"])


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


def email_activation_link_to_user(form_data, user_id):
    print "email_activation_link_to_user()"
    okta_util = OktaUtil(request.headers, config.okta)

    subject = "Welcome to the {app_title}".format(app_title=config.okta["app_title"])
    message = (
        "Welcome to the {app_title}! Click this link to activate your account <br />"
        "<a href='{activation_link}'>{activation_link}</a>").format(
            app_title=config.okta["app_title"],
            activation_link="{app_host}/activate/{user_id}".format(app_host=config.okta["app_host"], user_id=user_id)
        )

    return okta_util.send_mail(subject, message, [{"address" : form_data["email"]}])


def email_partner_admins_with_new_registration(form_data):
    print "email_partner_admins_with_new_registration()"

    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])

    subject = "A User is requesting {role} access to {group_name}".format(role=form_data["role"], group_name=form_data["partnerName"])
    message = (
        "A person by the name of {first_name} {last_name} is requesting {role} access to "
        "the Partner Portal {group_name} <br />"
        "Click <a href=\"{app_host}/admin/partner_approval_queue/{group_id}\">Here</a> to see the approval queue for this Partner"
    ).format(
        first_name=form_data["firstName"],
        last_name=form_data["lastName"],
        group_name=form_data["partnerName"],
        app_host=config.okta["app_host"],
        group_id=form_data["partner"],
        role=form_data["role"]
    )
    group_name = "{0}{1}".format(form_data["partnerName"], config.okta["partner_group_filter_suffix"])
    group_list = okta_util.search_groups(group_name, 1)
    user_list = okta_util.get_group_users(group_list[0]["id"])
    admin_email_list = []

    for user in user_list:
        admin_email_list.append({"address": user["profile"]["email"]})

    return okta_util.send_mail(subject, message, admin_email_list)


def email_org_admins_with_admin_request(form_data):
    print "email_org_admins_with_admin_request()"

    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])

    subject = "A User is requesting {role} access to {group_name}".format(role=form_data["role"], group_name=form_data["partnerName"])
    message = (
        "A person by the name of {first_name} {last_name} is requesting {role} access to "
        "the Partner Portal {group_name} <br />"
        "Click <a href=\"{app_host}/admin/partner_admin_approval_queue/{group_id}\">Here</a> to see the admin approval queue for this Partner"
    ).format(
        first_name=form_data["firstName"],
        last_name=form_data["lastName"],
        group_name=form_data["partnerName"],
        app_host=config.okta["app_host"],
        group_id=form_data["partner"],
        role=form_data["role"]
    )

    portal_admins = okta_util.find_users_by_attribute(config.okta["partner_admin_ud_indicator_attribute"], "true")
    admin_email_list = []

    for admin_user in portal_admins:
        print admin_user
        admin_email_list.append({"address": admin_user["profile"]["email"]})

    return okta_util.send_mail(subject, message, admin_email_list)


def create_user(form_data):
    print "create_user()"
    okta_util = OktaUtil(request.headers, config.okta)
    user = {
        "profile": {
            "lastName": form_data["lastName"],
            "firstName": form_data["firstName"],
            "email": form_data["email"],
            "login": form_data["email"]
        },
        "credentials": {
            "password": {"value": form_data["password"]}
        }
    }

    created_user = okta_util.create_user(user, activate_user=False)
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
                check_okta_session_url = okta_util.create_oidc_auth_code_url(None, config.okta["oidc_client_id"], config.okta["redirect_uri"])
                user_results_json = {
                    "active": False,
                    "redirect_url": check_okta_session_url
                }
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


def get_current_user_with_token(user_token_data):
    print "get_current_user_with_token()"
    current_user = None

    if "uid" in user_token_data:
        user_id = user_token_data["uid"]
        print "Looking up user by id: {0}".format(user_id)
        okta_util = OktaUtil(request.headers, config.okta)
        current_user = okta_util.get_user(user_id)

    return current_user


def get_current_user(add_groups=False, add_apps=False):
    print "get_current_user()"
    okta_util = OktaUtil(request.headers, config.okta)
    current_user = None
    has_admin_access = False
    current_token_info = get_current_user_token()

    if current_token_info["active"]:
        current_user = get_current_user_with_token(current_token_info)
        if add_groups:
            user_groups = okta_util.get_user_groups(current_user["id"])
            temp_groups = []
            partner_admin_names = []

            for group in user_groups:
                if (
                    group["profile"]["name"].find(config.okta["partner_group_filter_prefix"]) != -1 or
                    group["profile"]["name"] == config.okta["admin_okta_group_name"]):
                    temp_group = {
                        "id": group["id"],
                        "profile": {
                            "name_raw": group["profile"]["name"],
                            "name": group["profile"]["name"].replace(config.okta["partner_group_filter_prefix"],""),
                            "is_admin": is_admin(group),
                            "is_partner_admin": is_partner_admin(group),
                            "is_current_partner_admin": is_current_partner_admin(current_user, group),
                            "has_partner_admin_group": False
                        }
                    }
                    print "current_group.name: {0}".format(temp_group["profile"]["name"])
                    if temp_group["profile"]["is_partner_admin"]:
                        partner_admin_names.append(temp_group["profile"]["name"].replace(config.okta["partner_group_filter_suffix"], ""))

                    if (
                        temp_group["profile"]["is_admin"] or
                        temp_group["profile"]["is_partner_admin"] or
                        temp_group["profile"]["is_current_partner_admin"]):
                            has_admin_access = True

                    temp_groups.append(temp_group)

                    if "current_dlr" in current_user["profile"]:
                        if temp_group["id"] == current_user["profile"]["current_dlr"]:
                            current_user["profile"]["current_group"] = temp_group

            for group in temp_groups:
                if group["profile"]["name"] in partner_admin_names:
                    group["profile"]["has_partner_admin_group"] = True

            current_user["profile"]["groups"] = temp_groups
            current_user["profile"]["has_admin_access"] = has_admin_access

        if add_apps:
            temp_apps = []
            user_app_list = okta_util.list_user_applications(current_user["id"])

            for app in user_app_list:
                # print "app: {0}".format(json.dumps(app, indent=4, sort_keys=True))
                app_link = ""
                app_logo_url = ""

                app_link = app["_links"]["appLinks"][0]["href"]
                app_logo_url = app["_links"]["logo"][0]["href"]

                temp_app = {
                    "id": app["id"],
                    "label": app["label"],
                    "link": app_link,
                    "app_logo_url": app_logo_url
                }
                temp_apps.append(temp_app)


            current_user["profile"]["apps"] = temp_apps

    print "current_user: {0}".format(json.dumps(current_user, indent=4, sort_keys=True))

    return current_user

def is_partner_admin(group):
    print "is_partner_admin()"
    results = False

    if (
        group["profile"]["name"].find(config.okta["partner_group_filter_prefix"]) != -1 and
        group["profile"]["name"].find(config.okta["partner_group_filter_suffix"]) != -1):
        results = True

    return results

def is_current_partner_admin(user, group):
    print "is_current_partner_admin()"
    results = False

    if "current_dlr" in user["profile"]:
        if (
            group["id"] == user["profile"]["current_dlr"] and
            is_partner_admin(group)):
            results = True

    return results


def is_admin(group):
    print "is_admin()"
    results = False

    if (group["profile"]["name"].find(config.okta["admin_okta_group_name"]) != -1):
        results = True

    return results


def get_available_apps(user_with_apps):
    print "get_available_apps()"
    okta_util = OktaUtil(request.headers, config.okta)
    all_app_list = okta_util.list_all_applications()

    filtered_app_list = []
    print "user_app_list: {0}".format(user_with_apps["profile"]["apps"])
    for app in all_app_list:
        has_app = False

        for user_app in user_with_apps["profile"]["apps"]:
            # print "user_app: {0}".format(user_app)
            if app["id"] == user_app["id"]:
                has_app = True
                break

        if not has_app:
            filtered_app_list.append({"id": app["id"], "label": app["label"]})

    return filtered_app_list

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
    is_logged_in = False
    user = get_current_user(add_groups=True)
    if user:
        is_logged_in = True
        print "user: {0}".format(user)
    # SR: Removed this to allow for client side checking of an Okta session
    # This will do a full screen redirect
    # elif "redirect_url" in current_token_info:
    #    return redirect(current_token_info["redirect_url"])

    response = make_response(
        render_template(
            "index.html",
            user=user,
            error_list={},  # No errors by default
            form_data={},
            okta_config=config.okta,
            is_logged_in=is_logged_in
        )
    )

    if "token" in request.cookies:
        if request.cookies["token"] == "NO_TOKEN":
            response.set_cookie('token', "")

    return response

@app.route("/show_login", methods=["GET"])
def show_login():
    print "show_login()"

    user = None
    current_group = None
    user_groups = None
    current_token_info = get_current_user_token()
    is_admin = False
    print "current_token_info: {0}".format(current_token_info)
    if current_token_info["active"]:
        okta_util = OktaUtil(request.headers, config.okta)
        user = get_current_user_with_token(current_token_info)
        print "user: {0}".format(user)
        user_groups = []

        if "current_dlr" in user["profile"]:
            current_group = okta_util.get_group(user["profile"]["current_dlr"])
            print "current_group.name: {0}".format(current_group["profile"]["name"])

        temp_user_groups = okta_util.get_user_groups(user["id"])
        for user_group in temp_user_groups:
            if (
                user_group["profile"]["name"].find(config.okta["partner_group_filter_prefix"]) != -1 and
                user_group["profile"]["name"].find(config.okta["partner_group_filter_suffix"]) == -1):
                user_groups.append({
                    "id": user_group["id"],
                    "profile": {
                        "name": user_group["profile"]["name"].replace(config.okta["partner_group_filter_prefix"], "")
                    }
                })
            elif (
                (
                    user_group["profile"]["name"].find(config.okta["partner_group_filter_prefix"]) != -1 and
                    user_group["profile"]["name"].find(config.okta["partner_group_filter_suffix"]) != -1
                ) or (
                    user_group["profile"]["name"].find(config.okta["admin_okta_group_name"]) != -1
                )
                ):
                is_admin = True
        response = redirect(config.okta["app_host"])
    else:
        response = make_response(
            render_template(
                "login.html",
                current_token_info=current_token_info,
                user=user,
                current_group=current_group,
                error_list={},  # No errors by default
                form_data={},
                user_groups=user_groups,
                okta_config=config.okta,
                is_admin=is_admin
            )
        )

    # SR: Removed this to allow for client side checking of an Okta session
    # This will do a full screen redirect
    # elif "redirect_url" in current_token_info:
    #    return redirect(current_token_info["redirect_url"])

    if "token" in request.cookies:
        if request.cookies["token"] == "NO_TOKEN":
            response.set_cookie('token', "")

    # partner_db = PartnerDB(config.okta["db_file_name"])
    # partner_db.test()

    return response

@app.route("/my_apps", methods=["GET"])
@authenticated
def my_apps():
    print "my_apps()"

    user=get_current_user(add_groups=True, add_apps=True)
    is_logged_in = False
    if user:
        is_logged_in = True

    response = make_response(
        render_template(
            "my_apps.html",
            okta_config=config.okta,
            user=user,
            is_logged_in=is_logged_in,
            menu="my_apps"
        )
    )

    return response


@app.route("/request_apps", methods=["GET"])
@authenticated
def request_apps():
    print "request_apps()"

    user=get_current_user(add_groups=True, add_apps=True)
    is_logged_in = False
    available_apps = []

    # print "user: {0}".format(json.dumps(user, indent=4, sort_keys=True))

    if user:
        is_logged_in = True
        available_apps = get_available_apps(user)

    # print "user: {0}".format(json.dumps(user, indent=4, sort_keys=True))

    response = make_response(
        render_template(
            "request_apps.html",
            okta_config=config.okta,
            user=user,
            is_logged_in=is_logged_in,
            menu="request_apps",
            available_apps=available_apps
        )
    )

    return response


@app.route("/request_user_access", methods=["GET"])
@authenticated
def request_user_access():
    print "request_user_access()"

    user=get_current_user(add_groups=True)
    is_logged_in = False
    if user:
        is_logged_in = True

    response = make_response(
        render_template(
            "request_user_access.html",
            okta_config=config.okta,
            user=user,
            is_logged_in=is_logged_in,
            menu="request_user_access"
        )
    )

    return response


@app.route("/request_admin_access", methods=["GET"])
@authenticated
def request_admin_access():
    print "request_admin_access()"

    user=get_current_user(add_groups=True)
    is_logged_in = False
    if user:
        is_logged_in = True

    response = make_response(
        render_template(
            "request_admin_access.html",
            okta_config=config.okta,
            user=user,
            is_logged_in=is_logged_in,
            menu="request_admin_access"
        )
    )

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

    # reset default group
    print "OIDC Access token: {0}".format(oauth_token)
    user_info = get_user_info_from_token(oauth_token)

    okta_util = OktaUtil(request.headers, config.okta)
    user =  okta_util.get_user(user_info["sub"])
    print "user: {0}".format(user)

    # Update user profile to refresh group access
    user["profile"][config.okta["user_group_access_list"]] = []
    user_groups = okta_util.get_user_groups(user["id"])

    for group in user_groups:
        if group["profile"]["name"].find(config.okta["partner_group_filter_prefix"]) != -1 and not is_partner_admin(group):
            user["profile"][config.okta["user_group_access_list"]].append(group["profile"]["description"].replace(config.okta["user_current_group_desc_mapping_prefix"], ""))
            if "primary_dlr" not in user["profile"]:
                user["profile"]["primary_dlr"] = group["id"]
                user["profile"][config.okta["user_current_group_mapping"]] = group["id"]


    if "current_dlr" in user["profile"] and "primary_dlr" in user["profile"]:
        user["profile"][config.okta["user_current_group_mapping"]] = user["profile"]["primary_dlr"]
        current_group = okta_util.get_group(user["profile"]["primary_dlr"])
        user["profile"][config.okta["user_current_group_desc_mapping"]] = current_group["profile"]["description"].replace(config.okta["user_current_group_desc_mapping_prefix"], "")


    okta_util.update_user(user)

    return response


@app.route("/change_group/<group_id>", methods=["GET"])
def change_group(group_id):
    print "change_group()"
    okta_util = OktaUtil(request.headers, config.okta)

    user = get_current_user()

    print "current_dlr: {0}".format(user["profile"][config.okta["user_current_group_mapping"]])
    print "current_pdn: {0}".format(user["profile"][config.okta["user_current_group_desc_mapping"]])

    user["profile"][config.okta["user_current_group_mapping"]] = group_id
    current_group = okta_util.get_group(group_id)
    user["profile"][config.okta["user_current_group_desc_mapping"]] = current_group["profile"]["description"].replace(config.okta["user_current_group_desc_mapping_prefix"], "")

    print "current_dlr: {0}".format(user["profile"][config.okta["user_current_group_mapping"]])
    print "current_pdn: {0}".format(user["profile"][config.okta["user_current_group_desc_mapping"]])

    okta_util.update_user(user)

    response = {
        "success" : True
    }

    return json.dumps(response)


@app.route("/user_registration", methods=["GET"])
def user_registration():
    print "user_registration()"

    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])

    is_registration_completed = False
    partner_groups = okta_util.search_groups(config.okta["partner_group_filter_prefix"], config.okta["group_query_limit"])
    roles = partner_db.get_roles()

    response = make_response(
        render_template(
            "register.html",
            is_registration_completed=is_registration_completed,
            partner_groups=partner_groups,
            error_list={},  # No errors by default
            form_data={},
            roles_list=roles,
            okta_config=config.okta
        )
    )

    return response


@app.route("/register", methods=["POST"])
def register():
    print "register()"
    print request.form

    return handle_register(request.form)


@app.route("/activate/<user_id>", methods=["GET"])
def activate(user_id):
    print "activate()"

    return handle_activate(user_id)


@app.route("/activate_all/", methods=["GET"])
def activate_all():
    print "activate_all()"

    return handle_activate_all()


@app.route("/get_partner_profile_info", methods=["GET"])
def get_partner_profile_info():
    print "get_partner_profile_info()"
    term = request.args.get('term', '')
    okta_util = OktaUtil(request.headers, config.okta)
    partner_db = PartnerDB(config.okta["db_file_name"])

    db_results = partner_db.get_field_partner_profile("group_zipcode", term)
    results = []

    for row in db_results:
        group = okta_util.search_groups(row["okta_group_name"], 1)[0]
        admin_group = okta_util.search_groups("{0}{1}".format(row["okta_group_name"], config.okta["partner_group_filter_suffix"]), 1)[0]
        results.append(
            {
                "value": row["group_zipcode"],
                "label": row["okta_group_name"].replace(config.okta["partner_group_filter_prefix"], ""),
                "name": row["okta_group_name"],
                "id": group["id"],
                "admin_id": admin_group["id"]

            }
        )

    return json.dumps(results)


@app.route("/is_user_in_group/<user_id>/<group_id>", methods=["GET"])
def is_user_in_group(user_id, group_id):
    print "is_user_in_group()"
    okta_util = OktaUtil(request.headers, config.okta)
    groups = okta_util.get_user_groups(user_id)
    result = False

    for group in groups:
        if group["id"] == group_id:
            result = True
            break

    return json.dumps({"is_user_in_group": result})


@app.route("/application_request", methods=["POST"])
def application_request():
    print "application_request()"

    return handle_admin_application_request(request.get_json())


@app.route("/user_access_request", methods=["POST"])
def user_access_request():
    print "user_access_request()"

    return handle_partner_user_request(request.get_json())


@app.route("/partner_admin_request", methods=["POST"])
def partner_admin_request():
    print "partner_admin_request()"

    return handle_partner_admin_request(request.get_json())


@app.route("/admin/", methods=["GET"])
@authorize_partner
def admin():
    print "admin()"

    return handle_admin()


@app.route("/admin/admin_approval_queue/", methods=["GET"])
@authorize_admin
def admin_approval_queue():
    print "admin_approval_queue()"

    return handle_admin_approval_queue()


@app.route("/admin/application_approval_queue/<group_id>", methods=["GET"])
@authorize_partner
def admin_application_approval_queue(group_id):
    print "admin_application_approval_queue()"

    return handle_admin_application_approval_queue(group_id)


@app.route("/admin/partner_approval_queue/<group_id>", methods=["GET"])
@authorize_partner
def admin_partner_approval_queue(group_id):
    print "admin_partner_approval_queue()"

    return handle_admin_partner_approval_queue(group_id)


@app.route("/admin/approve_partner_access/<group_id>/<user_id>", methods=["GET"])
@authorize_partner
def admin_approve_partner_access(group_id, user_id):
    print "admin_approve_partner_access()"

    return handle_admin_approve_partner_access(group_id, user_id)


@app.route("/admin/deny_partner_admin_access/<group_id>/<user_id>", methods=["GET"])
@authorize_admin
def deny_partner_admin_access(group_id, user_id):
    print "deny_partner_admin_access()"

    return handle_admin_deny_partner_admin_access(group_id, user_id)


@app.route("/admin/approve_partner_admin_access/<group_id>/<user_id>", methods=["GET"])
@authorize_admin
def approve_partner_admin_access(group_id, user_id):
    print "approve_partner_admin_access()"

    return handle_admin_approve_partner_admin_access(group_id, user_id)


@app.route("/admin/deny_partner_access/<group_id>/<user_id>", methods=["GET"])
@authorize_partner
def admin_deny_partner_access(group_id, user_id):
    print "admin_deny_partner_access()"

    return handle_admin_deny_partner_access(group_id, user_id)


@app.route("/admin/approve_application_access/<group_id>/<user_id>/<app_id>", methods=["GET"])
@authorize_partner
def approve_application_access(group_id, user_id, app_id):
    print "approve_application_access()"

    return handle_admin_approve_application_access(group_id, user_id, app_id)


@app.route("/admin/deny_application_access/<group_id>/<user_id>/<app_id>", methods=["GET"])
@authorize_partner
def deny_application_access(group_id, user_id, app_id):
    print "deny_application_access()"

    return handle_admin_deny_application_access(group_id, user_id, app_id)


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

    if "ORG_HOST" in os.environ:
        config.okta["org_host"] = os.environ["ORG_HOST"]

    if "API_TOKEN" in os.environ:
        config.okta["api_token"] = os.environ["API_TOKEN"]

    if "OIDC_CLIENT_ID" in os.environ:
        config.okta["oidc_client_id"] = os.environ["OIDC_CLIENT_ID"]

    if "OIDC_CLIENT_SECRET" in os.environ:
        config.okta["oidc_client_secret"] = os.environ["OIDC_CLIENT_SECRET"]

    if "REDIRECT_URI" in os.environ:
        config.okta["redirect_uri"] = os.environ["REDIRECT_URI"]

    if "APP_HOST" in os.environ:
        config.okta["app_host"] = os.environ["APP_HOST"]

    if "POST_OIDC_REDIRECT" in os.environ:
        config.okta["post_oidc_redirect"] = os.environ["POST_OIDC_REDIRECT"]

    if "AUTH_SERVER_ID" in os.environ:
        config.okta["auth_server_id"] = os.environ["AUTH_SERVER_ID"]

    if "DB_FILE_NAME" in os.environ:
        config.okta["db_file_name"] = os.environ["DB_FILE_NAME"]

    if "SPARK_POST_API_KEY" in os.environ:
        config.okta["spark_post_api_key"] = os.environ["SPARK_POST_API_KEY"]

    if "PARTNER_GROUP_FILTER_PREFIX" in os.environ:
        config.okta["partner_group_filter_prefix"] = os.environ["PARTNER_GROUP_FILTER_PREFIX"]

    if "PARTNER_GROUP_FILTER_SUFFIX" in os.environ:
        config.okta["partner_group_filter_suffix"] = os.environ["PARTNER_GROUP_FILTER_SUFFIX"]

    if "PARTNER_PORTAL_LABEL" in os.environ:
        config.okta["partner_portal_label"] = os.environ["PARTNER_PORTAL_LABEL"]

    if "GROUP_QUERY_LIMIT" in os.environ:
        config.okta["group_query_limit"] = os.environ["GROUP_QUERY_LIMIT"]

    if "APP_OKTA_GROUP_ID" in os.environ:
        config.okta["app_okta_group_id"] = os.environ["APP_OKTA_GROUP_ID"]

    if "APP_TITLE" in os.environ:
        config.okta["app_title"] = os.environ["APP_TITLE"]

    if "APP_LOGO" in os.environ:
        config.okta["app_logo"] = os.environ["APP_LOGO"]

    if "ADMIN_OKTA_GROUP_ID" in os.environ:
        config.okta["admin_okta_group_id"] = os.environ["ADMIN_OKTA_GROUP_ID"]

    if "ADMIN_OKTA_GROUP_NAME" in os.environ:
        config.okta["admin_okta_group_name"] = os.environ["ADMIN_OKTA_GROUP_NAME"]

    if "USER_CURRENT_GROUP_MAPPING" in os.environ:
        config.okta["user_current_group_mapping"] = os.environ["USER_CURRENT_GROUP_MAPPING"]

    if "USER_CURRENT_GROUP_DESC_MAPPING" in os.environ:
        config.okta["user_current_group_desc_mapping"] = os.environ["USER_CURRENT_GROUP_DESC_MAPPING"]

    if "USER_GROUP_ACCESS_LIST" in os.environ:
        config.okta["user_group_access_list"] = os.environ["USER_GROUP_ACCESS_LIST"]

    if "USER_CURRENT_GROUP_DESC_MAPPING_PREFIX" in os.environ:
        config.okta["user_current_group_desc_mapping_prefix"] = os.environ["USER_CURRENT_GROUP_DESC_MAPPING_PREFIX"]

    print "okta_config: {0}".format(config.okta)
    app.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)))
