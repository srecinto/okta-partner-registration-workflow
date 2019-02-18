okta = {
    "org_host": "<Okta Org URL i.e. https://myorg.oktapreview.com>",    # Okta Org URL
    "api_token": "<Okta API Token>",                                    # Okta API Token
    "oidc_client_id": "<Okta OIDC App Client Id>",                      # Okta OIDC App Client ID
    "oidc_client_secret": "<Okta OIDC App Client Secret>",              # Okta OIDC App Client Secret
    "redirect_uri": "https://<My App URI>/oidc",                        # OIDC Redirect URI (for this app it is <base app URL>/oidc)
    "app_host": "https://<My App URI>",                                 # Base URL of the application
    "post_oidc_redirect": "https://<My App URI>",                       # Final Landing page of the app after successful login
    "auth_server_id": "<Okta API AM Auth Server Id>",                   # Okta Auth Server Id
    "db_file_name": "partner_portal.db",                                # Name of the DB file for SQL Lite
    "spark_post_api_key": "<Spark Post API Key>",                       # Spark Post API Key
    "partner_group_filter_prefix": "dlr_",                              # Group Filter in Okta for dealer groups that start with "dlr_"
    "partner_group_filter_suffix": " - Admins",                         # Group Filter in Okta for dealer group admins
    "partner_portal_label": "Dealer Portal",                            # Main Label
    "group_query_limit": 100,                                           # Limits the number of groups pulled back into token claims
    "app_okta_group_id": "<Okta Dealer Portal General Access Group>",   # Okta Group ID for the general APP access
    "app_title": "Dealer Partner Portal",                               # App label for browser and sub pages
    "app_logo": "logo-lavender.png",                                    # logo reference
    "admin_okta_group_id": "<Okta Portal Admin Group Id>",              # Okta Group ID for the Super Admin role
    "admin_okta_group_name": "Dealer Admin Approval Group",             # Okta Group Name for thde Super Admin Role
    "user_current_group_mapping": "current_dlr",                        # Okta Profile Property that holds the current dealer id for the UI drop down
    "user_current_group_desc_mapping": "current_pdn",                   # Okta Profile Property that holds the PDN number of the current dealer
    "user_group_access_list": "dlr_list",                               # Okta Profile Property that holds a list of dealers the user has access to
    "user_current_group_desc_mapping_prefix": "PDN "                    # Previx in Group discription for PDN
}