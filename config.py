okta = {
    "org_host": "<okta org url>",
    "api_token": "<okta api token>",
    "oidc_client_id": "<okta oidc app client id>",
    "oidc_client_secret": "<okta oidc app client secret>",
    "redirect_uri": "<application oidc post handler url>",
    "app_host": "<application url>",
    "post_oidc_redirect": "<application url to redirect to after oidc token is granted>",
    "auth_server_id": "<optional: auth server url if using Okta's Auth Server for authentication/OIDC token minting>",
    "db_file_name": "<file name of the sqlite db created>",
    "spark_post_api_key": "<api key for spark post account>",
    "partner_group_filter_prefix": "<prefix in okta group to search for the partner list>",
    "group_query_limit": 100 # Number of groups to return in partner filter
}
