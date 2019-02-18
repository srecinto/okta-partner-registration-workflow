# Okta Partner Registraion Workflow Example

This project was built using Python 2.7

This is a demo where partners can register, and go through an approval workflow using Okta as the Identity Provider.  Partners will have access to different Okta apps based on their partner portal selection.

## Requirements
* Python 2.7
* Okta domain
* Okta API Token
* Sparkpost API Key

## Dependencies
You can run all the dependencies via the requirements.txt
`pip install -r requirements.txt`

This project also uses SQLight for persistnce of the workflow features
If you are using apt-get you can use the following instructions below, otherwise
checkout http://sqlite.org/ for instructions on how to install your instance

c9 linux instructions to create the DB
`sudo apt-get update`
`sudo apt-get install sqlite3`
`sqlite3 partner_portal.db < sql/createdb.sql`


Or run them individually

**linter - flake8**

`pip install flake8`

**Web Framework - flask**

`pip install flask`
`pip install flask_login`

**HTTP Framework - Update requests**

Needed to install an update to fix a compatability issue

`pip install requests --upgrade`

## How to Run

NOTE: You may need to configure ports to listen to for serviing up the site

`python main.py`


## Heroku Hosted Configuration
There are four components to set up before running this application outside of your development environment

**1) Okta Configuration**
You need to have an Okta org with API Access management available.
You can get a free developer account at https://developer.okta.com to use for this demo

**2) Sparkpost API Key**
I use a 3rd part "Email as a Service" Provider called Sparkpost https://www.sparkpost.com/
Besure to set up an account and get an API Key

**3) Github Repo**
The best way to manage and run this application is to fork my exsisting repo https://github.com/srecinto/okta-partner-registration-workflow
into your own github repo then use that to connect with Heroku for auto deploys.  Any new updates and you would have to merge in from the base

**4) Heroku Hosting**
You can host the demo on Heroku using environment variables and auto code deployes from github with a quick set up.
Note that any locally persisted data will get wiped out periodically due to the ephemeral nature of Heroku's service


## Okta Configuration Instructions
* Create a Web OIDC Application in Okta
* Create and API Token In Okta
* Create an API AM Auth Server in Okta
* Add the following fields in the global user profile
`primary_dlr` Type: String Label "Primary Dealership" The default dealership that always gets set to upon login

`current_dlr` Type: String Label "Current Dealership" The current dealership selected on the dropdown

`dlr_list` Type: String Label "Dealer List" Use for list of dealershipt the user has been assigned to

`current_pdn` Type: String Label "Current PDN" Used to get the current dealership PDN

* Add the following fields in the claims information on Auth Server
`dlr_list` user.dlr_list

`current_dlr` user.current_dlr

`email` user.email

`lastName` user.lastName

`primary_dlr` user.primary_dlr

`firstName` user.firstName

`groups` groups: matches regex .*

`admin_group` groups: equals Dealer Admin Approval Group

* Add Heroku Application URI as redirect in Okta OIDC Application
* Add Heroku Application URI to CORS/REdirect in Okta API security


## Heroku Configuration Instructions
* Create a new App in Heroku
* Connect to your github repo containing the source code (master branch)
* Optionally Enable Automatic Deploys
* Deploy Branch (master)
* Go to "Settings" and select "Reveal Config Var"
* Set up the following Environment Variables

`ADMIN_OKTA_GROUP_ID` Okta Group ID for the Super Admin role

`ADMIN_OKTA_GROUP_NAME` Okta Group Name for thde Dealer Partner Portal Super Admin Role

`API_TOKEN` Okta API Token

`APP_HOST` Base URL of the application eg "https://[My App URI]"

`APP_LOGO` logo reference eg "logo-lavender.png"

`APP_OKTA_GROUP_ID` Okta Group ID for the general Dealer Portal App access

`APP_TITLE` App label for browser title and sub pages

`AUTH_SERVER_ID` Okta Auth Server Id

`DB_FILE_NAME` Name of the DB file for SQL Lite - Use "partner_portal.db" unless you change the file name in github

`GROUP_QUERY_LIMIT` Limits the number of groups pulled back into token claims eg. 100

`OIDC_CLIENT_ID` Okta OIDC App Client ID

`OIDC_CLIENT_SECRET` Okta OIDC App Client Secret

`ORG_HOST` Okta Org URL eg "https://myorg.oktapreview.com"

`PARTNER_GROUP_FILTER_PREFIX` Group Filter in Okta for dealer groups that start with "dlr_" eg. "dlr_James Davis Toyota"

`PARTNER_GROUP_FILTER_SUFFIX` Group Filter in Okta for dealer group admins, this is the end part of the group name " - Admins" eg "dlr_James Davis Toyota - Admin"

`PARTNER_PORTAL_LABEL` Main Label

`POST_OIDC_REDIRECT` Final Landing page of the app after successful login eg "https://[My Heroku App URI]"

`REDIRECT_URI` OIDC Redirect URI (for this app it is [base app URL]/oidc) eg "https://[My Heroku App URI]/oidc"

`SPARK_POST_API_KEY` Sparkpost API Key

`USER_CURRENT_GROUP_DESC_MAPPING` Okta Profile Property that holds the PDN number of the current dealer eg. "current_pdn"

`USER_CURRENT_GROUP_DESC_MAPPING_PREFIX` Previx in Group discription for PDN eg. "PDN "

`USER_CURRENT_GROUP_MAPPING` Okta Profile Property that holds the current dealer id for the UI drop down eg "current_dlr"

`USER_GROUP_ACCESS_LIST` Okta Profile Property that holds a list of dealers the user has access to
