# Okta Partner Registraion Workflow Example

This project was built using Python 2.7

This is a demo where partners can register, and go through an approval workflow using Okta as the Identity Provider.  Partners will have access to different Okta apps based on their partner portal selection.

## Requirements
* Python 2.7
* Okta domain
* Okta API Token

## Dependencies
You can run all the dependencies via the requirements.txt
`pip install -r requirements.txt`

Or run them individually

**linter - flake8**

`pip install flake8`

**Web Framework - flask**

`pip install flask`

**HTTP Framework - Update requests**

Needed to install an update to fix a compatability issue

`pip install requests --upgrade`

## How to Run

NOTE: You may need to configure ports to listen to for serviing up the site

`python main.py`