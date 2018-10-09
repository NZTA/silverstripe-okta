# Okta Integration

Okta provides secure identity management and single sign-on to the application, whether in the cloud, on-premises or on 
a mobile device for every employee.

## Requirements
SilverStripe 4.x

## Version info
The master branch of this module is currently aiming for SilverStripe 4.x compatibility

* [SilverStripe 3.0+ compatible version](https://github.com/NZTA/silverstripe-okta/tree/1.0.0)

## Configuration

You will need to setup signing certificates for the SAML assertions for both single login and single logout.

Self signed certificates for development can be generated using this helper tool:
https://developers.onelogin.com/saml/online-tools/x509-certs/obtain-self-signed-certs

These certificates can be defined with any name you wish and can be stored anywhere on the server. You will also need 
to upload the certificates to your Okta application.

You will then need to add the following environment variables in your `.env` file:

| Variable | Example value | Notes |
| ------ | ------ | ------ |
| SS_OKTA_SP_ISSUER | https://yourdomain.co.nz | Your application domain name |
| SS_OKTA_SP_LOGOUT_URL | https://yourdomain.co.nz/okta/slo | - |
| SS_OKTA_SP_X509 | '/var/www/certs/org-sp.crt' | Example path to generated cert for SLO |
| SS_OKTA_SP_PEM | '/var/www/certs/org-sp.pem' | Example path to generated private key for cert above for SLO |
| SS_OKTA_IDP_X509CERT | '/var/www/certs/org-idp.crt' | Download this certificate from Okta |
| SS_OKTA_IDP_ISSUER | http://okta.com/XYZ123 | - |
| SS_OKTA_IDP_LOGIN_URL | https://org.okta.com/app/appname/XYZ123/sso/saml | - |
| SS_OKTA_IDP_LOGOUT_URL | https://org.okta.com/app/appname/XYZ123/slo/saml | - |
| SS_OKTA_IP_WHITELIST | 127.0.0.1,192.168.0.10 | You bypass login through Okta for development by adding your IP address |

You can obtain the SS_OKTA_IDP_X509CERT, SS_OKTA_IDP_ISSUER, SS_OKTA_IDP_LOGIN_URL and SS_OKTA_IDP_LOGOUT_URL 
information from Okta, e.g. https://{org}.okta.com/app/{appname}/{XYZ123}/setup/help/SAML_2_0/instructions

Where:

org: organization name
appname: application name which is defined by Okta
XYZ123: random app id which is defined by Okta

Alternatively:

1. Login to your okta account
1. Click the admin button
3. Click applications in applications menu
4. Click your application from list of applications
5. Click on the 'Sign On' tab
6. Click on the 'view setup introduction' button

You will see the details and the download option for the certificate.

### Setup SAML settings in Okta

1. Login to your Okta account and follow the last steps to go to your application
2. Click 'General' tab
3. Click 'Edit' button in SAML settings
4. Click 'Next'
5. Click 'Show Advanced Settings'

Update the following settings

| Field | Value |
| ------ | ------ |
| Single sign on URL | https://yourdomian.co.nz/okta/sso |
| Audience URI (SP Entity ID) | https://yourdomain.co.nz |
| Name ID format | Unspecified |
| Application username | Email |
| Response | Signed |
| Assertion Signature  | Signed |
| Signature Algorithm | RSA-SHA256 |
| Digest Algorithm | SHA256 |
| Assertion Encryption  | Unencrypted |
| Key Transport Algorithm | RSA-OAEP |

### Setup Attribute statements

| Name | Value |
| ------ | ------ |
| FirstName | user.firstName |
| Surname | user.lastname  |
| Email | user.email |
| Login | user.login |
| SID | user.uniqueID |

### Assign people/accounts in okta
login to your okta account and follow the last steps to go to your application, then add people/accounts from the people section to give access to the application.

## Installation

In order for this module to work you will need to import the `onelogin/php-saml` module to your current project. You 
can do this by adding the following to your `composer.json` file:

```javascript
    "require": {
        "onelogin/php-saml": "dev-sign-logout-request"
    },
    "repositories": [
        {
            "type": "vcs",
            "url": "git@github.com:micmania1/php-saml.git"
        }
    ]
```

The original `onelogin/php-saml` module initially brought on issues upon signing out. Therefore, the purpose behind 
this fork is to resolve any issues that the original module brought on and ensure that no further issues arise.

Lastly, run `composer install`
