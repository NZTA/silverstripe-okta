<?php

namespace NZTA\Okta;

use OneLogin_Saml2_Utils;
use SilverStripe\Control\Director;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Factory;

class OktaFactory implements Factory
{
    /**
     * @param string $service
     * @param array $params
     * @return \NZTA\Okta\Okta|object
     * @throws \OneLogin_Saml2_Error
     */
    public function create($service, array $params = [])
    {
        $config = $this->getOktaConfig();
        return new Okta($config);
    }

    /**
     * Get okta configuration
     *
     * @return array
     * @throws \Exception
     */
    protected function getOktaConfig()
    {
        // Ensures all required constants have been defined.
        $this->ensureDefinedConstants();

        $SPX509cert = Environment::getEnv('SS_OKTA_SP_X509');
        $SPPem = Environment::getEnv('SS_OKTA_SP_PEM');
        $IDPX509cert = Environment::getEnv('SS_OKTA_IDP_X509CERT');
        $IDPLoginURL = Environment::getEnv('SS_OKTA_IDP_LOGIN_URL');
        $IDPLogoutURL = Environment::getEnv('SS_OKTA_IDP_LOGOUT_URL');
        $oktaStrict = Environment::getEnv('SS_OKTA_STRICT');

        $config = [
            'strict' => !Director::isDev(),
            'debug' => Director::isDev(),
            'sp' => [
                'entityId' => Environment::getEnv('SS_OKTA_SP_ISSUER'),
                'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
                'x509cert' => !empty($SPX509cert) ? OneLogin_Saml2_Utils::formatCert(file_get_contents($SPX509cert)) : '',
                'privateKey' => !empty($SPPem) ? OneLogin_Saml2_Utils::formatPrivateKey(file_get_contents($SPPem)) : '',
                'assertionConsumerService' => [
                    'url' => 'http://nztaintranet.local/okta/sso',//Controller::join_links(Director::absoluteBaseURL(), 'okta', 'sso'),
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                ],
                'singleLogoutService' => [
                    'url' => Environment::getEnv('SS_OKTA_SP_LOGOUT_URL'),
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ]
            ],

            'idp' => [
                'entityId' => Environment::getEnv('SS_OKTA_IDP_ISSUER'),
                'x509cert' => !empty($IDPX509cert) ? OneLogin_Saml2_Utils::formatCert(file_get_contents($IDPX509cert)) : '',
                'singleSignOnService' => [
                    'url' => $IDPLoginURL,
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],
                'singleLogoutService' => [
                    'url' => $IDPLogoutURL,
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ]
            ],

            'security' => [
                'authnRequestsSigned' => true,
                'logoutRequestSigned' => true,
                'logoutResponseSigned' => true,
                'wantMessagesSigned' => true,
                'signatureAlgorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        ];

        if (!empty($oktaStrict)) {
            $config['strict'] = (bool)$oktaStrict;
        }

        return $config;
    }

    /**
     * Ensures all required constants have been defined. if not throw an exception.
     * @throws \Exception
     */
    private function ensureDefinedConstants()
    {
        $constants = [
            'SS_OKTA_SP_ISSUER',
            'SS_OKTA_SP_LOGOUT_URL',
            'SS_OKTA_IDP_ISSUER',
            'SS_OKTA_IDP_LOGIN_URL',
            'SS_OKTA_IDP_LOGOUT_URL',
        ];

        foreach ($constants as $constant) {
            if (empty(Environment::getEnv($constant))) {
                throw new \Exception($constant . ' must be defined.');
            }
        }
    }
}
