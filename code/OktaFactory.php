<?php

class OktaFactory implements SilverStripe\Framework\Injector\Factory
{
    /**
     * @param string $service
     * @param array $params
     * @return Okta
     */
    public function create($service, array $params = [])
    {
        $config = $this->getOktaConfig();
        return new Okta($config);
    }

    /**
     * get okta configuration
     * @return array
     */
    protected function getOktaConfig()
    {
        // Ensures all required constants have been defined.
        $this->ensureDefinedConstants();

        $config = [
            'strict' => SS_ENVIRONMENT_TYPE !== 'dev',
            'debug'  => SS_ENVIRONMENT_TYPE === 'dev',
            'sp'     => [
                'entityId'                 => SS_OKTA_SP_ISSUER,
                'NameIDFormat'             => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
                'x509cert'                 => defined('SS_OKTA_SP_X509') ? OneLogin_Saml2_Utils::formatCert(SS_OKTA_SP_X509) : '',
                'privateKey'               => defined('SS_OKTA_SP_PEM') ? OneLogin_Saml2_Utils::formatPrivateKey(SS_OKTA_SP_PEM) : '',
                'assertionConsumerService' => [
                    'url'     => Controller::join_links(Director::absoluteBaseURL(), 'okta', 'sso'),
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                ],
                'singleLogoutService'      => [
                    'url'     => SS_OKTA_SP_LOGOUT_URL,
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ]
            ],

            'idp' => [
                'entityId'            => SS_OKTA_IDP_ISSUER,
                'x509cert'            => defined('SS_OKTA_IDP_X509CERT') ? OneLogin_Saml2_Utils::formatCert(SS_OKTA_IDP_X509CERT) : '',
                'singleSignOnService' => [
                    'url'     => SS_OKTA_IDP_LOGIN_URL,
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],
                'singleLogoutService' => [
                    'url'     => SS_OKTA_IDP_LOGOUT_URL,
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ]
            ],

            'security' => [
                'authnRequestsSigned'  => true,
                'logoutRequestSigned'  => true,
                'logoutResponseSigned' => true,
                'wantMessagesSigned'   => true,
                'signatureAlgorithm'   => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        ];

        if (defined('SS_OKTA_STRICT')) {
            $config['strict'] = (bool)SS_OKTA_STRICT;
        }

        return $config;
    }

    /**
     * Ensures all required constants have been defined. if not throw an exception.
     * @throws Exception
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
            if (!defined($constant)) {
                throw new Exception($constant . ' must be defined.');
            }
        }
    }
}
