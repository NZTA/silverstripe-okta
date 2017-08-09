<?php

class Okta
{
    /**
     * @var array
     */
    protected $config;

    /**
     * @var OneLogin_Saml2_Settings
     */
    protected $settings;

    /**
     * @var OneLogin_Saml2_Auth
     */
    protected $auth;

    /**
     * This controls whether the current session is kept when the ->slo() method
     * is called on this class.
     *
     * @var boolean
     */
    private static $keep_session_on_logout = false;

    /**
     * @param array $config
     */
    public function __construct($config)
    {
        $this->config = $config;
        $this->settings = new OneLogin_Saml2_Settings($config);
        $this->auth = new OneLogin_Saml2_Auth($config);
    }

    /**
     * @return array
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * @return OneLogin_Saml2_Settings
     */
    public function getSettings()
    {
        return $this->settings;
    }

    /**
     * @return OneLogin_Saml2_Auth
     */
    public function getAuth()
    {
        return $this->auth;
    }

    /**
     * @return string|null
     */
    public function getLoginUrl()
    {
        return $this->getAuth()->getSSOurl();
    }

    /**
     * @return string|null
     */
    public function getLogoutUrl()
    {
        $samlRequest = $this->createLogoutRequest();

        $parameters['SAMLRequest'] = $samlRequest;

        // Set RelayState to current site/subsite logout url
        // Redirect to this logout url after logout from Okta
        $parameters['RelayState'] = Controller::join_links(Director::absoluteBaseURL(), 'okta', 'loggedout');

        $security = $this->getSettings()->getSecurityData();
        if (isset($security['logoutRequestSigned']) && $security['logoutRequestSigned']) {
            $signature = $this->getAuth()->buildRequestSignature(
                $samlRequest,
                $parameters['RelayState'],
                $security['signatureAlgorithm']
            );
            $parameters['SigAlg'] = $security['signatureAlgorithm'];
            $parameters['Signature'] = $signature;
        }

        $url = OneLogin_Saml2_Utils::redirect(
            $this->getAuth()->getSLOurl(),
            $parameters,
            true
        );

        return $url;
    }

    /**
     * Helper that uses OneLogin to create encrypted SAML request used for logging out
     * @return string
     */
    protected function createLogoutRequest()
    {
        $logoutRequest = new OneLogin_Saml2_LogoutRequest(
            $this->getSettings(),
            null,
            Session::get('samlNameId'),
            Session::get('IdPSessionIndex')
        );

        return $logoutRequest->getRequest();
    }

    /**
     * @return bool
     */
    public function isLoggedIn()
    {
        $userData = Session::get('samlUserdata');
        $email = Session::get('samlNameId');
        $sessionIdx = Session::get('samlSessionIndex');

        if ($userData && $email && $sessionIdx) {
            $member = $this->findOrCreateMember($userData, $email);

            // If the user id has changed, we log the user in otherwise don't do anything
            // If we log the user in regardless, it clears the above sessions data
            // and forces them back to Okta
            if ($member->ID != Member::currentUserID()) {
                $member->logIn();
            }

            return true;
        }

        // Anybody who gets here should be logged out
        $member = Member::currentUser();
        if ($member) {
            $member->logOut();
        }

        return false;
    }

    /**
     * Finds an existing member or create a new one. This method logs the user in as that
     * method if they aren't already logged in (as that member).
     *
     * @param array $userData
     *
     * @return Member|false
     */
    protected function findOrCreateMember($userData, $email)
    {
        if (!Email::validEmailAddress($email)) {
            throw new Exception('Email must be a valid email address: ' . $email, 400);
        }

        if (empty($userData['SID']) || empty($userData['SID'][0])) {
            throw new Exception('SID not set in user data');
        }

        $member = Member::get()->filter('OktaID', $userData['SID'][0])->first();
        if (!$member) {
            $member = new Member();
            $member->OktaID = trim($userData['SID'][0]);
        }

        // Update/sync member data
        $member->Email = $email;
        $member->FirstName = $userData['FirstName'][0];
        $member->Surname = $userData['Surname'][0];
        $member->write();

        return $member;
    }

    /**
     * Attempts a single sign on
     *
     * @return bool
     */
    public function sso()
    {
        $requestId = Session::get('AuthNRequestID');
        $this->getAuth()->processResponse($requestId);

        Session::set('lastActive', time());
        Session::set('samlUserdata', $this->getAuth()->getAttributes());
        Session::set('samlNameId', $this->getAuth()->getNameId());
        Session::set('samlSessionIndex', $this->getAuth()->getSessionIndex());
        Session::clear('AuthNRequestID');

        return $this->isLoggedIn();
    }

    /**
     * One login module only supports HTTP-Redirect. We copy the _POST params to _GET
     * so that it functions properly.
     */
    public function slo()
    {
        if (isset($_POST['SAMLResponse'])) {
            $_GET['SAMLResponse'] = $_POST['SAMLResponse'];
        }

        if (isset($_POST['SAMLRequest'])) {
            $_GET['SAMLRequest'] = $_POST['SAMLRequest'];
        }

        if (isset($_POST['RelayState'])) {
            $_GET['RelayState'] = $_POST['RelayState'];
        }

        // Reason behind escaping processSLO method is,
        // this method set headers to redirect to logout URL and it calls exit() method
        if (!SapphireTest::is_running_test()) {
            $this->getAuth()->processSLO(Config::inst()->get('Okta', 'keep_session_on_logout'));
        }
    }

}

