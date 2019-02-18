<?php

namespace NZTA\Okta;

use Exception;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use OneLogin\Saml2\LogoutRequest;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\Email\Email;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\Security\IdentityStore;

class Okta
{
    /**
     * @var array
     */
    protected $config;

    /**
     * @var Settings
     */
    protected $settings;

    /**
     * @var \OneLogin_Saml2_Auth
     */
    protected $auth;

    /**
     * @var HTTPRequest
     */
    protected $request;

    /**
     * This controls whether the current session is kept when the ->slo() method
     * is called on this class.
     *
     * @var boolean
     */
    private static $keep_session_on_logout = false;

    /**
     * Okta constructor.
     *
     * @param array $config
     *
     * @throws \OneLogin_Saml2_Error
     */
    public function __construct($config)
    {
        $this->config = $config;
        $this->settings = new Settings($config);
        $this->auth = new Auth($config);
    }

    /**
     * @return array
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * @return Settings
     */
    public function getSettings()
    {
        return $this->settings;
    }

    /**
     * @return \OneLogin_Saml2_Auth
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
     * @return null|string
     * @throws \OneLogin_Saml2_Error
     */
    public function getLogoutUrl()
    {
        $samlRequest = $this->createLogoutRequest();

        $parameters['SAMLRequest'] = $samlRequest;

        // Set RelayState to current site/subsite logout url
        // Redirect to this logout url after logout from Okta
        $relayState = Controller::join_links(Director::absoluteBaseURL(), 'okta', 'loggedout');
        $parameters['RelayState'] = $relayState;

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

        $url = Utils::redirect(
            $this->getAuth()->getSLOurl(),
            $parameters,
            true
        );

        return $url;
    }

    /**
     * Helper that uses OneLogin to create encrypted SAML request
     * used for logging out
     *
     * @return string
     */
    protected function createLogoutRequest()
    {
        $session = $this->getSession();
        $logoutRequest = new LogoutRequest(
            $this->getSettings(),
            null,
            $session->get('samlNameId'),
            $session->get('IdPSessionIndex')
        );

        return $logoutRequest->getRequest();
    }

    /**
     * @return bool
     * @throws \SilverStripe\ORM\ValidationException
     */
    public function isLoggedIn()
    {
        $session = $this->getSession();

        $userData = $session->get('samlUserdata');
        $email = $session->get('samlNameId');
        $sessionIdx = $session->get('samlSessionIndex');
        $currentMember = Security::getCurrentUser();

        if ($userData && $email && $sessionIdx) {
            $member = $this->findOrCreateMember($userData, $email);

            // If the user id has changed,
            // we log the user in otherwise don't do anything
            // If we log the user in regardless, it clears the above sessions data
            // and forces them back to Okta
            $currentMemberID = ($currentMember) ? $currentMember->ID : null;

            if ($member->ID != $currentMemberID) {
                Injector::inst()->get(IdentityStore::class)->logIn($member, true, $this->request);
            }

            return true;
        }

        // Anybody who gets here should be logged out
        if ($currentMember) {
            Security::setCurrentUser(null);
            Injector::inst()->get(IdentityStore::class)->logOut($this->request);
        }

        return false;
    }

    /**
     * Finds an existing member or create a new one.
     * This method logs the user in as that
     * method if they aren't already logged in (as that member).
     *
     * @param array $userData
     * @param string $email
     *
     * @return Member|false
     * @throws \SilverStripe\ORM\ValidationException
     */
    protected function findOrCreateMember($userData, $email)
    {
        if (!Email::is_valid_address($email)) {
            throw new Exception(
                sprintf('Email must be a valid email address: %s', $email),
                400
            );
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
     * @throws \OneLogin_Saml2_Error
     * @throws \SilverStripe\ORM\ValidationException
     */
    public function sso()
    {
        $session = $this->getSession();

        $requestId = $session->get('AuthNRequestID');
        $this->getAuth()->processResponse($requestId);

        $session->set('lastActive', time());
        $session->set('samlUserdata', $this->getAuth()->getAttributes());
        $session->set('samlNameId', $this->getAuth()->getNameId());
        $session->set('samlSessionIndex', $this->getAuth()->getSessionIndex());
        $session->clear('AuthNRequestID');

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
        if (!defined('RUNNING_TESTS')) {
            $this->getAuth()->processSLO(Config::inst()->get(Okta::class, 'keep_session_on_logout'));
        }
    }

    /**
     * @return Session
     */
    private function getSession()
    {
        if (defined('RUNNING_TESTS')) {
            return Controller::curr()->getRequest()->getSession();
        } else {
            $request = Injector::inst()->get(HTTPRequest::class);

            $this->request = $request;

            return $request->getSession();
        }
    }
}
