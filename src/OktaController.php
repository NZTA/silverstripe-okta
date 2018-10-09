<?php

namespace NZTA\Okta;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Security;
use SilverStripe\Subsites\Model\Subsite;
use OneLogin_Saml2_Error;

class OktaController extends \PageController
{
    /**
     * @var array
     */
    private static $allowed_actions = [
        'sso',
        'slo',
        'loggedout',
    ];

    /**
     * Redirects to okta login
     *
     * @return \SilverStripe\Control\HTTPResponse
     */
    public function index()
    {
        $okta = Injector::inst()->create(Okta::class);

        return $this->redirect($okta->getLoginUrl());
    }

    /**
     * Performs okta and silverstripe login
     *
     * @param HTTPRequest $request
     *
     * @return HTTPResponse
     */
    public function sso(HTTPRequest $request)
    {
        $okta = Injector::inst()->create(Okta::class);
        $relay = $okta->getLoginUrl();

        // Attempt single sign on
        if ($okta->sso()) {
            $relay = $request->postVar('RelayState') ?: Director::baseUrl();
        }

        if ($this->owner->hasMethod('onAfterLogin')) {
            $this->owner->onAfterLogin();
        }

        return $this->redirect($relay);
    }

    /**
     * Performs okta and silverstripe logout
     *
     * @param HTTPRequest $request
     *
     * @return bool|HTTPResponse|String
     * @throws OneLogin_Saml2_Error
     */
    public function slo(HTTPRequest $request)
    {
        $session = $this->getRequest()->getSession();
        // Allows the user to see the loggedout page. We're not bothered about unsetting
        // this later as it only exists to protect the website from people who have not
        // logged in at all.
        $session->set('hasLoggedOut', true);

        try {
            $okta = Injector::inst()->create(Okta::class);
        } catch (OneLogin_Saml2_Error $e) {
            // if we're in dev we can redirect to the ss logout
            if (Director::isDev()) {
                return $this->redirect('/Security/Logout');
            }

            // if not in dev, just throw the error. Something has went wrong.
            throw $e;
        }

        if ($request->httpMethod() == 'POST') {
            return $this->logoutResponseFromOkta($request, $okta);
        }

        return $this->logoutFromSilverStripe($okta);
    }

    /**
     * logout from SilverStripe and redirect to Okta
     * to logged out from Okta
     * @param $okta
     *
     * @return HTTPResponse|string
     */
    private function logoutFromSilverStripe($okta)
    {
        $session = $this->getRequest()->getSession();

        if (!empty($session->get('samlNameId'))) {
            $logoutUrl = $okta->getLogoutUrl();
        } else {
            $logoutUrl = Director::baseUrl();
        }

        $this->clearSession();

        if (defined('RUNNING_TESTS')) {
            return $logoutUrl;
        }

        return $this->redirect($logoutUrl);
    }

    /**
     * After logged out from Okta, Okta will return POST SAML response
     * to the same URL (/okta/slo)
     * including RelayState, the one we set before send the logout request to Okta,
     *
     * @param HTTPRequest $request
     * @param Okta $okta
     *
     * @return HTTPResponse|String
     */
    private function logoutResponseFromOkta(HTTPRequest $request, $okta)
    {
        $okta->slo();

        $relayState = $request->postVar('RelayState');

        if (class_exists(Subsite::class)) {
            $subsiteDomains = [];
            $subsites = Subsite::get();

            foreach ($subsites as $subsite) {
                array_push($subsiteDomains, $subsite->domain());
            }
        }

        $relayStateWithoutProtocol = preg_replace(
            '#^https?://#',
            '',
            str_replace('/okta/loggedout', '', $relayState)
        );

        // If RelayState is set, then user will redirct to RelayState URL
        // if not redirect to current site logout URL
        // And also checking RelayState is one of Subsites URL to prevent
        // malformed RelayState URLS (if have any subsites)
        if (class_exists(Subsite::class)
            && $relayState && count($subsiteDomains) > 0
            && in_array($relayStateWithoutProtocol, $subsiteDomains)
        ) {
            $url = $relayState;
        } else {
            $url = Controller::join_links(Director::absoluteBaseURL(), 'okta', 'loggedout');
        }

        // Return URL for Unit tests
        if (defined('RUNNING_TESTS')) {
            return $url;
        }

        return $this->redirect($url);
    }

    /**
     * @return HTTPResponse|\SilverStripe\ORM\FieldType\DBHTMLText
     */
    public function loggedout()
    {
        $session = $this->getRequest()->getSession();

        if (Security::getCurrentUser()) {
            $url = Controller::join_links(Director::baseUrl(), 'okta', 'slo');
            return $this->redirect($url);
        }

        if (!$session->get('hasLoggedOut')) {
            return $this->redirect(Director::baseUrl());
        }

        $data = [
            'Title' => 'You have logged out!'
        ];

        return $this
            ->customise($data)
            ->renderWith(['Okta_loggedout', 'Page']);
    }

    /**
     * logout if your already logged in and
     * delete all the sessions after logout.
     */
    protected function clearSession()
    {
        $member = Security::getCurrentUser();
        if ($member) {
            Security::setCurrentUser(null);
            $this->getRequest()->getSession()->clearAll();
        }
    }
}
