<?php

class OktaRequestFilter implements RequestFilter
{

    /**
     * Session timeout in seconds. This does not apply if the
     * remote IP address is whitelisted.
     *
     * @see isTimeLimitedSession
     *
     * @var int
     */
    protected $sessionTimeout = 7200;

    /**
     * @var array
     */
    private static $okta_whitelist_urls = [];

    /**
     * @param SS_HTTPRequest $request
     * @param Session $session
     * @param DataModel $model
     *
     * @return bool
     */
    public function preRequest(SS_HTTPRequest $request, Session $session, DataModel $model)
    {
        // There are some circumstances where we don't want this filter to run. We shortcut
        // out here. See {@link hasAccess} for these scenarios.
        if ($this->hasAccess($request)) {
            $session->set('sessionCanTimeout', false);
            $session->set('lastActive', time());
            $session->save();
            return true;
        }

        // Create our okta instance
        $okta = Injector::inst()->create('Okta');

        // If the user has logged in, we're good.
        if ($okta->isLoggedIn()) {

            // If there is a OktaBackURL set, clear it and redirect there (the next request will proc the below code)
            // Back URL is guaranteed to be on the same domain, as it is only set by SS_HTTPRequest::getURL()
            if ($backURL = $session->get('OktaBackURL')) {
                $session->clear('OktaBackURL');
                $session->save();
                header("Location: " . $backURL);
                exit;
            }

            // If the session is not time limited, the user is logged in
            // We don't care about setting lastActive
            if (!$this->isTimeLimitedSession()) {
                $session->set('sessionCanTimeout', false);
                $session->save();
                return true;
            }

            // We're settings a 30 minute timeout on the session. We check this for all
            // cases regardless of whether okta is enabled or not.
            $lastActive = $session->get('lastActive');
            $timeout = strtotime(SS_Datetime::now()) - $this->sessionTimeout;
            if ($lastActive && $lastActive < $timeout) {
                header("Location: " . $okta->getLogoutUrl());
                exit;
            }

            $session->set('sessionCanTimeout', true);
            $session->set('lastActive', time());
            $session->save();

            return true;
        }

        // to prevent from exit() method in following $okta->getAuth()->login() return false before execute it,
        // $okta->getAuth()->login() method set headers to redirect to Okta to login and calls exit() method
        if (SapphireTest::is_running_test()) {
            return false;
        }

        // this uses OneLogin_Saml2_Utils to set headers to redirect to Okta to login
        $okta->getAuth()->login(Controller::join_links(Director::absoluteBaseURL(), $request->getURL(true)));
    }

    /**
     * @param SS_HTTPRequest $request
     * @param SS_HTTPResponse $response
     * @param DataModel $model
     *
     * @return none
     */
    public function postRequest(SS_HTTPRequest $request, SS_HTTPResponse $response, DataModel $model)
    {
        $response->addHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        $response->addHeader('Pragma', 'no-cache');
        $response->addHeader('Expires', '0');

    }

    /**
     * Allows access via the command line and when in dev mode logged in as admin
     *
     * @return bool
     */
    protected function hasAccess(SS_HTTPRequest $request)
    {
        // Whitelist (ie. backdoor for ops and for development)
        if ($this->isWhitelisted()) {
            return true;
        }

        // Whitelist URL
        if ($this->isURLWhiteListed($request)) {
            return true;
        }

        // We don't want to block CLI scripts or users accessing /okta and work in unit test
        if ((Director::is_cli() || $this->isAccessingOkta($request)) && !SapphireTest::is_running_test()) {
            return true;
        }

        // If we reach here and we're not in dev mode, the user doesn't have access
        if (strcmp(Director::get_environment_type(), 'dev') !== 0) {
            return false;
        }

        // When in dev mode, we allow access if you're admin, or are trying to access the
        // security section (but only if whitelisted). This is to still allow default admin login through default admin
        return $this->isAccessingSecurityAndWhitelisted($request) || Permission::check('ADMIN');
    }

    /**
     * Checks if the user is accessing /okta section of the site
     *
     * @return bool
     */
    private function isAccessingOkta(SS_HTTPRequest $request)
    {
        // We only want to check if we're accessing an action within the okta controller.
        // eg. okta/sso. The root url (/okta) redirects to the login anyway.
        if (strcasecmp(substr($request->getUrl(), 0, 5), 'okta/') === 0) {
            return true;
        }

        return false;
    }

    /**
     * Checks if the user is accessing the security section of the site
     *
     * @param SS_HTTPRequest $request
     *
     * @return bool
     */
    private function isAccessingSecurityAndWhitelisted(SS_HTTPRequest $request)
    {
        // The root url /security doesn't exist so we check that for the suffixed '/'
        return $this->isWhitelisted() && strcasecmp(substr($request->getUrl(), 0, 9), 'security/') === 0;
    }

    /**
     * Checks if the current users IP is in the whitelist to bypass okta.
     *
     * @example
     *    define('SS_OKTA_IP_WHITELIST', '127.0.0.1');
     *
     * @return bool
     */
    private function isWhitelisted()
    {
        if (!defined('SS_OKTA_IP_WHITELIST') || !isset($_SERVER['REMOTE_ADDR'])) {
            return false;
        }

        $whitelist = array_map('trim', explode(',', SS_OKTA_IP_WHITELIST));
        return in_array($_SERVER['REMOTE_ADDR'], $whitelist);
    }

    /**
     * This checks whether we should check the session to see if it has timed out.
     *
     * If the users IP address has been whitelisted in SS_SESSION_TIMELIMIT_WHITELIST, then
     * the session timeout does not apply.
     *
     * @example
     *        define('SS_SESSION_TIMELIMIT_WHITELIST', '127.0.0.1');
     *
     * @return bool
     */
    private function isTimeLimitedSession()
    {
        // If no ip whitelist is defined for session time limits, then the session is
        // limited by the sessionTimeout on this class.
        if (!defined('SS_SESSION_TIMELIMIT_WHITELIST') || !isset($_SERVER['REMOTE_ADDR'])) {
            return true;
        }

        $whitelist = array_map('trim', explode(',', SS_SESSION_TIMELIMIT_WHITELIST));
        return !in_array($_SERVER['REMOTE_ADDR'], $whitelist);
    }

    /**
     * Checks if the current URL is in the okta_whiltelist_urls to bypass okta.
     *
     * @param SS_HTTPRequest $request
     *
     * @return bool
     */
    private function isURLWhiteListed(SS_HTTPRequest $request)
    {
        $whitelist = Config::inst()->get('OktaRequestFilter', 'okta_whitelist_urls');

        if (empty($whitelist) || !is_array($whitelist)) {
            return false;
        }

        return $this->inMultipleArray($whitelist, $request);
    }

    /**
     * @param $whitelist
     * @param $request
     *
     * @return bool
     */
    private function inMultipleArray($whitelist, $request)
    {
        $requestUrl = $request->getUrl();

        // check current url against list of whitelist urls
        $retArray = array_filter($whitelist, function ($value) use ($requestUrl) {
            if (!empty($requestUrl)) {
                return (strpos($requestUrl, $value) !== false);
            }
        });

        return (count($retArray) > 0);
    }
}
