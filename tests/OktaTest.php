<?php

namespace NZTA\Okta;

use ReflectionMethod;
use ReflectionObject;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\Security\Member;
use SilverStripe\Control\Session;
use SilverStripe\Security\Security;
use SilverStripe\Subsites\Model\Subsite;

class OktaTest extends FunctionalTest
{

    /**
     * @var string
     */
    public static $fixture_file = __DIR__ . '/fixtures/PageTest.yml';

    /**
     * Using to prevent BasePage from requiring in JS files that do not exist.
     *
     * @var bool
     */
    public static $disable_themes = true;

    /**
     * @var Okta
     */
    private $okta;

    /**
     * @var Member
     */
    private $member;


    public function setUp()
    {
        parent::setUp();
        if (!defined('RUNNING_TESTS')) {
            define('RUNNING_TESTS', true);
        }

        $this->okta = Injector::inst()->create(Okta::class);
        $this->member = $this->objFromFixture(Member::class, 'member1');
    }

    /**
     * redirect to IDP URL when trying to access page
     */
    public function testUserAccessToPageWithoutLoggedIn()
    {
        if (!empty(Environment::getEnv('SS_OKTA_IP_WHITELIST'))) {
            $this->markTestSkipped('The SS_OKTA_IP_WHITELIST has been defined so cannot run this test.');
        }

        $page = $this->objFromFixture('Page', 'test-page');
        $middleware = Injector::inst()->get(OktaMiddleware::class);

        $request = new HTTPRequest('GET', $page->AbsoluteLink());
        $request->setSession($this->session());
        $result = $middleware->preRequest($request, new HTTPResponse());

        // Ensure user redirect to Okta to login
        // if unit test running return false before redirect to Okta
        $this->assertFalse($result);
    }


    /**
     * trying to logout from okta
     */
    public function testGetlogoutUrl()
    {
        $url = $this->okta->getLogoutUrl();
        $this->assertContains(Environment::getEnv('SS_OKTA_IDP_LOGOUT_URL'), $url);
    }

    /**
     * trying to login without saml session data
     */
    public function testUserWithoutSessionData()
    {
        $login = $this->okta->isLoggedIn();
        $this->assertFalse($login);
    }

    /**
     * check with already  SS logged user without saml session data
     */
    public function testLoggedUserWithoutSessionData()
    {
        $this->logInAs($this->member);
        $login = $this->okta->isLoggedIn();

        $this->assertFalse($login);
    }

    /**
     *  check with proper saml data
     */
    public function testUserWithSessionData()
    {
        $session = $this->session();

        $data = [
            'FirstName' => ['first name'],
            'Surname'   => ['surname'],
            'Email'     => ['myemail@abc.com'],
            'Login'     => 'myemail@abc.com',
            'SID'       => 'S-1-157275455'
        ];
        $session->set('samlUserdata', $data);
        $session->set('samlNameId', 'myemail@abc.com');
        $session->set('samlSessionIndex', 'id1494472649231.1217840392');

        $login = $this->okta->isLoggedIn();

        $this->assertTrue($login);
    }

    /**
     * check with invalid email
     */
    public function testUserWithSessionDataInvalidEmail()
    {
        $session = $this->session();

        $data = [
            'FirstName' => ['first name'],
            'Surname'   => ['surname'],
            'Email'     => ['invalid email'],
            'Login'     => 'invalid email',
            'SID'       => 'S-1-157275455'
        ];
        $session->set('samlUserdata', $data);
        $session->set('samlNameId', 'invalid email');
        $session->set('samlSessionIndex', 'id1494472649231.1217840392');

        try {
            $this->okta->isLoggedIn();
        } catch (\Exception $e) {
            $this->assertEquals(400, $e->getCode());
            $this->assertEquals("Email must be a valid email address: invalid email", $e->getMessage());
        }
    }

    /**
     * check whitelisted when its not set
     */
    public function testCheckCurrentIPWithoutSettingWhiteList()
    {
        if (!empty(Environment::getEnv('SS_OKTA_IP_WHITELIST'))) {
            $this->markTestSkipped('The SS_OKTA_IP_WHITELIST has been defined so cannot run this test.');
        }

        $reqMiddleware = Injector::inst()->create(OktaMiddleware::class);

        $reflector = new ReflectionObject($reqMiddleware);

        $method = $reflector->getMethod('isWhitelisted');
        $method->setAccessible(true);

        $this->assertFalse($method->invoke($reqMiddleware));
    }

    /**
     * check IP whitelisted when its set
     */
    public function testCheckCurrentIPInWhiteList()
    {
        if (empty(Environment::getEnv('SS_OKTA_IP_WHITELIST'))) {
            Environment::setEnv('SS_OKTA_IP_WHITELIST', $_SERVER['REMOTE_ADDR']);
        }

        $reqMiddleware = Injector::inst()->create(OktaMiddleware::class);

        $reflector = new ReflectionObject($reqMiddleware);

        $method = $reflector->getMethod('isWhitelisted');
        $method->setAccessible(true);

        $this->assertTrue($method->invoke($reqMiddleware));
    }

    /**
     * check time session when its not set
     */
    public function testTimeSession()
    {
        $reqMiddleware = Injector::inst()->create(OktaMiddleware::class);

        $reflector = new ReflectionObject($reqMiddleware);

        $method = $reflector->getMethod('isTimeLimitedSession');
        $method->setAccessible(true);

        $this->assertTrue($method->invoke($reqMiddleware));
    }

    /**
     * check time session when its set
     */
    public function testCheckSetTimeLimit()
    {
        Environment::setEnv('SS_SESSION_TIMELIMIT_WHITELIST', $_SERVER['REMOTE_ADDR']);

        $reqMiddleware = Injector::inst()->create(OktaMiddleware::class);

        $reflector = new ReflectionObject($reqMiddleware);

        $method = $reflector->getMethod('isTimeLimitedSession');
        $method->setAccessible(true);

        $this->assertFalse($method->invoke($reqMiddleware));
    }

    /**
     * check URL whitelisted when its set
     */
    public function testCheckURLWhiteList()
    {
        $page = $this->objFromFixture('Page', 'test-page');
        $page->publish('Stage', 'Live');

        $request = new HTTPRequest('get', $page->Link());

        $job = Injector::inst()->create(OktaMiddleware::class);

        $method = new ReflectionMethod(OktaMiddleware::class, 'isURLWhiteListed');
        $method->setAccessible(true);

        // check the isURLWhiteListed function before set the URL
        $this->assertFalse($method->invokeArgs($job, [$request]));

        // remove already added urls and add new url for test
        Config::inst()->remove(OktaMiddleware::class, 'okta_whitelist_urls');
        Config::inst()->update(OktaMiddleware::class, 'okta_whitelist_urls', [
            'test-page-title'
        ]);

        // check the isURLWhiteListed function after set url to whitelisted urls
        $this->assertTrue($method->invokeArgs($job, [$request]));
    }

    public function testUserLogoutFromMainSite()
    {
        $this->logInAs($this->member);

        $this->session()->set('samlNameId', 'testSamlName');
        // Check user Logged in before logout
        $member = Security::getCurrentUser();
        $this->assertTrue(isset($member));

        $controller = Injector::inst()->get(OktaController::class);
        $request = new HTTPRequest('GET', '/okta/slo');

        $controller->getRequest()->setSession($this->session());
        $result = $controller->slo($request);

        // Ensure user redirect to Okta to logged out from Okta
        $this->assertTrue((strpos($result, Environment::getEnv('SS_OKTA_IDP_LOGOUT_URL')) !== false));

        // Check User already LoggedOut
        $member = Security::getCurrentUser();
        $this->assertFalse(isset($member));
    }

    public function testUserLoggedOutFromOkta()
    {
        $controller = Injector::inst()->get(OktaController::class);
        $relayState = Controller::join_links(Director::absoluteBaseURL(), 'okta', 'loggedout');

        $request = new HTTPRequest('POST', '/okta/slo', '', ['RelayState' => $relayState]);
        $controller->getRequest()->setSession($this->session());
        $result = $controller->slo($request);

        // Ensure redirect to relayState
        $this->assertEquals($relayState, $result);
    }

    public function testSubsiteUserLoggedOutFromOkta()
    {
        $subsite = $this->objFromFixture(Subsite::class, 'subsite1');

        $controller = Injector::inst()->get(OktaController::class);
        $relayState = Controller::join_links($subsite->domain(), 'okta', 'loggedout');

        $request = new HTTPRequest('POST', '/okta/slo', '', ['RelayState' => $relayState]);
        $controller->getRequest()->setSession($this->session());
        $result = $controller->slo($request);

        // Ensure redirect to relayState
        $this->assertEquals($relayState, $result);
    }

    public function testUserSetUnauthorizedRelayState()
    {
        $unauthorizedDomain = 'http://example.org';

        $controller = Injector::inst()->get(OktaController::class);
        $relayState = Controller::join_links($unauthorizedDomain, 'okta', 'loggedout');

        $request = new HTTPRequest('POST', '/okta/slo', '', ['RelayState' => $relayState]);
        $controller->getRequest()->setSession($this->session());
        $result = $controller->slo($request);

        // Ensure redirect to relayState
        $this->assertNotEquals($relayState, $result);
    }
}
