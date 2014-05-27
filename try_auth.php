<?php
define("Auth_OpenID_DISABLE_SSL_VERIFYPEER", true);
require_once "common.php";
session_start();

function getOpenIDURL() {
    // Render a default page if we got a submission without an openid
    // value.
    if (empty($_GET['openid_identifier'])) {
        $error = "Expected an OpenID URL.";
        include 'index.php';
        exit(0);
    }

    return $_GET['openid_identifier'];
}

function run() {
    $openid = getOpenIDURL();
    $consumer = getConsumer();

    // Begin the OpenID authentication process.
    $auth_request = $consumer->begin($openid);

    // No auth request means we can't begin OpenID.
    if (!$auth_request) {
        displayError("Authentication error; not a valid OpenID.");
    }

    $sreg_request = Auth_OpenID_SRegRequest::build(
                                     // Required
                                     array('nickname'),
                                     // Optional
                                     array('fullname', 'email'));

    // Create attribute request object
    // Usage: make($type_uri, $count=1, $required=false, $alias=null)
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/contact/internet/email',2,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/namePerson/first',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/namePerson/last',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/namePerson/friendly',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/birthDate/birthYear',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/birthDate/birthMonth',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/birthDate/birthday',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/gender',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/contact/phone/home',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/contact/phone/cell',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/contact/postaladdress/home',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/contact/city/home',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/contact/state/home',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/contact/country/home',1,1);
    $attribute[] = Auth_OpenID_AX_AttrInfo::make('http://openid.net/schema/contact/postalcode/home',1,1);

    // Create AX fetch request
    $ax = new Auth_OpenID_AX_FetchRequest;

    // Add attributes to AX fetch request
    foreach($attribute as $attr){
        $ax->add($attr);
    }

    // Add AX fetch request to authentication request
    $auth_request->addExtension($ax);

    if ($sreg_request) {
        $auth_request->addExtension($sreg_request);
    }

	$policy_uris = null;
	if (isset($_GET['policies'])) {
    	$policy_uris = $_GET['policies'];
	}

    $pape_request = new Auth_OpenID_PAPE_Request($policy_uris);
    if ($pape_request) {
        $auth_request->addExtension($pape_request);
    }

    // Redirect the user to the OpenID server for authentication.
    // Store the token for this authentication so we can verify the
    // response.

    // For OpenID 1, send a redirect.  For OpenID 2, use a Javascript
    // form to send a POST request to the server.
    if ($auth_request->shouldSendRedirect()) {
        $redirect_url = $auth_request->redirectURL(getTrustRoot(),
                                                   getReturnTo(),
                                                   $immediate = true);

        // If the redirect URL can't be built, display an error
        // message.
        if (Auth_OpenID::isFailure($redirect_url)) {
            displayError("Could not redirect to server: " . $redirect_url->message);
        } else {
            // Send redirect.
            header("Location: ".$redirect_url);
        }
    } else {
        // Generate form markup and render it.
        $form_id = 'openid_message';
        $form_html = $auth_request->htmlMarkup(getTrustRoot(), getReturnTo(),
                                               true, array('id' => $form_id));

        // Display an error if the form markup couldn't be generated;
        // otherwise, render the HTML.
        if (Auth_OpenID::isFailure($form_html)) {
            displayError("Could not redirect to server: " . $form_html->message);
        } else {
            print $form_html;
        }
    }
}

run();

?>
