<?php

require_once "common.php";
session_start();

function escape($thing) {
    return htmlentities($thing);
}

function run() {
    $consumer = getConsumer();

    // Complete the authentication process using the server's
    // response.
    $return_to = getReturnTo();
    $response = $consumer->complete($return_to);

    // Check the response status.
    if ($response->status == Auth_OpenID_CANCEL) {
        // This means the authentication was cancelled.
        $msg = 'Verification cancelled.';
    } else if ($response->status == Auth_OpenID_FAILURE) {
        // Authentication failed; display the error message.
        $msg = "OpenID authentication failed: " . $response->message;
    } else if ($response->status == Auth_OpenID_SUCCESS) {
        // This means the authentication succeeded; extract the
        // identity URL and Simple Registration data (if it was
        // returned).
        $openid = $response->getDisplayIdentifier();
        $esc_identity = escape($openid);

        $success = sprintf('You have successfully verified ' .
                           '<a href="%s">%s</a> as your identity.',
                           $esc_identity, $esc_identity);

        if ($response->endpoint->canonicalID) {
            $escaped_canonicalID = escape($response->endpoint->canonicalID);
            $success .= '  (XRI CanonicalID: '.$escaped_canonicalID.') ';
        }

        // SReg attributes
        $sreg_resp = Auth_OpenID_SRegResponse::fromSuccessResponse($response);
        $sreg = $sreg_resp->contents();

        $success .= "<p>Registros SReg</p>";
        $success .= "<table>";
        if (@$sreg['email']) {
            $success .= "<tr><td>email</td><td>".escape($sreg['email'])."</td></tr>";
        }

        if (@$sreg['nickname']) {
            $success .= "<tr><td>nickname</td><td>".escape($sreg['nickname'])."</td></tr>";
        }

        if (@$sreg['fullname']) {
            $success .= "<tr><td>fullname</td><td>".escape($sreg['fullname'])."</td></tr>";
        }
        $success .= "</table>";

        // Attribute Exchange
        $ax = new Auth_OpenID_AX_FetchResponse();
        $obj = $ax->fromSuccessResponse($response);

        $success .= "<p>Registros AX</p>";
        $success .= "<table>";
        foreach ($obj->data as $key => $value) {
            $success .= "<tr><td>" . $key . "</td><td>" . $value[0] . "</td></tr>";
        }
        $success .= "</table>";

    }

    include 'index.php';
}

run();

?>