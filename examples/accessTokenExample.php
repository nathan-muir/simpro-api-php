<?php

namespace MyCompany;

use SimPro\Api\Client as SimProClient;
use Ndm\OAuth\Consumer as OAuthConsumer;
use Ndm\OAuth\SignatureMethod\Hmac;
use \Monolog\Logger;

if (PHP_SAPI != 'cli') die("This example must be run from the command line");

include (__DIR__ . "/../vendor/autoload.php");

define("SERVER", 'YOUR-SIMPRO-SERVER');
define("CONSUMER_KEY", 'YOUR-CONSUMER-KEY');
define("CONSUMER_SECRET", 'YOUR-SECRET');
define("CALLBACK_URL", "oob");

$Logger = new Logger('api-client');
$Logger->pushHandler(new \Monolog\Handler\StreamHandler('php://stderr'), Logger::INFO);

$AuthClient = new SimProClient(SERVER , new OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET, new Hmac()));
$AuthClient->setLogger($Logger);

// get a request token

try {
    $requestToken = $AuthClient->getRequestToken(CALLBACK_URL);

    echo 'RequestToken: ' . $requestToken->toString(),PHP_EOL,PHP_EOL;

    $authorizeUrl = $AuthClient->getAuthorizeUrl($requestToken);

    echo 'AuthorizeUrl: ' . $authorizeUrl, PHP_EOL;

    do {
        echo PHP_EOL, 'Enter Verifier: ';

        $verifier = trim(fgets(STDIN,30));
    } while ($verifier == '');

    // obtain the access token

    $accessToken = $AuthClient->getAccessToken($requestToken, $verifier);

    echo 'Access Token: ' . $accessToken->toString(),PHP_EOL,PHP_EOL;

    $RpcClient = $AuthClient->getRpcClient();

    $result = $RpcClient->call('CompanySearch');

    echo 'Success!', PHP_EOL;

    var_dump($result);
} catch (\Exception $ex){
    echo 'Error:', $ex->getMessage(), PHP_EOL;
}

