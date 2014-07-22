<?php
namespace SimPro\Api;

use \Ndm\JsonRpc\Client\HttpClient;
use \Ndm\OAuth\Consumer as OAuthConsumer;
use \Ndm\OAuth\Token as OAuthToken;
use \Ndm\OAuth\Request as OAuthRequest;


/**
 */
class Client implements \Psr\Log\LoggerAwareInterface {

    /**@#+
     * @const Endpoint Constants
     */
    const API_URL = 'https://%s/api/';

    const REQUEST_TOKEN_URL = 'https://%s/api/oauth/request_token.php';

    const ACCESS_TOKEN_URL = 'https://%s/api/oauth/access_token.php';

    const GATEWAY_URL = 'https://%s/api/oauth/gateway.php?oauth_consumer_key=%s';

    const AUTHORIZE_URL = 'https://%s/oauth/authorize.php?oauth_token=%s';

    const OAUTH_REALM = 'simPROAPI';
    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @var OAuthConsumer
     */
    private $consumer;

    /**
     * @var OAuthToken
     */
    public $accessToken;

    /**
     * @var string
     */
    private $host;


    /**
     * @param string                $host The host name of the simPRO installation. If a port is required, it can be in the format '{hostName}:{port}'
     * @param OAuthConsumer         $consumer
     * @param OAuthToken            $accessToken
     *
     * @throws \Exception
     */
    public function __construct($host, OAuthConsumer $consumer, OAuthToken $accessToken = null){
        // check the host name
        if (!$this->isValidHost($host)){
            throw new \RuntimeException("Invalid host: '{$host}'");
        }
        // set the consumer, token & signature method
        $this->consumer = $consumer;
        $this->accessToken = $accessToken;
        // set the host
        $this->host = $host;

        // Default the logger to null - can be overwritten using setLogger
        $this->logger = new \Psr\Log\NullLogger();
    }

    /**
     * @return \Ndm\JsonRpc\Client\Client
     */
    public function hasAccessToken(){
        return !empty($this->accessToken);
    }

    /**
     * Clears the access token
     */
    public function clearAccessToken(){
        $this->accessToken = null;
    }

    /**
     * @return \Ndm\JsonRpc\Client\Client
     */
    public function getRpcClient(){
        // generate the API URL from the host
        $url = sprintf(self::API_URL, $this->host);
        // create a JSON-RPC client connection to the url
        return HttpClient::connectOAuth($url, $this->consumer, $this->accessToken);
    }


    /**
     * Validates host name, with port number attached
     *
     * @link http://stackoverflow.com/questions/1755144/how-to-validate-host-name-in-php
     *
     * @param $hostName
     *
     * @return bool
     */
    private function isValidHost($hostName)
    {
        // check for presence of 'Port'
        $hostPieces = explode(':', $hostName, 2);
        if (count($hostPieces) > 1){
            $hostName = $hostPieces[0];
            if (!preg_match('/^\d+$/',$hostPieces[1])){
                return false;
            }
        }
        // check host portion is valid
        $hostPieces = explode(".",$hostName);
        foreach($hostPieces as $piece)
        {
            if (!preg_match('/^[a-z\d][a-z\d-]{0,62}$/i', $piece) || preg_match('/-$/', $piece) )
            {
                return false;
            }
        }
        return true;
    }


    /**
     * @param string $callbackUrl
     * @return OAuthToken
     * @throws \Exception
     */
    public function getRequestToken($callbackUrl = 'oob'){
        $this->logger->info("Obtaining Request Token", array("host"=>$this->host, "callbackUrl"=>$callbackUrl));
        // create the URL for the Request Token Endpoint
        $url = sprintf(self::REQUEST_TOKEN_URL, $this->host);
        // create an OAuth Request- configure with local parameters
        $oAuthRequest = OAuthRequest::fromConsumerAndToken($this->consumer, null, 'GET', $url);
        $oAuthRequest->setParameter('oauth_callback',$callbackUrl);
        $oAuthRequest->signRequest($this->consumer);
        // Perform request & Retrieve result
        $headers = array($oAuthRequest->toHeader(), 'Accept: application/x-www-form-urlencoded');
        $resultString = $this->performRequest($url, 'GET', $headers);
        // parse the result string (should be www-form-urlencoded
        parse_str($resultString, $result);
        // detect problems
        if (isset($result['oauth_problem'])){
            $this->logger->error("Failed to obtain Request Token", array("host"=>$this->host, "callbackUrl"=>$callbackUrl, "problem"=> $result['oauth_problem']));
            throw new \Exception("Failed to retrieve Request Token because: {$result['oauth_problem']}");
        }
        if (!isset($result['oauth_token']) || !isset($result['oauth_token_secret']) || !isset($result['oauth_callback_confirmed'])){
            $this->logger->error("Failed to obtain Request Token", array("host"=>$this->host, "callbackUrl"=>$callbackUrl));
            throw new \Exception("Failed to retrieve Request Token.");
        }
        // return the token
        return new OAuthToken($result['oauth_token'], $result['oauth_token_secret']);
    }


    /**
     * @param OAuthToken $requestToken
     * @return string
     */
    public function getAuthorizeUrl(OAuthToken $requestToken){
        return sprintf(self::AUTHORIZE_URL, $this->host, urlencode($requestToken->key));
    }


    /**
     * @param OAuthToken $requestToken
     * @param string            $verifier
     *
     * @throws \Exception
     * @return OAuthToken
     */
    public function getAccessToken(OAuthToken $requestToken, $verifier){
        $this->logger->info("Obtaining Access Token", array("host"=>$this->host, "verifier"=>$verifier));
        // create the URL for the Access Token Endpoint
        $url = sprintf(self::ACCESS_TOKEN_URL, $this->host);
        // create an OAuth Request- configure with local parameters
        $oAuthRequest = OAuthRequest::fromConsumerAndToken($this->consumer, $requestToken, 'GET', $url);
        $oAuthRequest->setParameter('oauth_verifier', $verifier);
        $oAuthRequest->signRequest($this->consumer, $requestToken);
        // Perform request & Retrieve result
        $headers = array($oAuthRequest->toHeader(), 'Accept: application/x-www-form-urlencoded');
        $resultString = $this->performRequest($url, 'GET', $headers);
        // parse the result string (should be www-form-urlencoded
        parse_str($resultString, $result);
        // detect problems
        if (isset($result['oauth_problem'])){
            $this->logger->error("Failed to obtain Access Token", array("host"=>$this->host, "verifier"=>$verifier, "problem"=> $result['oauth_problem']));
            throw new \Exception("Failed to retrieve Access Token because: {$result['oauth_problem']}");
        }
        if (!isset($result['oauth_token']) || !isset($result['oauth_token_secret'])){
            $this->logger->error("Failed to obtain Access Token", array("host"=>$this->host, "verifier"=>$verifier));
            throw new \Exception("Failed to retrieve Access Token.");
        }
        // set the access token for later use
        $this->accessToken = new OAuthToken($result['oauth_token'], $result['oauth_token_secret']);
        // return the token
        return $this->accessToken;
    }

    /**
     * @param string $username
     * @param string $password
     * @throws \Exception
     * @return OAuthToken
     */
    public function getAccessTokenViaGateway($username, $password){
        $this->logger->info("Obtaining Request Token via Gateway", array("host"=>$this->host, "username"=>$username));
        // create url with consumer_key
        $url = sprintf(self::GATEWAY_URL, $this->host, urlencode($this->consumer->key));
        // create auth header
        $headers = array(
            'Authorization: Basic ' . base64_encode("{$username}:{$password}")
        );

        $resultString = $this->performRequest($url, 'GET', $headers);

        parse_str($resultString, $result);
        // detect problems
        if (isset($result['oauth_problem'])){
            $this->logger->error("Failed to obtain Request Token via Gateway", array("host"=>$this->host, "username"=>$username, "problem"=> $result['oauth_problem']));
            throw new \Exception("Failed to retrieve Request Token via Gateway because: {$result['oauth_problem']}");
        }
        if (!isset($result['oauth_token']) || !isset($result['oauth_token_secret']) || !isset($result['oauth_verifier'])){
            $this->logger->error("Failed to obtain Request Token via Gateway", array("host"=>$this->host, "username"=>$username));
            throw new \Exception("Failed to retrieve Request Token via Gateway.");
        }
        // create the request token
        $requestToken = new OAuthToken($result['oauth_token'], $result['oauth_token_secret']);
        $verifier = $result['oauth_verifier'];
        // obtain the access token
        return $this->getAccessToken($requestToken, $verifier);
    }


    /**
     * @param string $url
     * @param string $method
     * @param array  $headers
     * @param string $content
     *
     * @return string
     * @throws \Exception
     */
    private function performRequest($url, $method='GET', $headers=array(), $content=''){
         $options = array(
            'http' => array(
                'content' => $content,
                'header'  => $headers,
                'method'  => $method,
                'timeout' => 10.0,
                'ignore_errors'=>true
            )
        );
        $context = stream_context_create($options);
        // connect and open the stream
        $stream = fopen($url, 'r', false, $context);
        // get the response headers etc.
        $headers = stream_get_meta_data($stream);
        // actual data at $url
        $content = stream_get_contents($stream);
        fclose($stream);

        if (!isset($headers['wrapper_data'])){
            throw new \Exception("Failed to connect to URL {$url}");
        }
        $this->logger->info('Received Reply', array('headers'=>$headers, 'content'=>$content));
        list ($successful, $statusCode, $statusMessage) = $this->checkStatus($headers['wrapper_data']);
        if (!$successful){
            $this->logger->error('Request was not successful',array('url'=>$url, 'context_options'=>$options, 'headers'=>$headers, 'content'=>$content));
            throw new \Exception("Request failed, received: {$statusCode} {$statusMessage}");
        }
        return $content;
    }

    /**
     * @param $headers
     * @return array
     */
    private function checkStatus($headers){
        if (isset($headers[0]) && count($parts = explode(' ', $headers[0], 3)) == 3) {
            $statusCode = (integer) $parts[1];
            $statusMessage = $parts[2];
            $success = (200 <= $statusCode  && $statusCode < 300);
            return array($success, $statusCode, $statusMessage);
        } else {
            return array(false, 0, "Unknown");
        }
    }

    /**
     * Sets a logger instance on the object
     *
     * @param \Psr\Log\LoggerInterface $logger
     *
     * @return null
     */
    public function setLogger(\Psr\Log\LoggerInterface $logger)
    {
        $this->logger = $logger;
    }
}

