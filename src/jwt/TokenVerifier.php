<?php
/**
 * Created by PhpStorm.
 * User: sariel
 * Date: 09/04/2016
 * Time: 3:54 PM
 */

namespace jwt;




use Exception;
use Firebase\JWT\JWT;

class TokenVerifier
{

    /**
     * @var Config
     */
    private $config;

    public function __construct(Config $config)
    {

        $this->config = $config;
    }

    private function getToken()
    {

        $authHeader = $_SERVER['Authorization'];

        list($jwt) = sscanf($authHeader, 'Authorization: Bearer %s');

        return $jwt;
    }

    private function isValidToken($jwt)
    {

        $secretKey = base64_decode($this->config->secretKey);

        try {
            JWT::decode($jwt, $secretKey, $this->config->algorithm);
        } catch (Exception $e) {

            echo 'Caught exception: ', $e->getMessage(), "\n";
            return false;
        }
        return true;

    }

    public  function verifyToken(){

        return $this->isValidToken($this->getToken());
    }
}