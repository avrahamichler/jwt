<?php
/**
 * Created by PhpStorm.
 * User: sariel
 * Date: 09/04/2016
 * Time: 2:07 PM
 */

namespace jwt;



use Firebase\JWT\JWT;

class TokenBuilder
{


    private $iat ;               // Issued at: time when the token was generated
    private $jti;               // Json Token Id: an unique identifier for the token
    private $iss;               // Issuer
    private $nbf;               // Not before
    private $expire;              // Expire
    private $userId;             // Data related to the signer user
    private $userName;
    /**
     * @var Config
     */
    private $config;

    public function __construct(Config $config)
    {

        $this->config = $config;
    }

    /**
     * @return mixed
     */
    public function getIat()
    {
        return $this->iat;
    }

    /**
     * @param mixed $iat
     *  Issued at: time when the token was generated
     * @return $this
     */
    public function setIat($iat)
    {
        $this->iat = is_null($iat)  ? time() : $iat;

        return $this;
    }

    /**
     * @return mixed
     */
    public function getJti()
    {
        return $this->jti;
    }

    /**
     * @param mixed $jti
     * @return $this
     */
    public function setJti($jti)
    {
        $this->jti = is_null($jti) ? base64_encode(mcrypt_create_iv(32)): $jti;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getIss()
    {
        return $this->iss;
    }

    /**
     * @param mixed $iss
     * @return $this
     */
    public function setIss($iss = 'localhost')
    {
        $this->iss = $iss;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getNbf()
    {
        return $this->nbf;
    }

    /**
     * @param mixed $nbf
     * @return $this
     */
    public function setNbf($nbf)
    {
        $this->nbf = is_null($nbf)  ? time() : $nbf;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getUserId()
    {
        return $this->userId;
    }

    /**
     * @param mixed $userId
     * @return $this
     */
    public function setUserId($userId)
    {
        $this->userId = $userId;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getUserName()
    {
        return $this->userName;
    }

    /**
     * @param mixed $userName
     * @return $this
     */
    public function setUserName($userName)
    {
        $this->userName = $userName;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getExpire()
    {
        return $this->expire;
    }

    /**
     * @param mixed $expire
     * @return $this
     */
    public function setExpire($expire)
    {
        $this->expire = $expire;
        return $this;
    }

    /**
     * @return string the token in string
     */
    public function build()
    {

       /* * Encode the array to a JWT string.
           * Second parameter is the key to encode the token.
           *
           * The output string can be validated at http://jwt.io/
           */

        $data = $this->getDataJWT();

        $jwt = $this->createToken($data);

        return $this->JWTTokenToString($jwt);
    }

    /**
     * @return array
     */
    private function getDataJWT()
    {
        $data = [
            'iat' => $this->iat,         // Issued at: time when the token was generated
            'jti' => $this->jti,          // Json Token Id: an unique identifier for the token
            'iss' => $this->iss,       // Issuer
            'nbf' => $this->nbf,        // Not before
            'exp' => $this->expire,           // Expire
            'data' => [                  // Data related to the signer user
                'userId' => $this->userId, // userid from the users table
                'userName' => $this->userName, // User name
            ]
        ];
        return $data;
    }

    /**
     * @param $data
     * @return string
     */
    private function createToken($data)
    {
        $secretKey = base64_decode($this->config->secretKey);

        $jwt = JWT::encode(
            $data,      //Data to be encoded in the JWT
            $secretKey, // The signing key
            $this->config->algorithm  // Algorithm used to sign the token, see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3
        );
        return $jwt;
    }

    /**
     * @param $jwt
     */
    private function JWTTokenToString($jwt)
    {
        $unencodedArray = ['jwt' => $jwt];
        json_encode($unencodedArray);
    }


}