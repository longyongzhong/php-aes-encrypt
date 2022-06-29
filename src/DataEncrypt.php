<?php


namespace PhpAesEncrypt;


use PhpAesEncrypt\exception\AESEncryptException;
use PhpAesEncrypt\exception\Sha1SignException;

class DataEncrypt
{
    private $token;
    private $encodingAesKey;
    private $appId;

    public function __construct($token, $encodingAesKey, $appId)
    {
        $this->token = $token;
        $this->encodingAesKey = $encodingAesKey;
        $this->appId = $appId;
    }

    /**
     * 加密数据
     * @param $data
     * @param $nonce
     * @param null $timeStamp
     * @return array
     * @throws exception\AESEncryptException
     */
    public function encryptData(string $data, string $nonce, $timeStamp = null)
    {
        try {
            $cipherAlgo = 'AES-128-CBC';
            $ivLength = openssl_cipher_iv_length($cipherAlgo);
            $iv = openssl_random_pseudo_bytes($ivLength);
            $data = pack("N", strlen($data)) . $data . $this->appId;
            $encryptedData = openssl_encrypt($data, $cipherAlgo, $this->encodingAesKey, OPENSSL_RAW_DATA, $iv);
            $encryptedDataBase64 = base64_encode($encryptedData);
            $timeStamp == null && $timeStamp = time();
            $ivBase64 = base64_encode($iv);
            $signature = $this->getSHA1($this->token, $timeStamp, $nonce, $encryptedDataBase64, $ivBase64);
        }catch (\Exception $e){
            throw new AESEncryptException($e->getMessage());
        }
        return [
            'encrypted_data' => $encryptedDataBase64,
            'timestamp' => $timeStamp,
            'signature' => $signature,
            'nonce' => $nonce,
            'app_id' => $this->appId,
            'iv' => $ivBase64
        ];
    }

    /**
     * 解密数据
     * @param $encryptedData
     * @param $iv
     * @param $signature
     * @param $nonce
     * @param null $timeStamp
     * @return string
     * @throws Sha1SignException
     */
    public function decryptData($encryptedData, $iv, $signature, $nonce, $timeStamp = null)
    {
        try {
            $timeStamp == null && $timeStamp = time();
            if ($signature != $this->getSHA1($this->token, $timeStamp, $nonce, $encryptedData, $iv)){
                throw new Sha1SignException('签名验证失败');
            }
            $cipherAlgo = 'AES-128-CBC';
            $iv = base64_decode($iv);
            $encryptedData = base64_decode($encryptedData);
            $decryptedData = openssl_decrypt($encryptedData, $cipherAlgo, $this->encodingAesKey, OPENSSL_RAW_DATA, $iv);
            $dataLength = unpack("N", substr($decryptedData, 0, 4))[1];
            $data = substr($decryptedData, 4, $dataLength);
            $appId = substr($decryptedData, $dataLength + 4);
            if ($appId != $this->appId) throw new \Exception('appID不一致');
        }catch (\Exception $e){
            throw new AESEncryptException($e->getMessage());
        }
        return $data;
    }

    /**
     * 用SHA1算法生成安全签名
     * @param string $token 票据
     * @param string $timestamp 时间戳
     * @param string $nonce 随机字符串
     * @param string $encryptedData
     * @param $iv
     * @return string
     */
    public function getSHA1(string $token, $timestamp, string $nonce, string $encryptedData, $iv)
    {
        //排序
        $array = array($encryptedData, $token, $timestamp, $nonce, $iv);
        sort($array, SORT_STRING);
        $str = implode($array);
        return sha1($str);
    }
}
