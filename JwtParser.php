<?php
set_include_path(get_include_path() . PATH_SEPARATOR . './phpseclib');
include_once('Crypt/RSA.php');
include_once('Math/BigInteger.php');

include_once('./ApiConnecter.php');


class JwtParser{
  //公開鍵を取得するためのエンドポイントURL
  protected $jwks_uri = '';

  //JWTをデコードした中身
  protected $jwt_string = '';
  protected $header    = [];
  protected $payload   = [];
  protected $signature = '';

  //公開鍵の内容
  protected $kid                 = '';
  protected $modulus             = '';
  protected $exponent            = '';
  protected $public_key_pem      = '';
  protected $public_key_resource = null;


  //---------------------------------------------
  //public_functions
  //---------------------------------------------
  public function __construct($jwt_string = null){
    if(empty($jwt_string)){
      return;
    }
    $this->jwt_string = $jwt_string;
    $this->splitJwtString();
    $this->generatePublicKey();
  }


  //setter
  public function setModulus($modulus){
    $this->modulus = $modulus;
  }
  public function setExponent($exponent){
    $this->exponent = $exponent;
  }


  //getter
  public function getJwt() {
    return $this->jwt_string;
  }
  public function getAlg() {
    return $this->header['alg'];
  }
  public function getKid() {
    return $this->kid;
  }
  public function getPayload() {
    return $this->payload;
  }
  public function getSignature() {
    return $this->signature;
  }

  public function getModulus() {
    return $this->modulus;
  }
  public function getExponent() {
    return $this->exponent;
  }

  public function getModulusInt() {
    $bin_modulus  = self::urlSafeBase64Decode($this->getModulus());
    return self::os2ip($bin_modulus);
  }
  public function getExponentInt() {
    $bin_exponent  = self::urlSafeBase64Decode($this->getExponent());
    return self::os2ip($bin_exponent);
  }

  public function getPublicKeyPem() {
    return $this->public_key_pem;
  }
  public function getPublicKeyResource() {
    return $this->public_key_resource;
  }

  public function iss_url(){
    return $this->payload['iss'].'.well-known/openid-configuration?p='.$this->payload['tfp'];
  }


  //PEM文字列を手動で生成
  public function generatePem(){
    $this->public_key_pem      = self::generatePemFormatStringFromModulusAndExponent($this->modulus, $this->exponent);
    $this->public_key_resource = openssl_get_publickey($this->public_key_pem);
  }


	/**
   * RSA 暗号で使われる「Modulus」と「Exponent」との値を受け取り、PEMフォーマットの文字列を生成する。
   * 「phpseclib」のライブラリが必須。 : http://phpseclib.sourceforge.net/index.html
   * 引数のふたつはAzure（やGoogleやYahoo）の公開鍵配布エンドポイント（ https://login.microsoftonline.com/XXXXX......./discovery/v2.0/keys?p=該当のポリシー名 ）
   * がよこすキーに含まれる「n」「e」の値。「AQAB」とか「tVKUtcx_n9rt5afY_2WF…」とかの値。
   * 
   * @param  string 公開鍵APIのよこすModulusの値。ふたつの素数の積。「n」とか「m」とかの略称で解説される。
   * @param  string 公開鍵APIのよこすExponentの値。「e」という略称で解説される。
   * @return string PEMフォーマットの文字列。openssl_get_publickey() の引数に使うことができる。
   */
  public static function generatePemFormatStringFromModulusAndExponent($modulus, $exponent){
    //公開鍵配布のAPIから受け取った値をURL対応Base64デコードしてバイナリデータを取得する
    $bin_modulus  = self::urlSafeBase64Decode($modulus);
    $bin_exponent = self::urlSafeBase64Decode($exponent);

    //バイナリデータをOS2IPという規格に従って整数に変換する。ここではMath_Bigintegerというオブジェクトにしている。
    $int_modulus  = self::os2ip($bin_modulus);
    $int_exponent = self::os2ip($bin_exponent);

    $rsa = new Crypt_RSA();
    $rsa->loadKey(
      [
        'e' => self::convertBinaryToBigIntegerObj($bin_exponent),
        'n' => self::convertBinaryToBigIntegerObj($bin_modulus)
      ]
    );
    return $rsa->getPublicKey();
  }


  /**
   * Base64デコードする。
   * 
   * base64_decode()関数の改良版
   *   * 入力文字の文字数が4の倍数でない場合、足りない分にパディング（=）を追加する。
   *     Base64の規格により、Base64エンコードされた文字列は4の倍数の文字数でなければならないため。
   *   * URLにおいて問題を起こす値（「+」と「/」）の取り扱いへの対応。base64urlというがPHPにはそのためのズバリな関数はない。
   * 
   * @param  string Base64エンコードされた文字列
   * @return string/binary Base64デコードされたデータ
   */
  public static function urlSafeBase64Decode($str) {
    $dec = strtr($str, "-_", "+/"); //URL対応する場合 : 「+」「/」への対応

    switch (strlen($dec) % 4) {
      case 0:
        break;
      case 2:
        $dec .= "==";
        break;
      case 3:
        $dec .= "=";
        break;
      default:
        return "";
    }
    return base64_decode($dec);
  }


  /**
   * Base64デコードされたバイナリデータを大きな整数オブジェクト（class Math_BigInteger）に変換する
   * 
   * @param  binary     base64デコードされたバイナリデータ
   * @return Math_BigInteger /phpseclib/Math/BigInteger.php のクラス
   */
  public static function convertBinaryToBigIntegerObj($bin){
    return new Math_BigInteger($bin, 256);
  }


  /**
   * Base64デコードされたバイナリデータを整数に変換する
   * この変換方式を「OS2IP」といい、バイト列を正の整数に変換する関数。
   * 
   * 参考 : https://qiita.com/bobunderson/items/d48f89e2b3e6ad9f9c4c#rsassa-pkcs1-v1_5
   * 
   * @param  binary base64デコードされたバイナリデータ
   * @return int
   */
  // 
  public static function os2ip($bin){
    return self::convertBinaryToBigIntegerObj($bin)->toString();
  }

  //---------------------------------------------
  //protected_functions
  //---------------------------------------------
  /**
   * JWTを分割して各プロパティにセットする。
   * JWTはピリオドで分割し、各文字列をBase64デコードする。ヘッダーとペイロード（コンテンツ部分）はJSONになる。
   */
  protected function splitJwtString(){
    if (empty($this->jwt_string)){
      return;
    }
    $split_jwt_strings = explode('.', $this->jwt_string);

    $this->header    = $this->convertJwtPartToArray($split_jwt_strings[0]);
    $this->kid       = $this->header['kid'];
    $this->payload   = $this->convertJwtPartToArray($split_jwt_strings[1]);
    $this->signature = $split_jwt_strings[2];
  }


  /**
   * JWTのヘッダー部分とコンテンツ部分の文字列をパースし、配列にする。
   * Base64エンコード文字列
   * →Jsonオブジェクト
   * →配列
   * 
   * @param  string JWTをピリオドで分割した部分のひとつ
   * @return array
   */
  protected function convertJwtPartToArray($str_jwt_part){
    if(empty($str_jwt_part)){
      return;
    }
    $str_base64_decoded = self::urlSafeBase64Decode($str_jwt_part);
    $json_array = json_decode($str_base64_decoded, true);
    return $json_array;
  }


  /**
   * Azure が配布している、IDトークン検証用の公開鍵を作成する。
   * 公開鍵は複数配布されることがあり、キーIDで識別できる。
   * 
   * 作成したポリシーごとに「OpenID Connect メタデータ エンドポイント」が用意されており、
   * ここから得られるデータのうち「jwks_uri」の値になっているURLのWebAPIに接続すると
   * 公開鍵のデータが得られる。
   * 
   * 公開鍵のデータ「Modulus(n)」「Exponent(e)」のふたつの値からPEMフォーマット文字列を生成可能。
   * 
   * @return null
   */
  protected function generatePublicKey(){
    $open_id_connect_metadata_json = ApiConnecter::postDataAndGetContentFromUrl(
      $this->iss_url(),
      [],
      $method = 'GET'
    );
    $open_id_connect_metadata_array = json_decode($open_id_connect_metadata_json, true);
    $this->jwks_uri = $open_id_connect_metadata_array['jwks_uri'];

    if(empty($this->jwks_uri) == false){
      $public_keys_json = ApiConnecter::postDataAndGetContentFromUrl(
        $this->jwks_uri,
        [],
        $method = 'GET'
      );
      $public_keys_array = json_decode($public_keys_json, true);
      if((empty($public_keys_array) == false)&&(empty($public_keys_array['keys']) == false)){
        foreach($public_keys_array['keys'] as $now_key_array){
          if($now_key_array['kid'] == $this->getKid()){
            $public_key_array = $now_key_array;

            $this->modulus             = $now_key_array['n'];
            $this->exponent            = $now_key_array['e'];
            $this->public_key_pem      = self::generatePemFormatStringFromModulusAndExponent($this->modulus, $this->exponent);
            $this->public_key_resource = openssl_get_publickey($this->public_key_pem);
          }
        }
      }
    }
  }


}
