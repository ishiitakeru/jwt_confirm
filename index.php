<?php 
require_once('./JwtParser.php');

//JWT解析
if((empty($_REQUEST['mode']) == false)&&($_REQUEST['mode'] == 'jwt')){
  $jwt = $_REQUEST['jwt'];
  $jwt_parser = new jwtParser($jwt);
}

//公開鍵の「e」「n」解析
if((empty($_REQUEST['mode']) == false)&&($_REQUEST['mode'] == 'en')){
  $jwt_parser = new jwtParser();
  $e = $_REQUEST['e'];
  $n = $_REQUEST['n'];
  $jwt_parser->setExponent($e);
  $jwt_parser->setModulus($n);
  $jwt_parser->generatePem();
}

?>

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf8" />
<title>WebAPIテスト</title>
<style>
input[type="text"]{
  width: 600px;
}
textarea{
  width:  600px;
  height: 300px;
}
th,
td{
 word-wrap:break-word;
}
th{
  width: 200px;
}
h2{
  margin: 10px 0;
  padding:10px 0;
  border-top:1px dashed silver;
  border-bottom:1px dashed silver;
}
</style>
</head>
<body>

<h1><a href="./index.php">Azure Active Directory B2C WebAPI 送信テスト</a></h1>

<h2>JWT検証</h2>
<p>JWT検証に便利なサイト : <a href="https://jwt.io/" target="_blank">https://jwt.io/</a></p>
<form method="GET" action="index.php">
  <table border="1">
    <tr>
      <th valign="middle">JWT</th>
      <td valign="middle"><textarea name="jwt"><?php echo(@$jwt); ?></textarea></td>
    </tr>
  </table>
  <input type="hidden" name="mode" value="jwt">
  <input type="submit" value="送信">
</form>


<h2>公開鍵の「e」「n」検証</h2>
<form method="GET" action="index.php">
  <table border="1">
    <tr>
      <th valign="middle">e(Exponent)</th>
      <td valign="middle"><input type="text" name="e" value="<?php echo(@$e); ?>" /></td>
    </tr>
    <tr>
      <th valign="middle">n(Modulus)</th>
      <td valign="middle"><textarea name="n"><?php echo(@$n); ?></textarea></td>
    </tr>
  </table>
  <input type="hidden" name="mode" value="en">
  <input type="submit" value="送信">
</form>


<?php if(empty($_REQUEST['mode']) == false){ ?>
  <h2>検証結果</h2>
  <table border="1">

    <?php if($_REQUEST['mode'] == 'jwt'){ ?>
      <tr>
        <th valign="middle">JWT</th>
        <td valign="middle"><textarea style="width:600px; height:600px;"><?php echo($jwt_parser->getJwt()); ?></textarea></td>
      </tr>
      <tr>
        <th valign="middle">kid</th>
        <td valign="middle"><input type="text" value="<?php echo($jwt_parser->getKid()); ?>" /></td>
      </tr>
      <tr>
        <th valign="middle">iss_url</th>
        <td valign="middle">
          <input type="text" value="<?php echo($jwt_parser->iss_url()); ?>" /><br>
          <a href="<?php echo($jwt_parser->iss_url()); ?>" target="_blank">[開く]</a>
        </td>
      </tr>
    <?php } ?>

    <tr>
      <th valign="middle">公開鍵 Exponent<br>素の値</th>
      <td valign="middle">
        <input type="text" value="<?php echo($jwt_parser->getExponent()); ?>" /><br>
      </td>
    </tr>
    <tr>
      <th valign="middle">公開鍵 Exponent<br>OS2IPで整数に変換</th>
      <td valign="middle">
        <input type="text" value="<?php echo($jwt_parser->getExponentInt()); ?>" /><br>
      </td>
    </tr>

    <tr>
      <th valign="middle">公開鍵 Modulus<br>素の値</th>
      <td valign="middle">
        <textarea><?php echo($jwt_parser->getModulus()); ?></textarea><br>
      </td>
    </tr>
    <tr>
      <th valign="middle">公開鍵 Modulus<br>OS2IPで整数に変換</th>
      <td valign="middle">
        <textarea><?php echo($jwt_parser->getModulusInt()); ?></textarea><br>
      </td>
    </tr>

    <tr>
      <th valign="middle">公開鍵文字列(PEM)</th>
      <td valign="middle"><textarea><?php echo($jwt_parser->getPublicKeyPem()); ?></textarea></td>
    </tr>

    <tr>
      <th valign="middle">公開鍵リソース</th>
      <td valign="middle"><?php var_dump($jwt_parser->getPublicKeyResource()); ?></td>
    </tr>

  </table>
  <hr>
<?php } ?>


</body>
</html>