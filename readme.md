# JWT及び公開鍵配布APIから得られる「e」「n」の値検証用サンプルプログラム

## 動作するPHPのバージョン
PHP Version 5.6.30 で動作確認済み

## 必須ライブラリ
* <a href="http://phpseclib.sourceforge.net/" target="_blank">phpseclib]</a>

### ライブラリ設置方法
ダウンロードした phpseclib を解凍し、以下のように設置してください。

```
index.php
ApiConnecter.php
JwtParser.php
phpseclib
  ├ phpseclib
  ├ Crypt
  │├ AES.php
  │├ …（各ファイル）
  ├ File
  │├ ANSI.php
  │├ …（各ファイル）
  ├ Math
  │├ BigInteger.php
  │├ …（各ファイル）
  …（以下略）
```

## 使い方
解析したいJWTの値、もしくはAzureやGoogleやYahooの公開鍵配布APIから取得した公開鍵の「e」「n」の値が手元にあるとする。

* XAMPPか何かでPHPが動くようにする。
* clone したディレクトリに、ダウンロードした phpseclib を解凍して配置する。
* index.php をブラウザで表示する。
* 取得したJWT、もしくは公開鍵の「e」「n」の値をフォームに入力し、対応する送信ボタンを押す。

## メモ
class JwtParser は、JWTや「e」「n」の検証実験や学習用に作ったものなので、洗練されたコードではありません。  
無駄にpublic static メソッドが多かったり、無駄なコメントがたくさんあったりします。
