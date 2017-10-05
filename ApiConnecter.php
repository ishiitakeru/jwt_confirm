<?php

/**
 * WebAPIに接続して戻り値を取得する。
 * 認証やトークンなどを必要としないシンプルな接続先に対して使える簡易版。
 */

class ApiConnecter{

	////////////////////////////////////////////////////////////
	/**
	 * APIにPOSTで値を送信値、戻り値を取得する。
	 * ベーシック認証には非対応。
	 * 
	 * @param  接続先APIのURL
	 * @param  array POST送信する値のセットの連想配列
	 * @param  string 送信メソッド（GET / POST）
	 * @return APIからの戻り値
	 */
	public static function postDataAndGetContentFromUrl(
		$api_url,
		$post_array,
    $method = 'POST'
	){

		//////////////////////////////
		//ポストデータを文字列の形に
		$data = http_build_query($post_array, "", "&");

		//////////////////////////////
		//コンテキストインスタンスにセットするオプションの配列を作成
		//options は、 $arr['wrapper']['option'] = $value のような形式の、連想配列の連想配列である必要がある
		//参照 : http://jp2.php.net/manual/ja/context.http.php
		$options_array = array();
		//送信メソッド
		$options_array["http"]["method"]  = $method;
		//ヘッダー
		$options_array["http"]["header"]  = "Content-type: application/x-www-form-urlencoded\r\n"
		                                  . "Content-Length: " . strlen($data) . "\r\n";
		//コンテント
		$options_array["http"]["content"] = $data;


		//////////////////////////////
		//コンテキストインスタンスを作成
		$context = stream_context_create();
		//コンテキストにオプション情報（ヘッダー情報、コンテントの内容、送信メソッドなど）をセット
		stream_context_set_option(
			$context,
			$options_array
		);

		//////////////////////////////
		//送信
		try{
			//APIへのクエリ送信、戻ってきたデータの受取
			$return_data = file_get_contents(
				$api_url, //接続先のURL
				false,    //パス検索
				$context  //送信する内容（リソースコンテクスト）
			);

		}catch(Exception $e){
			$return_data = "エラー : APIからのデータ取得に失敗しました。<br>\n".$e;

		}//try

		return $return_data;
	}//function
}//class
