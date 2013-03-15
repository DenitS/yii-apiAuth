<?php
/**
 * HttpDigest
 *
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 */
class AHttpAuthenticatorBasic extends AHttpAuthenticator implements IAHttpAuthenticator {
	
	public function beforeAuthentication() {
		
		if(!parent::beforeAuthentication())
			return false;
		
		//parse headers
		if(!isset($_SERVER['PHP_AUTH_USER']))
			return false;
		
		//load an identity with the username and password
		$this->identity = $this->loadIdentity($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
		
		return true;
	}
	
	public function authenticate() 
	{
		return $this->identity->authenticate();
	}
	
	public function afterAuthentication() 
	{	
		parent::afterAuthentication();
	}
	
	/**
	 * This function will be called when the user is cannot be authenticated
	 */
	public function unauthenticated($message='Unauthorized')	
	{
		header('WWW-Authenticate: Basic realm="' . Yii::app()->apiAuth->realm);
		throw new CHttpException('401', $message);
	}
}
