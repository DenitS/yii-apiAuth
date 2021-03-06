<?php

require_once(__DIR__.'/base/interfaces.php');

defined("YII_APIAUTH_BEGIN_TIME") or define("YII_APIAUTH_BEGIN_TIME", microtime(true));

/**
 * ApiAuth : The first A in AAA
 * Authenticate a user through Http Authentication Protocols like Http Digest or Http Basic
 * 
 * See the attached README.md file for installation and configuraton instructions
 * LICENSE and DISCLAIMER: See the attached LICENSE file.
 * 
 * @since 2013-01-27
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 * 
 */
class ApiAuth extends CComponent {
	
	public static $tablePrefix = "apiauth_";
	
	//auth settings
	public $realm = 'Restricted Area';
	public $protocol = self::AUTH_DIGEST; //'basic' or 'digest'
	public $hash;	//NOTE: When $protocol = 'digest', either specify 'md5' or leave this empty.
	
	//db config
	public $userClass = 'User';
	public $userIdentityClass = 'AUserIdentity'; //Only change this value to an Identity Class that extends AUserIdentity.
	public $userIdAttribute = 'id';
	public $usernameAttribute = 'username'; //This value will be set to the useridentity's getName() getter
	public $passwordAttribute = 'password';
	public $apiAuthUsernameAttribute;	//The value in from this attribute will be used as username in Http Authentication. It can be the same as $usernameColumn, but doesn't have to be.
	public $apiAuthPasswordAttribute;	//The value in from this attribute will be used as password in Http Authentication. It can be the same as $passwordColumn, but doesn't have to be.
	public $activeAttribute; //leave empty if your user model doesn't have this. When this property is used and it evaluates to false, access will be denied when using AUserIdentity.
	public $blockedAttribute; //leave empty if your user model doesn't have this. When this property is used and it evaluates to true, access will be denied when using AUserIdentity.
	
	//debug
	public $debug = false;
	
	//profiling
	public $enableProfiling = false;
	
	
	//available Authentication methods.
	const AUTH_BASIC = 'basic';
	const AUTH_DIGEST = 'digest';
	
	public function init()
	{	
		Yii::app()->setImport(array(
			'ext.apiAuth.components.*',
			'ext.apiAuth.components.protocols.*',
			'ext.apiAuth.components.protocols.basic.*',
			'ext.apiAuth.components.protocols.digest.*',
			'ext.apiAuth.models.*',
		));
		
		//set optional paramaters
		$this->initParameters();
		
		if($this->debug) {
			//validate them
			$this->validateParameters();
		}
	}
	
	private function initParameters()
	{
		if(empty($this->apiAuthUsernameAttribute))
			$this->apiAuthUsernameAttribute = $this->usernameAttribute;
		if(empty($this->apiAuthPasswordAttribute))
			$this->apiAuthPasswordAttribute = $this->passwordAttribute;
	}
	
	public function encryptPassword($username, $password)
	{
		//based on current config:
		if(empty($this->hash))
			return $password;
		
		switch($this->protocol) 
		{
			case self::AUTH_BASIC:
				return self::encryptBasic($password);
			case self::AUTH_DIGEST:
				return self::encryptDigestHA1($this->realm, $username, $password);
		}
		
		throw new Exception("Invalid authentication protocol: " . $this->protocol);
	}
	
	public static function encryptBasic($string)
	{
		$hash = Yii::app()->apiAuth->hash;
		if(!$hash)
			return $string;
		
		switch($hash)
		{
			case "md5":
				return md5($string);
			case "sha1":
				return sha1($string);
			default:
				return hash($hash, $string);				
		}
		return false;
	}
	
	/**
	 * Encrypt password parts in HA1 format for HTTP Digest Reponse
	 * 
	 * @param string $realm
	 * @param string $username
	 * @param string $password
	 * @return string 
	 */
	public static function encryptDigestHA1($realm, $username, $password)
	{
		return md5($username . ":" . $realm . ":" . $password);
	}
	
	public static function getTablePrefix()
	{
		return self::$tablePrefix;
	}
	
	private function ensureParamRequired($param)
	{
		if(empty($this->$param)) {
			throw new Exception("ApiAuth extension misconfigured. Missing required parameter: " . $param);
		}
	}
	
	private function ensureParamClassExists($param)
	{
		$className = $this->$param;
		if(!class_exists($className)) {
			throw new Exception("ApiAuth extension misconfigured. Invalid parameter $param. Class $className not found.");
		}
	}
	
	private function validateParameters()
	{	
		$this->ensureParamRequired('userClass');
		$this->ensureParamRequired('userIdentityClass');
		$this->ensureParamRequired('userIdAttribute');
		$this->ensureParamRequired('usernameAttribute');
		$this->ensureParamRequired('passwordAttribute');
		$this->ensureParamRequired('apiAuthUsernameAttribute');
		$this->ensureParamRequired('apiAuthPasswordAttribute');
		
		$this->ensureParamClassExists('userClass');
		$this->ensureParamClassExists('userIdentityClass');
	}
	
	public static function beginProfile($token, $category='ext.apiAuth') {
		$apiAuth = Yii::app()->apiAuth;
		if(isset($apiAuth) && Yii::app()->apiAuth->enableProfiling) {
			Yii::beginProfile($token, $category);
		}
	}
	public static function endProfile($token, $category='ext.apiAuth') {
		$apiAuth = Yii::app()->apiAuth;
		if(isset($apiAuth) && Yii::app()->apiAuth->enableProfiling) {
			Yii::endProfile($token, $category);
		}
	}
}