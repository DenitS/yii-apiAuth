<?php
/*
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 */

interface IAHttpAuthenticator {

	public function login();
	public function authenticate();
	public function unauthenticated($message);
	public function getIdentity();
	public function setIdentity($value);
	
}

interface IAIdentityBehavior {
	
	/**
	 * Validate identity password. 
	 * Every derived Identity Behavior class needs to override this method
	 * 
	 * @param string $password
	 * @return boolean 
	 */
	public function apiAuthValidatePassword($password);
	public function isValidApiAuthPassword($password);
	public function getPasswordValidationPerformed();
}


/**
* Constant time string comparison. This method has been gratefully borrowed from:
* http://www.yiiframework.com/wiki/425
* 
* @param string $a
* @param string $b
* @return boolean True when strings are equal. False otherwise
*/
function equals_ct($a, $b) {
   /**
	* @see http://codereview.stackexchange.com/questions/13512 
	*/
   if (!is_string($a) || !is_string($b)) {
	   return false;
   }
   $mb = function_exists('mb_strlen');
   $length = $mb ? mb_strlen($a, '8bit') : strlen($a);
   if ($length !== ($mb ? mb_strlen($b, '8bit') : strlen($b))) {
	   return false;
   }
   $check = 0;
   for ($i = 0; $i < $length; $i += 1) {
	   $check |= (ord($a[$i]) ^ ord($b[$i]));
   }
   return $check === 0;
}