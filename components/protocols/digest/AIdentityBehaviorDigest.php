<?php
/**
 * AIdentityBehaviorDigest
 * 
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 * 
 */
class AIdentityBehaviorDigest extends AIdentityBehavior {
	
	public $challengeResponseCallback;
	
	/**
	 * @param string $password
	 * @return boolean 
	 */
	public function apiAuthValidatePassword($password)
	{
		//execute challenge response callback method
		return (call_user_func($this->challengeResponseCallback, $password) === true);
	}
}