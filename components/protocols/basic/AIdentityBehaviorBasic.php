<?php
/**
 * AIdentityBehaviorBasic
 *
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 * 
 */
class AIdentityBehaviorBasic extends AIdentityBehavior {
	
	/**
	 * @param string $password
	 * @return boolean 
	 */
	public function apiAuthValidatePassword($password)
	{
		//compare user supplied password against the password we know.
		return (ApiAuth::encryptBasic($this->owner->password) === $password);
	}
}