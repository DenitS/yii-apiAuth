<?php
/**
 * AIdentityBehavior
 *
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 * 
 * @property-read boolean $passwordValidationPerformed Returns true when isValidApiAuthPassword() has been called.
 */
abstract class AIdentityBehavior extends CBehavior implements IAIdentityBehavior {
	
	const behaviorName = 'apiAuthIdentityBehavior';
	private $_passwordValidationPerformed = false;
	
	/**
	 * Apply the behavior that corresponds to the configure 
	 * authentication method (basic or digest) to $identity
	 * 
	 * @param CUserIdentity $identity
	 * @throws Exception when extension is configured with an unsupported authMethod
	 */
	public static function apply($identity)
	{	
		//handle different authentication methods
		switch(Yii::app()->apiAuth->protocol) 
		{
			//basic
			case ApiAuth::AUTH_BASIC:
				$identity->attachBehavior(self::behaviorName, new AIdentityBehaviorBasic);
				break;
			
			//digest
			case ApiAuth::AUTH_DIGEST:
				$identity->attachBehavior(self::behaviorName, new AIdentityBehaviorDigest);
				break;
			
			default:
				//do not allow authentication methods other than the ones specified above.
				throw new Exception("Behavior not implemented for authentication method: " . Yii::app()->apiAuth->protocol);
				break;
		}
	}
	
	/**
	 * This method simply returns the result of the protected apiAuthValidatePassword() method.
	 * This method flags this behavior's instance as having performed password validation
	 * so the Authenticator is able to see if the UserIdentity to wich this 
	 * behavior applies, actually calls this method. If it hasn't called this method
	 * authentication will fail.
	 * 
	 * @param string $password
	 * @return boolean True if password was succesfully validated, otherwise False 
	 */
	final public function isValidApiAuthPassword($password)
	{
		$isValid = ($this->apiAuthValidatePassword($password) === true);
		$this->_passwordValidationPerformed = true;
		return $isValid;
	}
	
	/**
	 * Returns true when isValidApiAuthPassword() has been called.
	 * 
	 * @return boolean
	 */
	final public function getPasswordValidationPerformed()
	{
		return $this->_passwordValidationPerformed;
	}
}