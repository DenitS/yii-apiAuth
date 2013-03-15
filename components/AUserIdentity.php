<?php
/**
 * AUserIdentity represents the data needed to identity an API Client.
 * It contains the authentication method that checks if the provided
 * data can identity the user.
 * 
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 * 
 */
class AUserIdentity extends CUserIdentity
{
	/**
	 * Authenticates a user.
	 */
	private $_id;
	private $_name;
	
	//user errors
	const ERROR_USER_BLOCKED=403;
	
	public function authenticate()
	{
		//check if username supplied
		if(empty($this->username)) {
			$this->errorCode = self::ERROR_UNKNOWN_IDENTITY;
			return false;
		}
		
		//get user model
		$user = $this->getUserModel();
		if(empty($user)) {
			//retain unknown identity error code when not debugging for slightly better security!
			$this->errorCode = (YII_DEBUG)? self::ERROR_UNKNOWN_IDENTITY : self::ERROR_USERNAME_INVALID;
			return false;
		}

		//check if user blocked
		if($this->isUserBlocked($user)) {
			$this->errorCode = self::ERROR_USER_BLOCKED;
			return false;
		}
		
		//perform password checks
		if($this->validatePassword($user) !== true) {
			$this->errorCode = (YII_DEBUG)? self::ERROR_UNKNOWN_IDENTITY : self::ERROR_PASSWORD_INVALID;
			return false;
		}
		
		//OK! all checks passed. yay!
		
		//set identity properties
		$this->_id = $user->getAttribute(Yii::app()->apiAuth->userIdAttribute);
		$this->_name = $user->getAttribute(Yii::app()->apiAuth->usernameAttribute);
		
		//return true
		$this->errorCode = self::ERROR_NONE;
		return true;
	}
	
	protected function getUserModel()
	{
		$apiAuth = Yii::app()->apiAuth;
		return CActiveRecord::model($apiAuth->userClass)->findByAttributes(array($apiAuth->apiAuthUsernameAttribute => $this->username));
	}
	
	private function validatePassword($user)
	{
		//If apiAuthIdentityBehavior is attached to this Identity, test through apiAuth behavior
		if(isset($this->apiAuthIdentityBehavior)) {
			// - perform apiAuth password validation
			return ($this->_isValidApiAuthPassword($user) === true);	
		} else {
			//If apiAuthIdentityBehavior isn't attached to this Identity, test custom userPassword validation
			//This can only occur if the programmer is using this identity outside apiAuth authenticators.
			return ($this->isValidUserPassword($user) === true);
		}
		
		//we won't ever get here. but hey..
		return false;
	}
	
	/**
	 * Check to see if user is not blocked
	 * 
	 * @param object $user User object (type: Yii::app()->apiAuth->userClass)
	 * @return boolean True if confirmed to be blocked, otherwise false.
	 */
	protected function isUserBlocked($user)
	{
		$activeColumn = Yii::app()->apiAuth->activeAttribute;
		if(!empty($activeColumn) && $user->$activeColumn == false) {
			return true;
		}
		
		$blockedColumn = Yii::app()->apiAuth->blockedAttribute;
		if(!empty($blockedColumn) && $user->$blockedColumn == true) {
			return true;
		}
		
		return false;
	}
	
	/**
	 * Validate user password. 
	 * Override this method or write your own logic here if you want to 
	 * use this identity outside of the apiAuth extension.
	 * 
	 * @return boolean True if password validates, False otherwise
	 */
	protected function isValidUserPassword($user)
	{
		// write your own password validation logic if you want to use this identity without using apiAuth Http Authentication
		throw new Exception("Password Validation logic not implemented");
	}
	
	/**
	 * Validate Password through AIdentityBehavior->isValidApiAuthPassword()
	 * 
	 * @param object $user
	 * @return boolean True if password is valid, False otherwise.
	 */
	private function _isValidApiAuthPassword($user)
	{
		//Validate with apiAuth mechanism
		$apiPasswordAttr = Yii::app()->apiAuth->apiAuthPasswordAttribute;
		$apiAuthPassword = $user->$apiPasswordAttr;
		return ($this->isValidApiAuthPassword($apiAuthPassword) === true);
	}
	
	public function getId()
	{
		return $this->_id;
	}
	
	public function getName()
	{
		return $this->_name;
	}
}
?>