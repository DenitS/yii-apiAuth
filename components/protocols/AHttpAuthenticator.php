<?php
/**
 * HttpAuthenticator
 * 
 * This class forms the base for apiAuth's authenticator classes. This class shouldn't be modified. 
 * If you want to implement your own authentication method, you should override this 
 * class in ext.apiAuth.components.authenticators and implement it's authentication logic in 
 * the authenticate() and beforeAuthentication() methods.
 *
 * @property CUserIdentity $identity
 * 
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 * 
 */
abstract class AHttpAuthenticator extends CComponent implements IAHttpAuthenticator
{
	protected $_identity;
		
	/**
	 * Logic to perform when user cannot be authenticated
	 * 
	 * @param string $message
	 * @throws CHttpException 
	 */
	public function unauthenticated($message=null) 
	{	
		if(!$message)
			$message = "Forbidden";
		throw new CHttpException(403, $message);
	}
	
	/**
	 * Perform Authentication Pre-processing Logic
	 * Derived classes can override this method. Returning false will prevent a user
	 * from authenticating.
	 * 
	 * @return boolean NOTE: When this method returns false, user will not be authenticated
	 */
	public function beforeAuthentication() {
		return true;
	}
	
	/**
	 * Perform Authentication Post-processing Logic 
	 * Derived classes can override this method.
	 */
	public function afterAuthentication(){ }
	
	
	/**
	 * Process the authentication request and login the UserIdentity to Yii's user component.
	 * Do not modify this method. If you want to customize the authenticators behavior
	 * override the beforeAuthentication and authenticate methods in a derived authenticator class.
	 * 
	 * @return boolean True if authentication successfull, false otherwise.
	 */
	final public function login()
	{	
		//preprocessing
		ApiAuth::beginProfile("ext.apiAuth.AHttpAuthenticator.beforeAuthentication()", "ext.apiAuth.AHttpAuthenticator");
		if($this->beforeAuthentication()) 
		{
			ApiAuth::endProfile("ext.apiAuth.AHttpAuthenticator.beforeAuthentication()", "ext.apiAuth.AHttpAuthenticator");
			
			//auth
			ApiAuth::beginProfile("ext.apiAuth.AHttpAuthenticator.authenticate()", "ext.apiAuth.AHttpAuthenticator");
			if($this->authenticate()) 
			{
				ApiAuth::endProfile("ext.apiAuth.AHttpAuthenticator.authenticate()", "ext.apiAuth.AHttpAuthenticator");
				
				//check if authentication behavior was performed on this user identity
				//if not, throw an exception. This module was misconfigured by the programmer.
				if(!$this->isPasswordValidationPerformed()) {
					//Message for the programmer that get's this error:
					//This was your own fault for either not reading the README.md file when configuring the module
					//or for making an adjustment that broke it. Please try to fix it yourself and 
					//please don't ask the author of this extension for help. ;)
					//HINT: The problem exists in the current UserIdentity->authorize() method
					$msg = (YII_DEBUG)? ". Description: UserIdentity does not implement valid API password validation logic" : "";
					throw new Exception("Internal Server Error" . $msg);
				}
				
				//post processing
				ApiAuth::beginProfile("ext.apiAuth.AHttpAuthenticator.afterAuthentication()", "ext.apiAuth.AHttpAuthenticator");
				$this->afterAuthentication();
				ApiAuth::endProfile("ext.apiAuth.AHttpAuthenticator.afterAuthentication()", "ext.apiAuth.AHttpAuthenticator");
				
				//log in
				Yii::app()->user->login($this->identity);
				
				return true;
			} 
			else 
			{
				ApiAuth::endProfile("ext.apiAuth.AHttpAuthenticator.authenticate()", "ext.apiAuth.AHttpAuthenticator");
				//auth failed
				return false;
			}
		}
		ApiAuth::endProfile("ext.apiAuth.AHttpAuthenticator.beforeAuthentication()", "ext.apiAuth.AHttpAuthenticator");
		//preprocessing failed
		return false;
	}
	
	/**
	 * @return CUserIdentity NOTE: Actual type will be instance of 
	 */
	public function getIdentity() {
		return $this->_identity;
	}
	
	/**
	 * @param CUserIdentity $value 
	 */
	public function setIdentity($value) {
		$this->_identity = $value;
	}
	
	/**
	 * Checks if behavior was applied to identity and password validation has been performed 
	 * correctly through the behavior method
	 * 
	 * This method will return false if this extension has been customized to use 
	 * a different User Identity class, that doesn't (correctly / or at all) implement 
	 * apiAuth validation methods (i.e.: validation through ApiAuth Identity Behavior classes)
	 * 
	 * @return boolean 
	 */
	private function isPasswordValidationPerformed()
	{
		//Is behavior at all applied?
		$behaviorName = AIdentityBehavior::behaviorName;
		if(!isset($this->identity->$behaviorName) || !($this->identity->$behaviorName instanceof AIdentityBehavior))
			return false;
		
		//test if password validation was performed (can only be true if it has)
		return ($this->identity->passwordValidationPerformed === true);
	}
	
	/**
	 * Loads a UserIdentity of type Yii::app()->apiAuth->userIdentityClass and 
	 * applies AIdentityBehavior to it, then returns the object.
	 * 
	 * @param type $username
	 * @param string $password Optional (empty is allowed for digest authentication)
	 * @return CUserIdentity NOTE: Actual type will be instance of Yii::app()->apiAuth->userIdentityClass
	 */
	protected function loadIdentity($username, $password=null)
	{
		//load identity
		$identityClass = Yii::app()->apiAuth->userIdentityClass;
		$identity = new $identityClass($username, $password);
		//apply behavior
		AIdentityBehavior::apply($identity);
		return $identity;
	}
}