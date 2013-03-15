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