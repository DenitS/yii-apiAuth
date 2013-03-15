<?php
require_once(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."ApiAuth.php");
/**
 * AAuthFilter
 * 
 * This class extends the CAccessControlFilter but we need it because 
 * in the yii version the $_rules property is private making it impossible to extend it.
 *
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 * 
 */
class AAuthFilter extends CFilter {
	
	private $_rules;
	
	public $message;
	
	public function getRules()
	{
		return $this->_rules;
	}
	
	/**
	 * @param array $rules list of access rules.
	 */
	public function setRules($rules)
	{
		foreach($rules as $rule)
		{
			if(is_array($rule) && isset($rule[0]))
			{
				$r=new AAuthRule;
				$r->authenticate=$rule[0]==='authenticate';
				foreach(array_slice($rule,1) as $name=>$value)
				{
					if($name==='expression' || $name==='message' || $name==='deniedCallback')
						$r->$name=$value;
					else
						$r->$name=array_map('strtolower',$value);
				}
				$this->_rules[]=$r;
			}
		}
	}
	
	public function preFilter($filterChain)
	{	
		$app=Yii::app();
		$request=$app->getRequest();
		$verb=$request->getRequestType();
		$ip=$request->getUserHostAddress();
		
		//always run authenticator if no rules specified
		$rules = $this->getRules();
		if(empty($rules)) {
			
			ApiAuth::beginProfile("ext.apiAuth.AAuthFilter.getAuthenticator()", "ext.apiAuth.AAuthFilter");
			$authenticator = $this->getAuthenticator();
			ApiAuth::endProfile("ext.apiAuth.AAuthFilter.getAuthenticator()", "ext.apiAuth.AAuthFilter");
			
			ApiAuth::beginProfile("ext.apiAuth.AAuthFilter.login()", "ext.apiAuth.AAuthFilter");
			if($authenticator->login()) {
				ApiAuth::endProfile("ext.apiAuth.AAuthFilter.login()", "ext.apiAuth.AAuthFilter");
				return true;
			}
			ApiAuth::endProfile("ext.apiAuth.AAuthFilter.login()", "ext.apiAuth.AAuthFilter");
			
			//unauthenticated
			$authenticator->unauthenticated();
		}
		
		//Run authenticator only when rules are specified and one of the rules require it
		foreach($rules as $rule)
		{
			/* @var $rule AAuthRule */
			//auth required?
			if(($required = $rule->authenticationRequired($filterChain->controller, $filterChain->action, $ip, $verb)) > 0)
			{ 
				$authenticator = $this->getAuthenticator();
				if($authenticator->login()) {
					return true; //authentication succesfull, don't process any other rules in this filter.
				} else {
					//authentication failed
					if(isset($rule->deniedCallback))
						call_user_func($rule->deniedCallback, $rule);
					else
						$authenticator->unauthenticated($this->resolveErrorMessage($rule));
					
					return false;
				}
			} else if($required < 0) {
				return true; //anonymous access allowed, don't process any other rules in this filter.
			}
		}
		
		return true;
	}
	
	/**
	 * Resolves the error message to be displayed.
	 * This method will check {@link message} and {@link CAccessRule::message} to see
	 * what error message should be displayed.
	 * @param CAccessRule $rule the access rule
	 * @return string the error message
	 * @since 1.1.1
	 */
	protected function resolveErrorMessage($rule)
	{
		if($rule->message!==null)
			return $rule->message;
		else if($this->message!==null)
			return $this->message;
		else
			return Yii::t('yii','Access Denied');
	}
	
	public function getAuthenticator()
	{
		$authenticatorClass = "AHttpAuthenticator".ucfirst(Yii::app()->apiAuth->protocol);
		Yii::trace('Loading "' . $authenticatorClass . '" apiAuth authenticator component', "ext.apiAuth.AAauthFilter");
		return new $authenticatorClass;
	}
}

/**
 * AAuthRule
 * 
 * This class is based heavily on Yii's CAccessRule class, but stripped of all references 
 * to users and roles, because these aren't available until after authentication.
 * 
 * Key Differences:
 *  - $rule->user is not available and does not apply
 *  - $rule->role is not available and does not apply
 *  - isUserAllowed() is replaced with authenticationRequired()
 *  - $rule->allow is replaced with $rule->authenticate, deny = anonymous
 *  - deniedCallback doesn't apply
 * 
 * @see http://www.yiiframework.com/doc/api/1.1/CAccessRule
 * @license http://www.yiiframework.com/license/
 */
class AAuthRule extends CComponent {
	
	/**
	 * @var boolean whether this is an 'authenticate' rule or 'anonymous' rule.
	 */
	public $authenticate;
	/**
	 * @var array list of action IDs that this rule applies to. The comparison is case-insensitive.
	 * If no actions are specified, rule applies to all actions.
	 */
	public $actions;
	/**
	 * @var array list of controler IDs that this rule applies to. The comparison is case-insensitive.
	 */
	public $controllers;
	/**
	 * @var array IP patterns.
	 */
	public $ips;
	/**
	 * @var array list of request types (e.g. GET, POST) that this rule applies to.
	 */
	public $verbs;
	/**
	 * @var string a PHP expression whose value indicates whether this rule should be applied.
	 * In this expression, you can use <code>$user</code> which refers to <code>Yii::app()->user</code>.
	 * The expression can also be a valid PHP callback,
	 * including class method name (array(ClassName/Object, MethodName)),
	 * or anonymous function (PHP 5.3.0+). The function/method signature should be as follows:
	 * <pre>
	 * function foo($user, $rule) { ... }
	 * </pre>
	 * where $user is the current application user object and $rule is this access rule.
	 */
	public $expression;
	/**
	 * @var string the error message to be displayed when unauthenticated is denied by this rule.
	 * If not set, a default error message will be displayed.
	 * @since 1.1.1
	 */
	public $message;
	
	/**
	 * Checks whether authentication is required or anonymous access is allowed.
	 * @param CController $controller the controller currently being executed
	 * @param CAction $action the action to be performed
	 * @param string $ip the request IP address
	 * @param string $verb the request verb (GET, POST, etc.)
	 * @return integer 1 if the authentication is required, -1 if anonymous action is allowed, 0 if the rule does not apply
	 */
	public function authenticationRequired($controller,$action,$ip,$verb)
	{
		if($this->isActionMatched($action)
			&& $this->isIpMatched($ip)
			&& $this->isVerbMatched($verb)
			&& $this->isControllerMatched($controller)
			&& $this->isExpressionMatched())
			return $this->authenticate? 1 : -1;
		else
			return 0;
	}

	/**
	 * @param CAction $action the action
	 * @return boolean whether the rule applies to the action
	 */
	protected function isActionMatched($action)
	{
		return empty($this->actions) || in_array(strtolower($action->getId()),$this->actions);
	}

	/**
	 * @param CAction $controller the action
	 * @return boolean whether the rule applies to the action
	 */
	protected function isControllerMatched($controller)
	{
		return empty($this->controllers) || in_array(strtolower($controller->getId()),$this->controllers);
	}

	/**
	 * @param string $ip the IP address
	 * @return boolean whether the rule applies to the IP address
	 */
	protected function isIpMatched($ip)
	{
		if(empty($this->ips))
			return true;
		foreach($this->ips as $rule)
		{
			if($rule==='*' || $rule===$ip || (($pos=strpos($rule,'*'))!==false && !strncmp($ip,$rule,$pos)))
				return true;
		}
		return false;
	}

	/**
	 * @param string $verb the request method
	 * @return boolean whether the rule applies to the request
	 */
	protected function isVerbMatched($verb)
	{
		return empty($this->verbs) || in_array(strtolower($verb),$this->verbs);
	}

	/**
	 * @return boolean the expression value. True if the expression is not specified.
	 */
	protected function isExpressionMatched()
	{
		if($this->expression===null)
			return true;
		else
			return $this->evaluateExpression($this->expression);
	}
}