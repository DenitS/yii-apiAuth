<?php
/**
 * AHttpAuthenticatorDigest
 * 
 * @see RFC2617 http://www.ietf.org/rfc/rfc2617.txt
 *
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 * 
 */
class AHttpAuthenticatorDigest extends AHttpAuthenticator implements IAHttpAuthenticator {
	
	/**
	 * Quality of Protection methods supported by the server. 
	 * Do not change this value unless you have to.
	 * 
	 * Allowed values: 
	 *  - 'auth' (recommended for compatibility reasons, even though auth,auth-int is supported as well)
	 *  - 'auth,auth-int'
	 *  - 'auth-int' 
	 * 
	 * For python clients that use urrllib2 and have problems connecting: set this value to 'auth' only.
	 * (@see bugs.python.org issues #1667860 and #9714)
	 * 
	 * @var string
	 */
	public $qop = "auth"; 
	
	/**
	 * @var AHttpDigest
	 */
	protected $receivedDigest;
	
	/**
	 * @var Nonce
	 */
	protected $nonce;
	
	/*
	 * This value is only set to true if $this->testChallengeResponse is called and returns true. 
	 * If it's not called, the useridentity does not implement the challenge response mechanim
	 * and the user cannot authenticate using the Http Digest Authenticator
	 * 
	 * @var bool 
	 */
	private $_challengeResponseValidated = false;
	
	public function beforeAuthentication() {
				
		if(!parent::beforeAuthentication())
			return false;
		
		//parse digest 
		if(!isset($_SERVER['PHP_AUTH_DIGEST']))
			return false;
		
		try {
			$this->receivedDigest = new AHttpDigest($_SERVER['PHP_AUTH_DIGEST']);
		} catch(Exception $e) {
			throw new CHttpException(400, $e->getMessage());
		}
		
		//check if digest succesfully parsed and available for further processing
		if(!$this->receivedDigest || !$this->receivedDigest->response)
			return false;
		
		//get nonce from digest
		$this->nonce = $this->getReceivedNonce();
		if(!$this->nonce)
			return false;
		
		//check nonce
		if($this->nonce->isExpired()) {
			//tell client his authentantion data is stale 
			//so he can automatically reauthenticate, without asking the user 
			//for new credentials
			$this->sendDigestResponseHeaders(true);
			Yii::app()->end(); //halt execution
		}
		
		//Load an identity with only the username.
		//The user password is not sent unencrypted over the wire in 
		//HTTP Digest Authentication, so it's not available for us to use here).
		$this->identity = $this->loadIdentity($this->receivedDigest->username);		
		
		//Link challenge response callback to identity instance for digest authentication
		//NOTE: this property will be available because loadIdentity() applies AIdentityBehaviorDigest to the identity instance.
		$this->identity->challengeResponseCallback = array($this, 'testChallengeResponse');
		
		return true;
	}
	
	public function authenticate() 
	{
		$authenticated = $this->identity->authenticate();
//		if(!$authenticated && $this->identity->errorCode == AUserIdentity::ERROR_USER_BLOCKED)
//			parent::unauthenticated("Forbidden: Account has been suspended");
		
		return ($authenticated && $this->_challengeResponseValidated);
	}
	
	public function afterAuthentication() 
	{
		//auth succesfull. Make sure nonce cannot be re-used to prevent replay attacks.
		$this->nonce->markAsUsed(); 
		
		parent::afterAuthentication();
	}
	
	/**
	 * This function will be called when the user cannot be authenticated
	 */
	public function unauthenticated($message = 'Unauthorized')
	{
		$this->sendDigestResponseHeaders();
		
		//No digest received. Step 1 in authentication handshake.
		if(!isset($this->receivedDigest)) {
			//quit immediately with HTTP 401 (slight speedup, compared to Yii::app()->end() which allows for finalization of CWebApplication, logging, etc.)
			header("HTTP/1.0 401 " . $message);
			exit; 
		}
		
		//Digest received. Step 2 in authentication handshake. 
		//Apparently still unauthenticated. client must be specifying wrong header (i.e. wrong credentials, invalid header, etc.)
		throw new CHttpException(401, $message);
	}
	
	/* ------------------- CHALLENGE RESPONSE CALLBACK METHOD ------------------- */
	
	/**
	 *
	 * @param string $password
	 * @return bool true if test succesfull, false otherwise
	 */
	public function testChallengeResponse($password)
	{
		$challenge = $this->createDigestChallenge($password);
		$response = $this->receivedDigest->response;
		
		return $this->_challengeResponseValidated = ($challenge == $response);
	}
	
	/* ------------------- HELPER METHODS ------------------- */
	
	/**
	 * Validates receivedDigest's nonce and marks it as used if valid.
	 * 
	 * @return boolean 
	 */
	private function getReceivedNonce()
	{
		//check db for use and valid (issued by us) nonce.
		$nonce = ANonce::model()->findByPk($this->receivedDigest->nonce);
		
		//nonce not in db. Either it's not issued by the server, or long since expired and already removed from db.
		if(!$nonce) {
			return false;
		}
		
		//invalid (don't allow nonce re-use)
		if(hexdec($this->receivedDigest->nc) <= $nonce->use_count) {
			return false;
		}
		
		//good
		return $nonce;
	}
	
	/**
	 * Creates a new Nonce and saves it to DB
	 * 
	 * @return \Nonce
	 * @throws CHttpException if nonce cannot be saved.
	 */
	private function createNonce()
	{
		$nonce = new ANonce('create');
		$nonce->nonce = uniqid(Yii::app()->apiAuth->realm.".");
		
		if(!$nonce->save())
			throw new CHttpException(500, "Internal Server Error");
		
		return $nonce;
	}
	
	private function sendDigestResponseHeaders($stale=false)
	{
		$nonce = $this->createNonce();
		$staleHeaderStr = ($stale===true)? ",stale=TRUE" : "";		
		header('WWW-Authenticate: Digest realm="' . Yii::app()->apiAuth->realm . '",qop="'.$this->qop.'",nonce="' . $nonce->nonce . '",opaque="' . md5(Yii::app()->apiAuth->realm) . '"'.$staleHeaderStr);
	}
	
	/**
	 * Create A Digest challenge for use by the testChallengeResponse function
	 * 
	 * @param string $password
	 * @return string HMAC
	 */
	private function createDigestChallenge($password)
	{	
		//init vars
		$HA1 = "";
		$HA2 = "";
		$response = "";
		
		//calculate $A1
		if(empty(Yii::app()->apiAuth->hash)) //assume plaintext $password in db
			$HA1 =  Yii::app()->apiAuth->encryptDigestHA1(Yii::app()->apiAuth->realm, $this->identity->username, $password);
		else //$password should already be encrypted
			$HA1 = $password;
		
		//calculate $A2
		switch($this->receivedDigest->qop) 
		{
			case AHttpDigest::QOP_AUTH_INT:
				$HA2 = md5($_SERVER['REQUEST_METHOD'] . ':' . $this->receivedDigest->uri) . ":" . md5(Yii::app()->request->rawBody);
				break;
			default:
				$HA2 = md5($_SERVER['REQUEST_METHOD'] . ':' . $this->receivedDigest->uri);
				break;
		}
		
		//calculate $response with $A1, digest params and $A2
		switch($this->receivedDigest->qop)
		{
			case AHttpDigest::QOP_AUTH;
			case AHttpDigest::QOP_AUTH_INT;
				$response = md5($HA1 . ':' . $this->receivedDigest->nonce . ':' . $this->receivedDigest->nc . ':' . $this->receivedDigest->cnonce . ':' . $this->receivedDigest->qop . ':' . $HA2);
				break;
			default:
				$response = md5($HA1 . ':' . $this->receivedDigest->nonce . ':' . $HA2);
				break;
		}
		
		return $response;
	}
}

/**
 * HttpDigest
 * 
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 */
class AHttpDigest
{
	public $nonce;
	public $cnonce; //client nonce
	public $nc; //nonce count.
	public $opaque;
	public $qop;
	public $username;
	public $uri;
	public $response;
	
	const QOP_AUTH = "auth";
	const QOP_AUTH_INT = "aut-int";
	
	public function __construct($digestHeader=null)
	{
		if($digestHeader !== null) {
			$this->applyDigestHeader($digestHeader);
		}
	}
	
	/**
	 * Parse a header string and apply it to the instance of this object.
	 * 
	 * @param mixed $digestHeader String or Array
	 */
	private function applyDigestHeader($digestHeader)
	{
		if(empty($digestHeader))
			return;
		
		if(is_string($digestHeader))
			$digestHeader = self::parseDigestStr($digestHeader);
		
		foreach($digestHeader as $name => $value) {
			if(property_exists($this, $name))
				$this->$name = $value;
		}
	}
	
	/**
	 * Function to parse the http auth header
	 * 
	 * @param string $digestHeaderStr
	 * @return array containing the parts in key=>value array structure
	 * @throws Exception when header is invalid (parts are missing)
	 */
	public static function parseDigestStr($digestHeaderStr) {

		// protect against missing data
		$requiredParts = array(
			self::QOP_AUTH => array(
				'nonce',
				'nc',
				'cnonce',
				'qop',
				'username',
				'uri',
				'response',
			),
			self::QOP_AUTH_INT => array(
				'nonce',
				'nc',
				'cnonce',
				'qop',
				'username',
				'uri',
				'response',
			),
			'' => array(
				'nonce',
				'username',
				'uri',
				'response',
			),
		);
		$data = array();
	
		$matches = array();
		preg_match_all('/(\w+)=([\'"])?([^\'",]+)/i', $digestHeaderStr, $matches, PREG_SET_ORDER);
		
		foreach ($matches as $m) {
			$data[$m[1]] = $m[3] ? $m[3] : $m[4];
		}
		
		//check required parts.
		$qop = (isset($data['qop']))? $data['qop'] : '';
		
		if(!isset($requiredParts[$qop])) 
			throw new Exception('Invalid HTTP Digest Authentication Header. Invalid QOP: ' . $qop);
			
		
		$requiredParts = array_flip($requiredParts[$qop]);
		foreach($data as $part => $value) {
			unset($requiredParts[$part]);
		}

		//bugfix for missing username (occurs when user hits OK without entering data in some clients)
		if(isset($requiredParts['username'])) {
			$data['username'] = '';	
			unset($requiredParts['username']);
		}

		if(count($requiredParts) > 0) {
			throw new Exception('Invalid HTTP Digest Authentication Header. Missing parts: ' . print_r(array_keys($requiredParts), true));
		}
		
		return $data;
	}
}
