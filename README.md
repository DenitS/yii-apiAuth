Yii ApiAuth Extension
=====================

ApiAuth : The first A in AAA

Authenticate a (REST) client through Http Authentication Methods like Http Digest or 
Http Basic (or implement your own authentication scheme)

Most webservers, like Apache or IIS support different types of HTTP authentication, but they 
can be difficult (if not impossible) to integrate with a custom user account source, 
especially one that is implemented in Yii. 
This extension uses only Yii, PHP and MySQL and should be easy to integrate in an 
existing Yii based Authorization scenario.

Even though this extension can be used for virtually any authentication 
scenario, it is mostly suitable for automation, for example in REST requests. 
Hence it's name apiAuth.

Yii comes with an extensive built in authorization scheme and many great 
extensions like Rights, Auth or yii-user that you can use alongside this 
extension.
@see http://www.yiiframework.com/doc/guide/1.1/en/topics.auth 

Home
----

	https://github.com/DenitS/yii-apiAuth/


Git Clone
---------

	git clone git@github.com:DenitS/yii-apiAuth.git


Requirements
------------
* Yii 1.1.12 or newer
* PHP 5.3 or newer
* A database system like MySQL (Other database systems than MySQL are currently not supported, but probably easy to implement).


Installation
------------

1. Create a folder 'apiAuth' in the extensions folder (application.extensions)
2. Copy the contents of the yii-apiAuth extension to it.
3. Create the nonce table by running:

	$ ./yiic migrate up --migrationPath=ext.apiAuth.migrations


Configuration
-------------

main.php
```php
	<?php
	return array(
		#...
		'import' => array(
			#...
			'ext.apiAuth.components.*',
			#...
		),
		#...
		'components' => array(
			#...
			'apiAuth' => array(
				'class' => 'ext.apiAuth.ApiAuth',

				// Below are the Extensions configurable attributes, specified with their default values.
				// The optional values can be left out of the configuration file (will get default values specified here)

				//'realm' => 'Restricted Area',                     //optional
				//'protocol' => 'digest',                           //optional: 'basic' or 'digest' (recommended)
				//'hash' => null,                                   //optional: empty or 'md5' (recommended. See comment on apiAuthPasswordAttribute)
				// The name of your (api) user model (i.e.: this can be your front-end User model, or a custom Api User model)
				'userClass' => 'User',                              //required
				// Let apiAuth know where to find required user model attributes
				'userIdAttribute' => 'id',                          //required
				'usernameAttribute' => 'username',                  //required, will be used for authentication, unless apiAuthUsernameAttribute is set.
				'passwordAttribute' => 'password',                  //required, will be used for authentication, unless apiAuthPasswordAttribute is set.
				//You can specify a different username for API authentication, which doesn't have to be the same as 'usernameAttribute'. When left unset, this value will be set to the same value as usernameAttribute
				'apiAuthUsernameAttribute' => 'username',           //optional, when left unset, this property will take it's value from 'usernameAttribute'
				// IMPORTANT note about 'apiAuthPasswordAttribute': 
				// apiAuth uses the value of apiAuthPasswordAttribute for password verification. 
				// It's property MUST be availble in the user model. It can be left empty or unspecified
				// in which case it will be set to the same value as 'passwordAttribute' when the extension is
				// initialized. 
				//
				// Please note that there are specific requirements as to how passwords are stored:
				// * When using 'hash' => null, store the password in plain-text.
				// * When using 'hash' => 'md5', encrypt your passwords using: 
				//
				//		$user->{apiAuthPasswordAttribute} = Yii::app()->apiAuth->encryptPassword($username, $password);
				//
				// The application's realm setting should NEVER be changed after storing digest encrypted passwords.
				// If the application's realm or the username changes, the encrypted password should be 
				// updated as well, which shall be quite difficult to do if you don't have the unencrypted password.
				'apiAuthPasswordAttribute' => 'api_password',       //optional, when left unset, this property will take it's value from 'passwordAttribute'
				'activeAttribute' => null,                          //optional, specify your user models boolean 'is active' attribute if it has one. When the user's attribute evalutes to false, authentication will fail.
				'blockedAttribute' => null,                         //optional, specify your user models boolean 'is blocked' attribute if it has one. When the user's attribute evalutes to true, authentication will fail.
				// It is strongly recommended to leave the following setting on it's default value. 
				// If you do override it, make sure you change it to a derived class of AUserIdentity.
				//'userIdentityClass' => 'AUserIdentity',           //optional
			),
			#...
		),
		#...
	);
	?>	
```

Securing Controllers
--------------------


Secure controllers and actions by extending your controller with AController (Note the A). 

Example:	

```php
	<?php
	class YourController extends AController {
```

Make sure you don't do it the other way around, for example:

```php
	<?php
	class Controller extends AController { //this would create an infinate extends loop.
```

Add the AAuthFilter to your controller's filter() method.

Full Example:

```php
	<?php 
	class YourController extends AController { //note: AController extends Controller, so this should not break your existing configuration.

		public function filters() 
		{
			//Specify the ApiAuth filter to require authentication. 
			//
			//If you need further access control (authorization) you can specifiy other filters here, 
			//just make sure you specify ApiAuth as the first filter! 
			//Authorization is slightly difficult when performed before authentication ;)
			//
			//For example, to use Yii's access control as authorization scheme, change this to:
			//
			//		return array('ApiAuth', 'accessControl'); 

			return array('ApiAuth'); 
		}

		// Uncomment this method to specify Auth Rules on specific actions, verbs or IP's.
		// When no rules are supplied or when this method is not specified, authentication will 
		// be required for all actions in this controller.
		//
		// These rules work almost in the same way as Yii's accessRules() allow or deny configuration, 
		// but note that users and roles are not available here. A user has to already be logged in for these to be available.
		// @see AAuthRule or 
		// @see http://www.yiiframework.com/doc/guide/1.1/en/topics.auth#access-control-filter
		/* 
		public function apiAuthRules() {
			return array(
				array( //allow anonymous access to the index action
					'anonymous',
					'actions' => array('index'),
				),
				array( //make sure authentication is required on all other actions
					'authenticate',
				),
			);
		}
		*/
	}
	?>
```

HTTP Digest: cleaning up Nonces
-------------------------------

Over time the nonce table will grow in size. You will have to clean it periodically,
but you will have to do this manually. I didn't want to call a DELETE FROM statement on every 
request, so i've created a static method in the ANonce model class that you can 
call whenever and wherever you like (See below). 

For example it can be called from a yii command script,
which you can in turn call via a cron job or the windows task scheduler. 

```php
ANonce::cleanExpiredNonces();
```

Contribute
----------

Contributions, remarks, improvements, etc. are always welcome. 

Please submit contributions to the `dev` branch or [submit an issue](https://github.com/DenitS/yii-apiAuth/issues/new) in the github repository

