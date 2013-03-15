<?php

/**
 * ANonce
 *
 * The followings are the available columns in table 'nonce':
 * @property string $nonce
 * @property string $expires_at
 * @property integer $use_count
 * 
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 * 
 */
class ANonce extends CActiveRecord
{
	public $expires_in = 3600; //in seconds (1hr)
	public static $expiredNonceRetentionTime = 600; //10 m.
	
	/**
	 * Returns the static model of the specified AR class.
	 * @param string $className active record class name.
	 * @return Nonce the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}

	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return ApiAuth::getTablePrefix().'nonce';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			array('nonce', 'length', 'max'=>255),
		);
	}

	/**
	 * @return array relational rules.
	 */
	public function relations()
	{
		return array();
	}

	/**
	 * @return array customized attribute labels (name=>label)
	 */
	public function attributeLabels()
	{
		return array(
			'nonce' => 'Nonce',
			'expires_at' => 'Expires At',
			'use_count' => 'Use Count',
		);
	}
	
	public function afterConstruct() {
		parent::afterConstruct();
		$this->expires_at = time() + $this->expires_in;
	}
	
	public function afterFind()
	{
		$this->use_count = (int)$this->use_count;
	}
	
	public function markAsUsed()
	{
		if($this->isNewRecord)
			throw new Exception("Cannot mark Nonce as used as it doesn't exist in DB yet.");
			
		$this->saveAttributes(array('use_count' => ($this->use_count + 1)));
	}
	
	public function isUsed($counter)
	{
		if(!$counter || $counter < 0)
			throw new Exception("Invalid parameter");
		return ($counter <= $this->use_count);
	}
	
	public function isExpired()
	{
		if(!isset($this->expires_at))
			return false;
		return (time() > $this->expires_at);
	}
	
	public static function cleanExpiredNonces()
	{
		$maxExpTime = time() + self::$expiredNonceRetentionTime;
		self::model()->deleteAll(array(
			'condition' => 'expires_at < :maxExpTime',
			'params' => array(
				':exp_date' => $maxExpTime
			),
		));
	}
}