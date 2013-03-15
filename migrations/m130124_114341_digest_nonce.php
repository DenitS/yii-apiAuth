<?php

class m130124_114341_digest_nonce extends CDbMigration
{
	public function up()
	{
		Yii::import('ext.apiAuth.*');
		
		$this->createTable(ApiAuth::getTablePrefix().'nonce', array(
			'nonce' => 'string',
			'expires_at' => 'bigint',
			'use_count' => 'integer NOT NULL DEFAULT 0',
			'PRIMARY KEY(`nonce`)',
		));
	}

	public function down()
	{
		Yii::import('ext.apiAuth.*');
		$this->dropTable(ApiAuth::getTablePrefix().'nonce');
	}
}