<?php

App::uses('OAuthAppModel', 'OAuth.Model');

/**
 * RefreshToken Model
 *
 * @property Client $Client
 * @property User $User
 */
class RefreshToken extends OAuthAppModel {

/**
 * Primary key field
 *
 * @var string
 */
	public $primaryKey = 'refresh_token';

/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'refresh_token';

/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'refresh_token' => array(
			'notBlank' => array(
				'rule' => array('notBlank'),
			),
			'isUnique' => array(
				'rule' => array('isUnique'),
			)
		),
		'client_id' => array(
			'notBlank' => array(
				'rule' => array('notBlank'),
			),
		),
		'user_id' => array(
			'notBlank' => array(
				'rule' => array('notBlank'),
			),
		),
		'expires' => array(
			'numeric' => array(
				'rule' => array('numeric'),
			),
		),
	);

	public $actsAs = array(
		'OAuth.HashedField' => array(
			'fields' => 'refresh_token',
		),
	);

/**
 * belongsTo associations
 *
 * @var array
 */
	public $belongsTo = array(
		'Client' => array(
			'className' => 'OAuth.Client',
			'foreignKey' => 'client_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		)
	);

}
