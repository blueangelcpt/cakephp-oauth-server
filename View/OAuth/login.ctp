<?php
	echo $this->Session->flash('auth');
	echo $this->Form->create('Business');
	foreach ($OAuthParams as $key => $value) {
		echo $this->Form->hidden(h($key), array('value' => h($value)));
	}
?>
<h3>Please login</h3>
<?php
	echo $this->Form->input('username');
	echo $this->Form->input('password');
	echo $this->Form->end('submit');