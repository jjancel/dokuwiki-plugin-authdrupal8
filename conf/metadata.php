<?php
/**
 * Options for the authdrupal8 plugin
 *
 * @author jjancel <jjancel@dialoguesenhumanite.org>
 */

$meta['database']	= array('string','_caution' => 'danger');
$meta['username']	= array('string','_caution' => 'danger');
$meta['password']	= array('password','_caution' => 'danger');
$meta['prefix']		= array('string','_caution' => 'danger');
$meta['host']			= array('string','_caution' => 'danger');
$meta['debug']		= array('multichoice','_choices' => array(0,1,2),'_caution' => 'security');
