<?php
/**
* DokuWiki Plugin authdrupal8 (Auth Component)
* Provides authentication against a Drupal8 to Drupal10 MySQL database backend
* @author     jjancel <jjancel@dialoguesenhumanite.org>
* @copyright  2024 jjancel
* @license    GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
* @version    1.1
*
* Plugin is widely based on the MySQL authentication backend by
* Matthias Jung <matzekuh@web.de>
* Andreas Gohr <andi@splitbrain.org>
* Chris Smith <chris@jalakai.co.uk>
* Matthias Grimm <matthias.grimmm@sourceforge.net>
* Jan Schumann <js@schumann-it.com>
* Alex Shepherd <n00bATNOSPAMn00bsys0p.co.uk>
* Miro Janosik <miro-d7@mypage.sk>
*/

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class auth_plugin_authdrupal8 extends DokuWiki_Auth_Plugin {
 // @var resource holds the database connection
 protected $dbcon = 0;
 protected $checkPass = "SELECT pass FROM %{drupalPrefix}users_field_data WHERE name='%{user}'";
 protected $getUserInfo = "SELECT name, mail FROM %{drupalPrefix}users_field_data WHERE name='%{user}'";
 protected $getGroups = "SELECT roles_target_id FROM %{drupalPrefix}user__roles userroles INNER JOIN %{drupalPrefix}users_field_data userdata ON userroles.entity_id = userdata.uid WHERE userdata.name = '%{user}'";
 protected $getUserCount = "SELECT COUNT(*) AS num FROM %{drupalPrefix}users_field_data WHERE status = 1";
 protected $TablesToLock = array();
 // Constructor.
 public function __construct() {
  parent::__construct(); // for compatibility
  if(!function_exists('mysqli_connect')) {
   $this->_debug("MySQL err: PHP MySQL extension not found.", -1, __LINE__, __FILE__);
   $this->success = false;
   return;
  }
  // set capabilities based upon config strings set
  if(!$this->getConf('database') || !$this->getConf('username') || !$this->getConf('host')) {
   $this->_debug("MySQL err: insufficient configuration.", -1, __LINE__, __FILE__);
   $this->success = false;
   return;
  }
  // set capabilities accordingly
  $this->cando['addUser']      = false; // can Users be created?
  $this->cando['delUser']      = false; // can Users be deleted?
  $this->cando['modLogin']     = false; // can login names be changed?
  $this->cando['modPass']      = false; // can passwords be changed?
  $this->cando['modName']      = false; // can real names be changed?
  $this->cando['modMail']      = false; // can emails be changed?
  $this->cando['modGroups']    = false; // can groups be changed?
  $this->cando['getUsers']     = false; // FIXME can a (filtered) list of users be retrieved?
  $this->cando['getUserCount'] = true; // can the number of users be retrieved?
  $this->cando['getGroups']    = false; // FIXME can a list of available groups be retrieved?
  $this->cando['external']     = false; // does the module do external auth checking?
  $this->cando['logout']       = true; // can the user logout again? (eg. not possible with HTTP auth)
  // FIXME intialize your auth system and set success to true, if successful
  $this->success = true;
 }
 // end Constructor

/**
* Checks if the given user exists and the given plaintext password
* is correct. Furtheron it might be checked wether the user is
* member of the right group
*
* @param  string $user user who would like access
* @param  string $pass user's clear text password to check
* @return bool
* 
* @author  Andreas Gohr <andi@splitbrain.org>
* @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
* @author  Matthias Jung <matzekuh@web.de>
*/
 public function checkPass($user, $pass) {
  global $conf;
  $rc = false;
  if($this->_openDB()) {
   $sql = str_replace('%{user}', $this->_escape($user), $this->checkPass);
   $sql = str_replace('%{drupalPrefix}', $this->getConf('prefix'), $sql);
   $result = $this->_queryDB($sql);
   if($result !== false && count($result) == 1) {
    $rc = $this->_hash_password($pass, $result[0]['pass']) == $result[0]['pass'];
   }
   $this->_closeDB();
  }
  return $rc;
 }

 /**
 * Hashes the password using drupals hashing algorithms
 * 
 * @param   string  $pass   user's clear text password to hash
 * @param   string  $hashedpw  user's pre-hashed password from the database
 * @return  mixed   boolean|string  hashed password string in case of success, else return boolean false
 * 
 * @author  Matthias Jung <matzekuh@web.de>
 */
 protected function _hash_password($pass, $hashedpw) {
  require_once('password.inc');
  if(!function_exists('_password_crypt')) {
   msg("Drupal installation not found. Please check your configuration.",-1,__LINE__,__FILE__);
   $this->success = false;
  }
  $hash = _password_crypt('sha512', $pass, $hashedpw);
  return $hash;
 }

 /**
 * Return user info
 *
 * @author  Andreas Gohr <andi@splitbrain.org>
 * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 *
 * @param string $user user login to get data for
 * @param bool $requireGroups  when true, group membership information should be included in the returned array;
 * when false, it maybe included, but is not required by the caller
 * @return array|bool
 */
 public function getUserData($user, $requireGroups=true) {
  if($this->_cacheExists($user, $requireGroups)) {
   return $this->cacheUserInfo[$user];
  }
  if($this->_openDB()) {
   $this->_lockTables("READ");
   $info = $this->_getUserInfo($user, $requireGroups);
   $this->_unlockTables();
   $this->_closeDB();
  } else {
   $info = false;
  }
  return $info;
 }

 /**
 * Get a user's information
 *
 * The database connection must already be established for this function to work.
 *
 * @author Christopher Smith <chris@jalakai.co.uk>
 *
 * @param  string  $user  username of the user whose information is being reterieved
 * @param  bool $requireGroups  true if group memberships should be included
 * @param  bool $useCache  true if ok to return cached data & to cache returned data
 *
 * @return mixed   false|array false if the user doesn't exist
 * array containing user information if user does exist
 */
 protected function _getUserInfo($user, $requireGroups=true, $useCache=true) {
  $info = null;
  if ($useCache && isset($this->cacheUserInfo[$user])) {
   $info = $this->cacheUserInfo[$user];
  }
  if (is_null($info)) {
   $info = $this->_retrieveUserInfo($user);
  }
  if (($requireGroups == true) && $info && !isset($info['grps'])) {
   $info['grps'] = $this->_getGroups($user);
  }
  if ($useCache) {
   $this->cacheUserInfo[$user] = $info;
  }
  return $info;
 }

 /**
 * retrieveUserInfo
 *
 * Gets the data for a specific user. The database connection
 * must already be established for this function to work.
 * Otherwise it will return 'false'.
 *
 * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 * @author Matthias Jung <matzekuh@web.de>
 *
 * @param  string $user  user's nick to get data for
 * @return false|array false on error, user info on success
 */
 protected function _retrieveUserInfo($user) {
  $sql = str_replace('%{user}', $this->_escape($user), $this->getUserInfo);
  $sql = str_replace('%{drupalPrefix}', $this->getConf('prefix'), $sql);
  $result = $this->_queryDB($sql);
  if($result !== false && count($result)) {
   $info  = $result[0];
   return $info;
  }
  return false;
 }

 /**
 * Retrieves a list of groups the user is a member off.
 *
 * The database connection must already be established
 * for this function to work. Otherwise it will return
 * false.
 *
 * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 * @author Matthias Jung <matzekuh@web.de>
 *
 * @param  string $user user whose groups should be listed
 * @return bool|array false on error, all groups on success
 */
 protected function _getGroups($user) {
  $groups = array();
  if($this->dbcon) {
   $sql = str_replace('%{user}', $this->_escape($user), $this->getGroups);
   $sql = str_replace('%{drupalPrefix}', $this->getConf('prefix'), $sql);
   $result = $this->_queryDB($sql);
   if($result !== false && count($result)) {
    foreach($result as $row) {
     $groups[] = $row['roles_target_id'];
    }
   }
   return $groups;
  }
  return false;
 }

 /**
 * Counts users.
 *
 * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 * @author  Matthias Jung <matzekuh@web.de>
 *
 * @param  array $filter  filter criteria in item/pattern pairs
 * @return int count of found users
 */
 public function getUserCount($filter=array()) {
  $rc = 0;
  if($this->_openDB()) {
   $sql = str_replace('%{drupalPrefix}', $this->getConf('prefix'), $this->getUserCount);
   $result = $this->_queryDB($sql);
   $rc = $result[0]['num'];
   $this->_closeDB();
  }
  return $rc;
 }

 /**
 * Retrieve groups [implement only where required/possible]
 *
 * Set getGroups capability when implemented
 *
 * @param   int $start
 * @param   int $limit
 * @return  array
 */
 //public function retrieveGroups($start = 0, $limit = 0) {
  // FIXME implement
 // return array();
 //}

 /**
 * Return case sensitivity of the backend
 *
 * MYSQL is case-insensitive
 *
 * @return false
 */
 public function isCaseSensitive() {
  return false;
 }

 /**
 * Check Session Cache validity [implement only where required/possible]
 *
 * DokuWiki caches user info in the user's session for the timespan defined
 * in $conf['auth_security_timeout'].
 *
 * This makes sure slow authentication backends do not slow down DokuWiki.
 * This also means that changes to the user database will not be reflected
 * on currently logged in users.
 *
 * To accommodate for this, the user manager plugin will touch a reference
 * file whenever a change is submitted. This function compares the filetime
 * of this reference file with the time stored in the session.
 *
 * This reference file mechanism does not reflect changes done directly in
 * the backend's database through other means than the user manager plugin.
 *
 * Fast backends might want to return always false, to force rechecks on
 * each page load. Others might want to use their own checking here. If
 * unsure, do not override.
 *
 * @param  string $user - The username
 * @return bool
 */
 //public function useSessionCache($user) {
 // FIXME implement
 //}

 /**
 * Opens a connection to a database and saves the handle for further
 * usage in the object. The successful call to this functions is
 * essential for most functions in this object.
 *
 * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 *
 * @return bool
 */
 protected function _openDB() {
  if(!$this->dbcon) {
   $con = @mysqli_connect($this->getConf('host'), $this->getConf('username'), $this->getConf('password'));
   if($con) {
    if((mysqli_select_db($con, $this->getConf('database')))) {
     if((preg_match('/^(\d+)\.(\d+)\.(\d+).*/', mysqli_get_server_info($con), $result)) == 1) {
      $this->dbver = $result[1];
      $this->dbrev = $result[2];
      $this->dbsub = $result[3];
     }
     $this->dbcon = $con;
     if($this->getConf('charset')) {
      mysqli_query($con, "SET CHARACTER SET 'utf8'");
     }
     return true; // connection and database successfully opened
    } else {
     mysqli_close($con);
     $this->_debug("MySQL err: No access to database {$this->getConf('database')}.", -1, __LINE__, __FILE__);
    }
   } else {
    $this->_debug(
     "MySQL err: Connection to {$this->getConf('username')}@{$this->getConf('host')} not possible.",
     -1, __LINE__, __FILE__
    );
   }
   return false; // connection failed
  }
  return true; // connection already open
 }

 /**
 * Closes a database connection.
 *
 * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 */
 protected function _closeDB() {
  if($this->dbcon) {
   mysqli_close($this->dbcon);
   $this->dbcon = 0;
  }
 }

 /**
 * Sends a SQL query to the database and transforms the result into
 * an associative array.
 *
 * This function is only able to handle queries that returns a
 * table such as SELECT.
 *
 * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 *
 * @param string $query  SQL string that contains the query
 * @return array|false with the result table
 */
 protected function _queryDB($query) {
  if($this->getConf('debug') >= 2) {
   msg('MySQL query: '.hsc($query), 0, __LINE__, __FILE__);
  }
  $resultarray = array();
  if($this->dbcon) {
   $result = @mysqli_query($this->dbcon, $query);
   if($result) {
    while($t = mysqli_fetch_assoc($result))
     $resultarray[] = $t;
    mysqli_free_result($result);
    return $resultarray;
   }
   $this->_debug('MySQL err: '.mysqli_error($this->dbcon), -1, __LINE__, __FILE__);
  }
  return false;
 }

 /**
 * Escape a string for insertion into the database
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 *
 * @param  string  $string The string to escape
 * @param  boolean $like   Escape wildcard chars as well?
 * @return string
 */
 protected function _escape($string, $like = false) {
  if($this->dbcon) {
   $string = mysqli_real_escape_string($this->dbcon, $string);
  } else {
   $string = addslashes($string);
  }
  if($like) {
   $string = addcslashes($string, '%_');
  }
  return $string;
 }

 /**
 * Wrapper around msg() but outputs only when debug is enabled
 *
 * @param string $message
 * @param int $err
 * @param int $line
 * @param string $file
 * @return void
 */
 protected function _debug($message, $err, $line, $file) {
  if(!$this->getConf('debug')) return;
  msg($message, $err, $line, $file);
 }

 /**
 * Sends a SQL query to the database
 *
 * This function is only able to handle queries that returns
 * either nothing or an id value such as INPUT, DELETE, UPDATE, etc.
 *
 * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 *
 * @param string $query  SQL string that contains the query
 * @return int|bool insert id or 0, false on error
 */
 protected function _modifyDB($query) {
  if($this->getConf('debug') >= 2) {
   msg('MySQL query: '.hsc($query), 0, __LINE__, __FILE__);
  }
  if($this->dbcon) {
   $result = @mysqli_query($this->dbcon, $query);
   if($result) {
    $rc = mysqli_insert_id($this->dbcon); //give back ID on insert
    if($rc !== false) return $rc;
   }
   $this->_debug('MySQL err: '.mysqli_error($this->dbcon), -1, __LINE__, __FILE__);
  }
  return false;
 }

 /**
 * Locked a list of tables for exclusive access so that modifications
 * to the database can't be disturbed by other threads. The list
 * could be set with $conf['plugin']['authmysql']['TablesToLock'] = array()
 *
 * If aliases for tables are used in SQL statements, also this aliases
 * must be locked. For eg. you use a table 'user' and the alias 'u' in
 * some sql queries, the array must looks like this (order is important):
 *   array("user", "user AS u");
 *
 * MySQL V3 is not able to handle transactions with COMMIT/ROLLBACK
 * so that this functionality is simulated by this function. Nevertheless
 * it is not as powerful as transactions, it is a good compromise in safty.
 *
 * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 *
 * @param string $mode  could be 'READ' or 'WRITE'
 * @return bool
 */
 protected function _lockTables($mode) {
  if($this->dbcon) {
   $ttl = $this->$TablesToLock;
   if(is_array($ttl) && !empty($ttl)) {
    if($mode == "READ" || $mode == "WRITE") {
     $sql = "LOCK TABLES ";
     $cnt = 0;
     foreach($ttl as $table) {
      if($cnt++ != 0) $sql .= ", ";
      $sql .= "$table $mode";
     }
     $this->_modifyDB($sql);
     return true;
    }
   }
  }
  return false;
 }
 /**
 * Unlock locked tables. All existing locks of this thread will be
 * abrogated.
 *
 * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
 *
 * @return bool
 */
 protected function _unlockTables() {
  if($this->dbcon) {
   $this->_modifyDB("UNLOCK TABLES");
   return true;
  }
  return false;
 }

 /**
 * Flush cached user information
 *
 * @author Christopher Smith <chris@jalakai.co.uk>
 *
 * @param  string  $user username of the user whose data is to be removed from the cache
 * if null, empty the whole cache
 */
 protected function _flushUserInfoCache($user=null) {
  if (is_null($user)) {
   $this->cacheUserInfo = array();
  } else {
   unset($this->cacheUserInfo[$user]);
  }
 }

 /**
 * Quick lookup to see if a user's information has been cached
 *
 * This test does not need a database connection or read lock
 *
 * @author Christopher Smith <chris@jalakai.co.uk>
 *
 * @param  string  $user  username to be looked up in the cache
 * @param  bool $requireGroups  true, if cached info should include group memberships
 *
 * @return bool existence of required user information in the cache
 */
 protected function _cacheExists($user, $requireGroups=true) {
  if (isset($this->cacheUserInfo[$user])) {
   if (!is_array($this->cacheUserInfo[$user])) {
    return true;  // user doesn't exist
   }
   if (!$requireGroups || isset($this->cacheUserInfo[$user]['grps'])) {
    return true;
   }
  }
  return false;
 }

}
// end class auth_plugin_authdrupal8
