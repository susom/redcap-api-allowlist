<?php
namespace Stanford\ApiWhitelist;

include_once "emLoggerTrait.php";
include_once "createProjectFromXML.php";
use \REDCap;
use \Exception;
use \Logging;


class ApiWhitelist extends \ExternalModules\AbstractExternalModule
{
    use emLoggerTrait;

    public $token;             // request token
    public $ip;                // request ip
    public $username;          // request username
    public $project_id;        // request project_id

    public $required_whitelist_fields = array('rule_id', 'username', 'project_id', 'ip_address', 'inactive');
    public $config_valid;      // configuation valid
    public $config_errors;     // array of configuration errors
    public $logging_option;    // configured log option

    public $ts_start;          // script start
    public $config_pid;        // configuration project
    public $rules;             // Rules from rules database

    public $result;            // PASS / REJECT / ERROR / SKIP
    public $rule_id;           // Match rule_id if any
    public $comment;           // Text comment
    public $log_id;            // log_id if last inserted db log

    const LOG_TABLE                      = 'redcap_log_api_whitelist';
    const REQUIRED_WHITELIST_FIELDS      = array('rule_id', 'username', 'project_id', 'ip_address', 'enabled');
    const KEY_LOGGING_OPTION             = 'whitelist-logging-option';
    const KEY_REJECTION_MESSAGE          = 'rejection-message';
    const KEY_VALID_CONFIGURATION        = 'configuration-valid';
    const KEY_VALID_CONFIGURATION_ERRORS = 'configuration-validation-errors';
    const KEY_CONFIG_PID                 = 'config-pid';
    const KEY_REJECTION_EMAIL_NOTIFY     = 'rejection-email-notification';
    const KEY_REJECTION_EMAIL_LOGS       = 'rejection-email-logs';
    const DEFAULT_REJECTION_MESSAGE      = 'This redcap API is restricted using the API whitelist external module. To request an exception for your project, please email HOMEPAGE_CONTACT_EMAIL';
    const MIN_EMAIL_RESEND_DURATION      = 15; //minutes

    public function __construct() {
        parent::__construct();
        $this->disableUserBasedSettingPermissions();
    }


    function redcap_module_system_enable($version) {
        $this->validateSetup();
        $this->emDebug("Module Enabled.  Valid?", $this->config_valid);
    }


    function redcap_module_save_configuration($project_id) {
        $this->checkFirstTimeSetup();
        $this->validateSetup();
        $this->emDebug('Config Updated.  Valid?', $this->config_valid);
    }


    /**
     * Update the display of the sidebar link depending on configuration
     * @param $project_id
     * @param $link
     * @return null
     */
    function redcap_module_link_check_display($project_id, $link) {
        if ($this->getSystemSetting(self::KEY_VALID_CONFIGURATION) == 1) {
            // Do nothing - no need to show the link
        } else {
            $link['icon'] = "exclamation";
        }
        return $link;
    }

    function checkFirstTimeSetup(){
        global $homepage_contact_email;

        if($this->getSystemSetting('first-time-setup')){
            $this->createAPIWhiteListRulesProject();
        }
        $rejectionMessage = str_replace('HOMEPAGE_CONTACT_EMAIL', $homepage_contact_email,self::DEFAULT_REJECTION_MESSAGE);
        $this->emDebug($homepage_contact_email, $rejectionMessage);
        $this->setSystemSetting('rejection-message', $rejectionMessage);
        $this->setSystemSetting('first-time-setup',0);
        $this->setSystemSetting(self::KEY_REJECTION_EMAIL_NOTIFY, 1);
        $this->setSystemSetting('whitelist-logging-option','1');
    }

    /**
     * Fetch all users from within the external modules log that have been sent a email notification within
     *  the MIN_EMAIL_RESEND_DURATION threshold
     * @return array : array of users that have already been notified
     */
    function getRecentlyNotifiedUsers() {
        $sql = "select user, max(timestamp) as ts where message = 'NOTIFICATION' group by user";
        $q = $this->queryLogs($sql);
        $usersRecentlyNotified = array();
        while($row = db_fetch_assoc($q)) {
            $user = $row['user'];
            $ts = $row['ts'];
            $diff = round((strtotime("NOW") - strtotime($ts)) / 60,2);
            if($diff < self::MIN_EMAIL_RESEND_DURATION){
                //dont notify these users, already notified
                array_push($usersRecentlyNotified, $user);
            }
        }
        $this->emDebug('Users not to Notify', $usersRecentlyNotified);
        return $usersRecentlyNotified;
    }

    /**
     * Fetch all rejection notifications since last email and group by user
     * @param null $userFilter
     * @return 2d array, each rejection row indexed by user
     */
    function getRejectionNotifications($userFilter = null) {
        $sql = "select log_id, timestamp, ip, project_id, user where message = 'REJECT'";
        $q = $this->queryLogs($sql);
        $payload = array();

        while($row = db_fetch_assoc($q)){
            $user = $row['user'];
            if(in_array($user,$userFilter)){
                //if in the recently notified users list, skip
                continue;
            } else {
                //sum all query information, notify user
                if(!array_key_exists($user, $payload)){
                    //create user in payload array
                    $this->emDebug($user, $payload);
                    $payload[$user] = array();
                }
                array_push($payload[$user], $row);
            }
        }
        return $payload;
    }

    /**
     * Determines whether or not to send a user an email notification based on MIN_EMAIL_RESEND_DURATION
     * @throws Exception
     * @return void
     */
    function checkNotifications() {
        $filter = $this->getRecentlyNotifiedUsers();
        //fetch users that have already been notified within the threshold period

        $notifications = ($this->getRejectionNotifications($filter));
        //fetch all rejection messages, grouped by user

        if(!empty($notifications)) {
            $header = $this->getSystemSetting('rejection-email-header');
            $rejectionEmailFrom = $this->getSystemSetting('rejection-email-from-address');
            if(!empty($rejectionEmailFrom)) {
                foreach($notifications as $user => $rows){
                    $logIds = array();
                    $sql = "SELECT user_email from  redcap_user_information where username = '" . db_real_escape_string($this->username) . "'";
                    $q = $this->query($sql);
                    $email = db_result($q,0);
                    //fetch the first col in the returned row

                    $table = "<table>
                                <thead><tr>
                                    <th>Time</th>
                                    <th>IP Address</th>
                                    <th>Project ID</th>
                                </tr></thead>
                              <tbody>";

                    foreach ($rows as $row) {
                        $table .= "<tr><td>{$row['timestamp']}</td><td>{$row['ip']}</td><td>{$row['project_id']}</td></tr>";
                        array_push($logIds, $row['log_id']);
                        //keep track of logID to remove from table upon fin
                    }
                    $table .= "</tbody></table>";
                    $messageBody = $header . "<hr>" . $table;
                    $emailResult = REDCap::email($email,$rejectionEmailFrom,'API whitelist rejection notice', $messageBody);
                    if($emailResult){
                        $this->logNotification($user);

                        $this->emLog('deleting log_ids', $logIds);

                        $sql = 'log_id in ('. implode(',', $logIds) . ')';
                        $this->removeLogs($sql);
                    } else {
                        $this->emError('Email not sent', $messageBody , $rejectionEmailFrom, $email);
                    }
                }
            }
        }
    }
    /**
     * Create a NOTIFICATION entry in the log table : indicates when last email was sent
     * @param $user , username
     * @return void
     */

    function logNotification($user){
        $this->log("NOTIFICATION", array(
            'user' => $user
        ));
    }

    /**
     * Create a REJECT entry in the log table
     * @throws Exception
     */
    function logRejection() {
        // Are we logging rejections for email?
        $emailRejection = $this->getSystemSetting(self::KEY_REJECTION_EMAIL_NOTIFY);
        if (empty($emailRejection)) {
            // No need to do anything
            return;
        }

        // Log the rejection
        $this->log("REJECT", array(
            'user' => $this->username,
            'ip'    => $this->ip,
            'project_id' => $this->project_id)
        );
    }


    /**
     * Determine if the module is configured properly
     * store this as two parameters in the em-settings table*
     * @param $quick_check  / true for a quick check of whether or not the config is valid
     * @return bool
     * @throws Exception
     */
    function validateSetup($quick_check = false) {
        // Quick Check
        if ($quick_check) {
            // Let's just look at the KEY_VALID_CONFIGURATION setting
            if (!$this->getSystemSetting(self::KEY_VALID_CONFIGURATION) == 1) {
                $this->emDebug('EM Configuration is not valid - skipping API filter');
                return false;
            }
        }
        // Do a thorough check
        // Verify that the module is set up correctly
        $config_errors = array();

        // Make sure rejection message is set
        if (empty($this->getSystemSetting(self::KEY_REJECTION_MESSAGE))) $config_errors[] = "Missing rejection message in module setup";

        // Make sure configuration project is set
        $this->config_pid = $this->getSystemSetting(self::KEY_CONFIG_PID);
        if (empty($this->config_pid)) {
            $config_errors[] = "Missing API Whitelist Configuration project_id setting in module setup";
        } else {
            // Verify that the project has the right fields
            $q = REDCap::getDataDictionary($this->config_pid, 'json');
            $dictionary = json_decode($q,true);
            //$this->emDebug($dictionary);

            // Look for missing required fields from the data dictionary
            $fields = array();
            foreach ($dictionary as $field) $fields[] = $field['field_name'];

            $missing = array_diff(self::REQUIRED_WHITELIST_FIELDS, $fields);
            if (!empty($missing)) $config_errors[] = "The API Whitelist project (#$this->config_pid) is missing required fields: " . implode(", ", $missing);
        }

        // Check for custom log table
        if ($this->getSystemSetting(self::KEY_LOGGING_OPTION) == 1) {
            // Make sure we have the custom log table
            if(! $this->tableExists(self::LOG_TABLE)) {
                // Table missing - try to create the table
                $this->emDebug("Trying to create custom logging table in database: " . self::LOG_TABLE);
                if (! $this->createLogTable()) {
                    $this->emDebug("Not able to create log table from script - perhaps db user doesn't have permissions");
                    $config_errors[] = "Error creating log table automatically - check the control center API Whitelist link for instructions";
                } else {
                    $this->emDebug("Custom logging table (". self::LOG_TABLE . ") created from script");

                    // Sanity check to make sure table creation worked
                    if(! $this->tableExists(self::LOG_TABLE)) {
                        $this->emError("Log table creation reported true but I'm not able to verify - this shouldn't happen");
                        $config_errors[] = "Missing required table after table creation reported success - this shouldn't happen.  Is " . self::LOG_TABLE . " there or not?";
                    } else {
                        // Table was created
                        $this->emLog("Created database table " . self::LOG_TABLE . " auto-magically");
                    }
                }
            } else {
                // Custom table exists!
                $this->emDebug("Custom log table verified");
            }
        }
        // Save setup validation to database so we don't have to do this on each api call
        $this->config_valid = empty($config_errors);
        $this->config_errors = $config_errors;

        $this->setSystemSetting(self::KEY_VALID_CONFIGURATION, $this->config_valid ? 1 : 0);
        $this->setSystemSetting(self::KEY_VALID_CONFIGURATION_ERRORS, json_encode($this->config_errors));

        if (!$this->config_valid) $this->emLog("Config Validation Errors", $this->config_errors);

        return $this->config_valid;
    }


    /**
     * This is the magic hook to capture API requests
     * Try to keep light-weight to skip non-API requests
     * Init on API requests
     * @param null $project_id
     * @throws
     * @returns void
     */
    function redcap_every_page_before_render ($project_id = null) {

        // Exit if this isn't an API request
        if (!self::isApiRequest()) return;

        $this->emDebug($this->getModuleName() . " is parsing API Request");

        $this->result = $this->screenRequest();

        switch ($this->result) {
            case "SKIP":
                // Do nothing
                break;
            case "PASS":
                //$this->emDebug("VALID REQUEST - go ahead!", $this->ip, $this->username, $this->project_id, $this->rule_id);
                $this->logRequest();
                break;
            case "ERROR":
                $this->logRequest();
                break;
            case "REJECT":
//                $this->checkRejectionEmailNotification();
                $this->logRequest();
                $this->logRejection();
                $this->checkNotifications();

                header('HTTP/1.0 403 Forbidden');
                echo $this->getSystemSetting(self::KEY_REJECTION_MESSAGE);
                $this->exitAfterHook();     // Prevent API code from executing
                break;
            default:
                $this->emError("Unexpected result from screenRequest: ", $this->result);
        }
        return;
    }


    /**
     * Function that dynamically creates and assigns a API whitelist Redcap project
     * @return boolean success
     * @throws Exception
     */
    public function createAPIWhiteListRulesProject(){
        $odmFile = $this->getModulePath() . 'assets/APIWhitelistRulesProject.xml';
        $this->emDebug("ODM FILE",$odmFile);
        $newProjectHelper = new createProjectFromXML($this);
        $superToken = $newProjectHelper->getSuperToken(USERID);

        if (empty($superToken)) {
            $this->emError("Unable to get SuperToken to create Rules project");
            return false;
        }

        // Import Project
        $newToken = $newProjectHelper->createProjectFromXMLfile($superToken, $odmFile);
        $this->emDebug('heres the new token', $newToken);
        list($username, $newProjectID) = $this->getUserProjectFromToken($newToken);
        $this->emDebug('fin', $username, $newProjectID);

        // Set the config project id
        $this->setSystemSetting('config-pid', $newProjectID);

        // Fix dynamic SQL fields
        $newProjectHelper->convertDyanicSQLField($newProjectID,'project_id','select project_id, CONCAT_WS(" ",CONCAT("[", project_id, "]"), app_title) from redcap_projects;');

        // Enable surveicSQLField($newProjectID,'username','select username, CONCAT_WS(" ", CONCAT("[", username, "]"), user_firstname, user_lastname) from redcap_user_information;');
        //        $newProjectHelper->convertDyanys and update instrument
        $sql = "update redcap_projects set surveys_enabled = 1 where project_id = $newProjectID";
        $result = $this->query($sql);
        $this->emDebug($sql, $result);

        $sql = "insert into redcap_surveys (project_id, form_name, title) values ($newProjectID, 'api_whitelist_request', 'API Whitelist Request')";
        $result = $this->query($sql);
        $this->emDebug($sql, $result);

        return true;
    }


    /**
     * Screen the API request against the whitelist
     * Set the $this->result to "PASS" / "ERROR" / "REJECT"
     * A result of "SKIP" means that we don't do anything
     * @return string RESULT: "PASS" / "ERROR" / "REJECT" / "SKIP"
     */
    function screenRequest() {
        try {
            // Start counting
            $this->ts_start = microtime(true);

            // Do a 'quick' validate check - if the config isn't valid, then abort
            if (!$this->validateSetup(true)) {
                $this->comment = "EM Configuration is not valid";
                $this->emDebug($this->comment);
                return "ERROR";
            }

            // Parse the token
            $this->token = $this->getToken();
            if (empty($this->token)) {
                // Don't do anything on an empty token
                $this->emDebug("Missing token - skip");
                $this->result = "SKIP";
                return "SKIP";
            }

            // Get the IP
            $this->ip = trim($_SERVER['REMOTE_ADDR']);

            // Get the configuration project
            $this->config_pid = $this->getSystemSetting(self::KEY_CONFIG_PID);

            // Load all of the whitelist rules
            $this->loadRules($this->config_pid);

            // Get the project and user from the token
            $this->loadProjectUsername($this->token);

            if(empty($this->rules)){
                $this->emLog('No current rules are set in current whitelist config');
            }

            foreach ($this->rules as $rule) {
                //check all records if pass, else reject
                $this->rule_id = $rule['rule_id'];

                $check_ip = $rule['whitelist_type___1'];
                $check_user = $rule['whitelist_type___2'];
                $check_pid = $rule['whitelist_type___3'];

                if (!($check_ip || $check_user || $check_pid)) {
                    // NONE ARE CHECKED - SKIP THIS CONFIG
                    $this->emError("Rule " . $rule['rule_id'] . " does not have any filters checked!");
                    continue;
                }

                $valid_ip = $check_ip ? $this->validIP($rule['ip_address']) : true;
                $valid_user = $check_user ? $this->validUser($rule['username']) : true;
                $valid_pid = $check_pid ? $this->validPid($rule['project_id']) : true;

                $this->emDebug($valid_ip, $valid_user, $valid_pid);


                if ($valid_ip && $valid_user && $valid_pid) {
                    // APPROVE API REQUEST
                    return "PASS";
                }

            } // End of rules

            //Fail request
            return "REJECT";

        } catch (Exception $e) {
            $this->emError($e->getMessage(), $e->getLine());
            $this->comment = "Screen request error: " . $e->getMessage();
            return "ERROR";
        }
    }

    /**
     * Check if current user IP is valid under any of the specified rules
     * Param: String CIDR values
     * @return bool T/F
     */
    function validIP($cidrs) {
        $this->emError('CIDRS', $cidrs);
        $ips = preg_split("/[\n,]/", $cidrs);
        $this->emError($ips);

        //check if any of the ips are valid
        foreach($ips as $ip){
            if($this->ipCIDRCheck(trim($ip)))
                return true;
        }
        return false;
    }


    /**
     * Checks equality between current user and $username
     * Param: String $username
     * @return bool T/F
     */
    function validUser($username) {
        if (empty($username)) {
            $this->emError("unable to parse username from rule ". $this->rule_id);
        }
        if (empty($this->username)) {
            $this->emError("Unable to parse username from token " . $this->token);
        }
        $this->emError($this->username, $username);

        return $this->username == $username;
    }


    /**
     * Checks equality between project and $pid
     * Param: String $pid
     * @return bool T/F
     * @throws Exception
     */
    function validPid($pid) {
        if (empty($pid)) {
            $this->emError("Unable to parse project_id from rule" . $this->rule_id);
            throw new Exception ("Unable to parse project_id from rule " . $this->rule_id);
        }
        if (empty($this->project_id)) {
            throw new Exception ("Unable to parse project_id from token " . $this->token);
        }
        return $this->project_id == $pid;
    }



    /**
     * Log the request according to system settings
     */
    function logRequest() {
        $this->logging_option = $this->getSystemSetting(self::KEY_LOGGING_OPTION);
        $content = !(empty($_REQUEST['content'])) ? db_real_escape_string($_REQUEST['content']) : "";

        switch ($this->logging_option) {
            case 0:
                // No database logging
                break;
            case 1:
                // Custom Table Logging
                $this->logToDatabase();
                break;
            case 2:
                // Log to REDCap Log Table
                $cm = json_encode(array(
                    "result"        => $this->result,
                    "content"       => $content,
                    "ip"            => $this->ip,
                    "username"      => $this->username,
                    "project_id"    => $this->project_id,
                    "rule_id"       => $this->rule_id,
                    "comment"       => $this->comment));

                //REDCap::logEvent("API Whitelist Request $this->result", $cm, "", null, null, $this->project_id);
                // To override the username I'm using the direct method call instead of REDCap::logEvent
                Logging::logEvent("", self::LOG_TABLE, "OTHER", null, $cm, "API Whitelist Request $this->result", "", $this->username, $this->project_id);
                break;
        }
        // Log to EmLogger
        $this->emLog(array(
            "result"     => $this->result,
            "content"    => $content,
            "ip"         => $this->ip,
            "username"   => $this->username,
            "project_id" => $this->project_id,
            "rule_id"    => $this->rule_id,
            "comment"    => $this->comment));
    }


    /**
     * Write to the custom logging database table
     */
    function logToDatabase() {
        $comment = empty($this->comment) ? json_encode($_REQUEST) : $this->comment;
        $sql = sprintf("INSERT INTO %s SET 
            ip_address = '%s',
            username = '%s',
            project_id = %d,
            result = '%s',
            rule_id = %d,
            comment = '%s'",
            db_real_escape_string(self::LOG_TABLE),
            db_real_escape_string($this->ip),
            db_real_escape_string($this->username),
            db_real_escape_string($this->project_id),
            db_real_escape_string($this->result),
            db_real_escape_string($this->rule_id),
            db_real_escape_string($comment)
        );
        db_query($sql);
        $this->log_id = db_insert_id();

        // Register a shutdown function to record the duration of the API call to the log database
        register_shutdown_function(array($this, "logToDatabaseUpdateDuration"));
        $this->emDebug($sql, $this->log_id);
    }


    /**
     * This function is called from a shutdown to update the database entry with the elapsed duration of the API call in the event
     * a local database is used for logging
     */
    public function logToDatabaseUpdateDuration() {
        $duration = round((microtime(true) - $this->ts_start) * 1000, 3);
        $sql = sprintf("UPDATE %s SET duration = %u where log_id = %d LIMIT 1",
            self::LOG_TABLE, $duration, $this->log_id);
        $q = db_query($sql);
        $this->emDebug($this->log_id, $this->ts_start, $sql, $q);
    }


    /**
     * Check if table exists
     * @param $table_name
     * @return bool
     */
    public function tableExists($table_name) {
        // Make sure we have the custom log table
        $q = db_query("SELECT 1 FROM " . db_real_escape_string($table_name) . " LIMIT 1");
        return !($q === FALSE);
    }

    /**
     * Create the custom log table
     * @return bool
     */
    public function createLogTable() {
        $q = db_query($this->createLogTableSql());
        return !($q === FALSE);
    }


    /**
     * Return the SQL to create the log table
     * @return string
     */
    public function createLogTableSql() {
        $sql="
            CREATE TABLE `" . self::LOG_TABLE . "` (
              `log_id` int(10) NOT NULL AUTO_INCREMENT,
              `ip_address` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
              `username` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
              `project_id` int(10) DEFAULT NULL,
              `ts` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
              `duration` float DEFAULT NULL,
              `result` enum('PASS','REJECT','ERROR') CHARACTER SET utf8 DEFAULT NULL,
              `rule_id` int(10) DEFAULT NULL,
              `comment` text CHARACTER SET utf8,
              PRIMARY KEY (`log_id`)
            ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
        ";
        return $sql;
    }


    /**
     * Load all of the configuration rules
     * @param $pid
     */
    function loadRules($pid) {
        $q = REDCap::getData($pid, 'json'); //, NULL, NULL, NULL, NULL, FALSE, FALSE, FALSE, $filter);
        $this->rules = json_decode($q,true);
    }


    /**
     * Backend endpoint for dataTable ajax
     * @param $timePartition : 'hour' || 'day', || 'month' || 'year' || 'all'
     * @return payload 2D array: [
     *  [Project-ID, Included IPs, Duration, Pass, Rejecct, Error]
     *  [] ...
     * ]
     **/
    function fetchDataTableInfo($timePartition){
        if($timePartition === "ALL"){
            $sql = "Select * from redcap_log_api_whitelist";
        } else {
            $sql = "Select * from redcap_log_api_whitelist where ts>=DATE_SUB(NOW(),INTERVAL 1 {$timePartition} )";
        }
        $this->emDebug($sql);

        $result = $this->query($sql);
        $this->emDebug($result);

        $payload = array();
        $payload['data'] = array();

        //Tables for efficiency, 1 iteration only
        $indexTable = []; //keeps track of project IDs
        $ipTable = []; //keeps track of IPs
        foreach($result as $index => $row){
            $ar = [];
            $key = array_search($row['project_id'], $indexTable); //check if project ID has been seen before
            if($key === false){ //if project id hasn't been pushed to payload
                $ipTable = [];
                array_push($indexTable, $row['project_id']); //add to indexTable, KEY = Payload index
                array_push($ipTable, $row['ip_address']);
                array_push($ar, $row['project_id'], $row['ip_address'], $row['duration']);

                if($row['result'] === 'PASS'){ //Count value for each type
                    array_push($ar, 1,0,0);
                }elseif($row['result'] === 'REJECT'){
                    array_push($ar, 0,1,0);
                }else{
                    array_push($ar, 0,0,1);
                }

                array_push($payload['data'], $ar);

            }else{ //project ID exists, increment payload information
                $payload['data'][$key][2] += $row['duration']; //column 2 will always be duration

                if($row['result'] === 'PASS'){
                    $payload['data'][$key][3]++;
                } elseif($row['result'] === 'REJECT'){
                    $payload['data'][$key][4]++;
                }else{
                    $payload['data'][$key][5]++;
                }
            }

//            $ip = array_search($row['ip_address'], $ipTable); //check if ip address has been seen before
            $ip = in_array($row['ip_address'], $ipTable);
            if(!$ip){
//                $this->emLog($row['ip_address'], $ipTable);
                if($row['ip_address'] === "")
                    $concat = ", " . "none";
                else
                    $concat = ", " . $row['ip_address'];
                $payload['data'][$key][1] .= $concat;
                array_push($ipTable, $row['ip_address']);
            }

//            $this->emLog($payload);
        }
//        $this->emLog($ipTable);

//        $this->emLog($payload);
        return $payload;
    }

//    function fetchRecentRecords(){
//        $sql = "Select * from redcap.redcap_log_api_whitelist ORDER BY ts";
//        $result = $this->query($sql);
//        $this->emLog('her4');
//        $this->loadRules($this->getSystemSetting(self::KEY_CONFIG_PID));
//        $this->emLog('pid key', $this->getSystemSetting(self::KEY_CONFIG_PID));
//        $this->emLog($this->$rules);
//        foreach ($result as $index => $row){
//            $this->emLog($row);
//        }
//        return "none";
//    }
//
//    function consolidateRecords(){
//
//    }


    /**
     * Get the token from the query
     * @return string
     * @throws Exception
     */
    function getToken() {
        $token = isset($_REQUEST['token']) ? trim($_REQUEST['token']) : "";
        // Check format of token
        if (!empty($token) && !preg_match("/^[A-Za-z0-9]+$/", $token)) {
            // Invalid token - let REDCap handle this
            $this->emDebug("Invalid token format");
            throw new Exception("Invalid token format");
        } else {
            return $token;
        }
    }


    /**
     * Given a token, determine the project and username
     * @throws Exception
     */
    public function loadProjectUsername($token) {
        list($this->username, $this->project_id) = $this->getUserProjectFromToken($token);
        $this->emDebug("Token belongs " . $this->username . " / pid " . $this->project_id);
    }


    /**
     * Fetch user information from corresponding API token
     * @param String $token
     * @return array [username, project_id]
     * @throws Exception
     */
    public function getUserProjectFromToken($token){
        $sql = "
            SELECT username, project_id 
            FROM redcap_user_rights
            WHERE api_token = '" . db_escape($token) . "'";
        $q = db_query($sql);
        if (db_num_rows($q) != 1) {
            throw new Exception ("Returned invalid number of hits in loadProjectUsername from token $token" );
        } else {
            $row = db_fetch_assoc($q);
            return array($row['username'], $row['project_id']);
        }
    }


    /**
     * Check if valid API request
     * @return bool
     */
    static function isApiRequest() {
        return defined('API') && API === true;
    }


    /**
     * Checks if the IP is valid given an IP or CIDR range
     * e.g. 192.168.123.1 = 192.168.123.1/30
     * @param $CIDR
     * @return bool
     */
    public function ipCIDRCheck ($CIDR) {
        $IP = $this->ip;
        if(strpos($CIDR, "/") === false) $CIDR .= "/32";
        list ($net, $mask) = explode ('/', $CIDR);
        $ip_net = ip2long ($net);
        $ip_mask = ~((1 << (32 - $mask)) - 1);
        $ip_ip = ip2long ($IP);

        $this->emError(($ip_ip& $ip_mask), ($ip_net & $ip_mask));

        return (($ip_ip & $ip_mask) == ($ip_net & $ip_mask));
    }


}