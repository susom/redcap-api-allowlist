<?php
namespace Stanford\ApiWhitelist;

include_once "emLoggerTrait.php";

use \REDCap;
use \Exception;
use \Logging;

class ApiWhitelist extends \ExternalModules\AbstractExternalModule
{
    use emLoggerTrait;

    private $token;             // request token
    private $ip;                // request ip
    private $username;          // request username
    private $project_id;        // request project_id

    private $required_whitelist_fields = array('rule_id', 'username', 'project_id', 'ip_address', 'inactive');
    public $config_valid;       // configuation valid
    public $config_errors;     // array of configuration errors
    private $logging_option;    // configured log option

    private $ts_start;          // script start
    public $config_pid;        // configuration project
    private $rules;             // Rules from rules database

    private $result;            // PASS / REJECT / ERROR / SKIP
    private $rule_id;           // Match rule_id if any
    private $comment;           // Text comment
    private $log_id;            // log_id if last inserted db log

    const LOG_TABLE                      = 'redcap_log_api_whitelist';
    const REQUIRED_WHITELIST_FIELDS      = array('rule_id', 'username', 'project_id', 'ip_address', 'inactive');
    const KEY_LOGGING_OPTION             = 'whitelist-logging-option';
    const KEY_REJECTION_MESSAGE          = 'rejection-message';
    const KEY_VALID_CONFIGURATION        = 'configuration-valid';
    const KEY_VALID_CONFIGURATION_ERRORS = 'configuration-validation-errors';
    const KEY_CONFIG_PID                 = 'config-pid';


    public function __construct() {
        parent::__construct();
        $this->disableUserBasedSettingPermissions();
    }


    function redcap_module_system_enable($version) {
        $this->validateSetup();
        $this->emDebug("Module Enabled.  Valid?", $this->config_valid);
    }


    function redcap_module_save_configuration($project_id) {
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
                $this->logRequest();

                //$this->emDebug("INVALID REQUEST", $this->ip, $this->username, $this->project_id, $this->rule_id);
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


            // Check for IP match
            if ($this->validIpAddress()) {
                // Request matches IP rule
                return "PASS";
            }

            // Get the project and user from the token
            $this->loadProjectUsername($this->token);

            // Verify that username/project are valid
            if ($this->validProjectUsername()) {
                return "PASS";
            }

            // Fail request
            return "REJECT";

        } catch (Exception $e) {
            $this->emError($e->getMessage(), $e->getLine());
            $this->comment = "Screen request error: " . $e->getMessage();
            return "ERROR";
        }
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
    function logToDatabaseUpdateDuration() {
        $duration = round((microtime(true) - $this->ts_start) * 1000, 3);
        $sql = sprintf("UPDATE %s SET duration = %u where log_id = %d LIMIT 1",
            self::LOG_TABLE, $duration, $this->log_id);
        $q = db_query($sql);
        $this->emDebug($this->log_id, $this->ts_start, $sql, $q);
    }


    /**
     * Look through all rules to find a matching username/project_id setting
     * @return bool
     */
    public function validProjectUsername() {
        // Skip if we don't have a valid username and project_id
        if (empty($this->username) OR empty($this->project_id)) {
            $this->emDebug("Missing valid username or project", $_POST);
            return false;
        }

        // Go through each rule and check for a match
        foreach ($this->rules as $rule) {
            if (empty($rule['username']) AND empty($rule['project_id'])) continue;
            if ($rule['inactive___1'] == '1') continue;


            if ($rule['username'] === $this->username AND $rule['project_id'] == $this->project_id) {
                // Allow based on username and project_id match
                $this->rule_id = $rule['rule_id'];
                return true;
            }

            if ($rule['project_id'] == $this->project_id AND empty($rule['username'])) {
                // Allow based on project_id
                $this->rule_id = $rule['rule_id'];
                return true;
            }

            if ($rule['username'] === $this->username AND empty($rule['project_id'])) {
                // Allow based on username role
                $this->rule_id = $rule['rule_id'];
                return true;
            }
        }
        return false;
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
     * Look through all rules to find a matching IP
     * @return bool
     */
    public function validIpAddress() {
        foreach ($this->rules as $rule) {
            if ($rule['inactive___1'] == '1') continue;

            if (!empty($rule['ip_address'])) {
                if (self::ipCIDRCheck($rule['ip_address'])) {
                    $this->rule_id = $rule['rule_id'];
                    return true;
                }
            }
        }
        return false;
    }


    /**
     * Load all of the configuration rules
     * @param $pid
     */
    function loadRules($pid) {
        $q = REDCap::getData($pid, 'json');
        $this->rules = json_decode($q,true);
    }


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
        $sql = "
            SELECT username, project_id 
            FROM redcap_user_rights
            WHERE api_token = '" . db_escape($token) . "'";
        $q = db_query($sql);
        if (db_num_rows($q) != 1) {
            throw new Exception ("Returned invalid number of hits in loadProjectUsername from token $token" );
        } else {
            $row = db_fetch_assoc($q);
            $this->username = $row['username'];
            $this->project_id = $row['project_id'];
        }
        $this->emDebug("Token belongs " . $this->username . " / pid " . $this->project_id);
    }











    /**
     * Is this an API request
     * @return bool
     */
    static function isApiRequest() {
        return defined('API') && API === true;
    }


    //
    /**
     * Checks if the IP is valid given an IP or CIDR range
     * e.g. 192.168.123.1 = 192.168.123.1/30
     * @param $CIDR
     * @return bool
     */
    public function ipCIDRCheck ($CIDR) {
        $ip = $this->ip;
        if(strpos($CIDR, "/") === false) $CIDR .= "/32";
        list ($net, $mask) = explode("/", $CIDR);
        $ip_net  = ip2long($net);
        $ip_mask = ~((1 << (32 - $mask)) - 1);
        $ip_ip = ip2long($ip);
        $ip_ip_net = $ip_ip & $ip_mask;
        return ($ip_ip_net == $ip_net);
    }




}