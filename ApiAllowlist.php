<?php
namespace Stanford\ApiAllowlist;

include_once "emLoggerTrait.php";

include_once "createProjectFromXML.php";

use \REDCap;
use \Exception;
use \Logging;


class ApiAllowlist extends \ExternalModules\AbstractExternalModule
{
    use emLoggerTrait;

    public $token;             // request token
    public $ip;                // request ip
    public $username;          // request username
    public $project_id;        // request project_id

    public $config_valid;      // configuration valid
    public $config_errors;     // array of configuration errors
    public $logging_option;    // configured log option

    public $ts_start;          // script start
    public $config_pid;        // configuration project
    public $rules;             // Rules from rules database

    public $result;            // PASS / REJECT / ERROR / SKIP
    public $rule_id;           // Match rule_id if any
    public $comment;           // Text comment
    public $log_id;            // log_id if last inserted db log

    # Internal Module Constants
    const LOG_TABLE                      = 'redcap_log_api_allowlist';
    const RULES_SURVEY_FORM_NAME         = 'api_allowlist_request';
    const REQUIRED_ALLOWLIST_FIELDS      = array('rule_id', 'expiration_date', 'allowlist_type', 'username', 'project_id', 'ip_address', 'enabled');
    const KEY_LOGGING_OPTION             = 'allowlist-logging-option';
    const KEY_REJECTION_MESSAGE          = 'rejection-message';
    const KEY_VALID_CONFIGURATION        = 'configuration-valid';
    const KEY_ALLOWLIST_ACTIVE           = 'activate-allowlist';
    const KEY_VALID_CONFIGURATION_ERRORS = 'configuration-validation-errors';
    const KEY_CONFIG_PID                 = 'rules-pid';
    const KEY_REJECTION_EMAIL_NOTIFY     = 'rejection-email-notification';
    const DEFAULT_REJECTION_MESSAGE      = 'Your API request has been rejected because your user, project, or network address have not been approved for API access.  To request API approval please complete the following survey or contact your REDCap support team.  INSERT_SURVEY_URL_HERE';
    const DEFAULT_EMAIL_REJECTION_HEADER = 'One or more API requests were made to REDCap using tokens associated with your account. Below is a summary of the rejected requests. In order to use the API you must request approval for your application. Please contact HOMEPAGE_CONTACT_EMAIL or complete the following survey: INSERT_SURVEY_URL_HERE';
    const MIN_EMAIL_RESEND_DURATION      = 60; //minutes interval to prevent default notifications from repeating rejections
    const HOURS_TO_NOTIFY_REJECTIONS     = 24; //only try and notify users for rejections less than 24 hours old
    const EXPIRED_RULE_EMAIL             = 'An API Allowlist rule associated with your account has expired and has been marked inactive.  If you are no longer are using the REDCap API for this project/network/user you can ignore this message.  If you are still using this API, you will receive rejection notification emails when requests are blocked.  For assistance with this message, please contact your REDCap support team.';



    /**
     * When the module is first enabled on the system level, check for a valid configuration
     * @param $version
     */
    function redcap_module_system_enable($version) {
        try {
            $this->validateSetup();
            $this->emDebug("Module Enabled.  Valid?", $this->config_valid);
        } catch (Exception $e) {
            $this->emError($e->getMessage(), $e->getLine());
        }
    }


    /**
     * On config chagne, check for setup and update validation setting
     * @param $project_id
     * @throws Exception
     */
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
        $is_valid = $this->getSystemSetting(self::KEY_VALID_CONFIGURATION);
        if ($is_valid == 1) {
            // Do nothing - show default info link
            $is_active = $this->getSystemSetting(self::KEY_ALLOWLIST_ACTIVE);
            if($is_active == 0) {
                $link['icon'] = "fas fa-times-circle";
                $link['name'] = "API Allowlist - <span class='badge bg-secondary text-light'>Inactive</span>";
            }
        } else {
            // configuration is not valid
            $link['icon'] = "fas fa-times-circle";
            $link['name'] = "API Allowlist - <span class='badge bg-danger text-light'>Setup Incomplete</span>";
        }
        return $link;
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

        // Make sure module is active
        if (! $this->getSystemSetting(self::KEY_ALLOWLIST_ACTIVE)) {
            $this->comment = "Allowlist is not enabled";
            $this->emDebug($this->comment);
            return;
        }

        $this->emDebug($this->getModuleName() . " is parsing API Request");

        $this->result = $this->screenRequest();

        $this->emDebug("Result: " . $this->result);

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
                // $this->logRejection();
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
     * Try to automatically configure the EM
     * @throws Exception
     */
    function checkFirstTimeSetup(){
        if($this->getSystemSetting('first-time-setup')){
            $this->emDebug("Setting up First Time Setup");

            // Check if we already have a project_id
            $config_project = $this->getSystemSetting(self::KEY_CONFIG_PID);
            if (empty($config_project)) {
                // Try to make the new rule project
                $newProjectID = $this->createAPIAllowListRulesProject();
            }

            // Update project parameters
            if ($newProjectID > 0) {
                global $homepage_contact_email;
                $url = $this->getRulesPublicSurveyUrl($newProjectID);
                $this->emDebug("Got survey hash of $url");

                $rejectionMessage = str_replace('HOMEPAGE_CONTACT_EMAIL', $homepage_contact_email,self::DEFAULT_REJECTION_MESSAGE);
                $rejectionMessage = str_replace('INSERT_SURVEY_URL_HERE', $url, $rejectionMessage);
                $this->setSystemSetting('rejection-message', $rejectionMessage);

                $emailHeader = str_replace('HOMEPAGE_CONTACT_EMAIL', $homepage_contact_email, self::DEFAULT_EMAIL_REJECTION_HEADER);
                $emailHeader = str_replace('INSERT_SURVEY_URL_HERE', $url, $emailHeader);
                $this->setSystemSetting('rejection-email-header', $emailHeader);
                $this->setSystemSetting(self::KEY_REJECTION_EMAIL_NOTIFY, true);
                $this->setSystemSetting('rejection-email-from-address', $homepage_contact_email);

                $this->setSystemSetting('first-time-setup', false);
                $this->setSystemSetting('allowlist-logging-option','1');
            }

            // Try to make database table
            if (!$this->tableExists(self::LOG_TABLE)) {
                $result = $this->createLogTable();
                $this->emDebug("Creating " . self::LOG_TABLE . " with result: " . (int)$result);
            }

        }



    }


    /**
     * Called Every 15 minutes via cron, determines whether or not to email user with Rejection notices
     * Runs assuming MIN_EMAIL_RESEND_DURATION, is 15m
     *
     */
    function cronRejectionNotifications(){
        $this->checkNotifications();
    }


    /**
     * Get the public survey url for the current PID
     * @param $pid
     * @return string
     * @throws Exception
     */
    function getRulesPublicSurveyUrl($pid) {

        // Get the survey and event ids in the project
        $proj = new \Project($pid);
        $event_id = $proj->firstEventId;
        $survey_id = $proj->firstFormSurveyId;
        $this->emDebug($survey_id, $event_id);

        // See if there is a hash yet
		$sql = "select hash from redcap_surveys_participants where survey_id = ? and event_id = ? and participant_email is null";
		$q = $this->query($sql, [$survey_id, $event_id]);

		// Hash exists
		if ($row = $q->fetch_assoc()) {
    		// Hash exists
			$hash = $row['hash'];
		} else {
    		// Create hash
			$hash = \Survey::setHash($survey_id, null, $event_id, null, true);
		}

        return APP_PATH_SURVEY_FULL . "?s=$hash";
    }

    /**
     * Quick util to get home url for project
     * @param $pid
     * @return string
     */
    public function getProjectHomeUrl($pid) {
        return substr(APP_PATH_WEBROOT_FULL,0,-1) .
            APP_PATH_WEBROOT . 'index.php?pid=' . $pid;
    }


    /**
     * Fetch all users from within the external modules log that have been sent an email notification within
     *  the MIN_EMAIL_RESEND_DURATION threshold
     * @return array array of users that have already been notified
     */
    function getRecentlyNotifiedUsers() {
        $sql = "SELECT
                lp.value as user,
                max(l.timestamp) AS ts
            FROM redcap_external_modules_log l
            LEFT JOIN redcap_external_modules_log_parameters lp on lp.log_id = l.log_id and lp.name = 'user'
            WHERE
                l.message = 'NOTIFICATION'
            AND l.timestamp >= ( NOW() - INTERVAL " . self::MIN_EMAIL_RESEND_DURATION . " MINUTE )
            GROUP BY user";
        $q = $this->query($sql, []);

        $usersRecentlyNotified = [];
        while($row = db_fetch_assoc($q)) {
            $usersRecentlyNotified[] = $row['user'];
        }
        //$this->emDebug("Recently Notified: " . $sql, json_encode($usersRecentlyNotified));
        return $usersRecentlyNotified;
    }


    /**
     * Fetch all rejected API calls in the past 24 hours where owner hasn't been notified
     * @param null $userFilter
     * @return 2d array, each rejection row indexed by user
     */
    function getRejections($userFilter = null) {
        $sql = "select
                log_id,
                username as user,
                ts as timestamp,
                ip_address as ip,
                project_id
            from redcap_log_api_allowlist
            where
                ts > NOW() - INTERVAL ? HOUR
            AND notified = false
            AND result = 'REJECT'";
        $q = $this->query($sql, [self::HOURS_TO_NOTIFY_REJECTIONS]);

        // $sql = "select log_id, timestamp, ip, project_id, user where message = 'REJECT'";
        // $q = $this->queryLogs($sql, []);
        $payload = array();
        while($row = db_fetch_assoc($q)){
            $user = $row['user'];
            if(in_array($user,$userFilter)){
                //if in the recently notified users list, skip
                $this->emDebug("Not notifying $user as they were recently contacted");
                continue;
            } else {
                //sum all query information, notify user
                if(!array_key_exists($user, $payload)){
                    //create user in payload array
                    $payload[$user] = array();
                }
                array_push($payload[$user], $row);
            }
        }
        return $payload;
    }


    /**
     * Get an email address for a username
     * @param $user
     * @return bool
     */
    function getUserEmail($user) {
        $sql = "SELECT user_email from redcap_user_information where username = ?";
        $q = $this->query($sql, [$user]);
        return db_result($q,0);
    }


    /**
     * Determines whether or not to send a user an email notification based on MIN_EMAIL_RESEND_DURATION
     * @throws Exception
     * @return void
     */
    function checkNotifications() {
        // fetch users that have already been notified within the threshold period
        $filter = $this->getRecentlyNotifiedUsers();

        // fetch all rejection messages in the recent day, grouped by user
        $rejections = ($this->getRejections($filter));
        //$this->emDebug($rejections);

        if(!empty($rejections)) {
            $header = $this->getSystemSetting('rejection-email-header');
            $rejectionEmailFrom = $this->getSystemSetting('rejection-email-from-address');
            if(!empty($rejectionEmailFrom)) {
                foreach($rejections as $user => $rows){
                    $logIds = array();
                    $email = $this->getUserEmail($user);

                    //fetch the first col in the returned row
                    $css = "style='text-align:left; padding-right: 15px;' ";
                    $table = "<table>
                                <thead><tr>
                                    <th $css>Time</th>
                                    <th $css>IP Address</th>
                                    <th $css>Project ID</th>
                                </tr></thead>
                              <tbody>";

                    foreach ($rows as $row) {
                        $project = "<a href='{$this->getProjectHomeUrl($row['project_id'])}' target='_blank'>{$row['project_id']}</a>";
                        $table .= "<tr><td $css>{$row['timestamp']}</td><td $css>{$row['ip']}</td><td $css>$project</td></tr>";

                        //keep track of logID to remove from table upon fin
                        $logIds[] = $row['log_id'];
                    }
                    $table .= "</tbody></table>";
                    $messageBody = $header . "<hr>" . $table;
                    $this->emDebug($email, $rejectionEmailFrom, $messageBody);
                    $emailResult = REDCap::email($email,$rejectionEmailFrom,'API Allowlist rejection notice', $messageBody);
                    $this->emDebug("Result:", $emailResult);
                    if($emailResult){
                        $this->logNotification($user);
                        $this->emDebug('deleting log_ids', $logIds);
                        $sql = "update " . self::LOG_TABLE . " set notified = true where log_id in (" .
                            implode(',', $logIds) . ")";
                        $result = $this->query($sql,[]);
                        $this->emDebug("Marking " . count($logIds) . " rejected calls for $user as notified - " . json_encode($result));
                    } else {
                        $this->emError('Email not sent', $messageBody , $rejectionEmailFrom, $email);
                    }
                }
            }
        }
    }


    /**
     * Create a NOTIFICATION entry in the log table : indicates when last email was sent to user
     * @param $user username
     * @return void
     */
    function logNotification($user){
        $this->log("NOTIFICATION", array(
            'user' => $user
        ));
    }

    // /**
    //  * Create a REJECT entry in the log table
    //  * @throws Exception
    //  */
    // function logRejection() {
    //     // Are we logging rejections for email?
    //     $emailRejection = $this->getSystemSetting(self::KEY_REJECTION_EMAIL_NOTIFY);
    //     if (empty($emailRejection)) {
    //         // No need to do anything
    //         return;
    //     }
    //
    //     // Log the rejection
    //     $this->log("REJECT", array(
    //             'user' => $this->username,
    //             'ui_id' => $this->username,
    //         'ip'    => $this->ip,
    //         'project_id' => $this->project_id)
    //     );
    // }


    /**
     * Determine if the module is configured properly
     * store this as two parameters in the em-settings table
     * @param $quick_check  / true for a quick check of whether or not the config is valid
     * @return bool
     * @throws Exception
     */
    function validateSetup($quick_check = false) {
        # Quick Check
        if ($quick_check) {
            // Let's just look at the KEY_VALID_CONFIGURATION setting
            if (!$this->getSystemSetting(self::KEY_VALID_CONFIGURATION) == 1) {
                $this->emDebug('EM Configuration is not valid');
                return false;
            }
        }

        # Do a Thorough Check
        // Verify that the module is set up correctly
        $config_errors = array();

        // Make sure rejection message is set
        if (empty($this->getSystemSetting(self::KEY_REJECTION_MESSAGE))) {
            $config_errors[] = "Missing rejection message in module setup";
        }

        // Make sure configuration project is set
        $this->config_pid = $this->getSystemSetting(self::KEY_CONFIG_PID);
        if (empty($this->config_pid)) {
            $config_errors[] = "Missing API Allowlist Configuration project_id setting in module setup";
        } else {
            // Verify that the project has the right fields
            $q = REDCap::getDataDictionary($this->config_pid, 'json');
            $dictionary = json_decode($q,true);

            // Parse out fields from dictionary
            $fields = array();
            foreach ($dictionary as $field) $fields[] = $field['field_name'];

            // Check for required fields
            $missing = array_diff(self::REQUIRED_ALLOWLIST_FIELDS, $fields);
            if (!empty($missing)) $config_errors[] = "The API Allowlist project (#$this->config_pid) is missing required fields: " . implode(", ", $missing);
        }

        // Check for presence of custom log table if configured
        if ($this->getSystemSetting(self::KEY_LOGGING_OPTION) == 1) {
            // Make sure we have the custom log table
            if(! $this->tableExists(self::LOG_TABLE)) {
                // Table missing - try to create the table
                $config_errors[] = "Table-based logging is enabled but the required table `" . self::LOG_TABLE . "` has not been created.";
            } else {
                // Custom table exists!
                // $this->emDebug("Custom log table verified");
            }
        }

        // Save validation results to system settings to support 'quick' checks
        $this->config_valid = empty($config_errors);
        $this->config_errors = $config_errors;

        $this->setSystemSetting(self::KEY_VALID_CONFIGURATION, $this->config_valid ? 1 : 0);
        $this->setSystemSetting(self::KEY_VALID_CONFIGURATION_ERRORS, json_encode($this->config_errors));

        if (!$this->config_valid) $this->emLog("Config Validation Errors", $this->config_errors);

        return $this->config_valid;
    }


    // public function foo() {
    //     $this->emDebug("Trying to create custom logging table in database: " . self::LOG_TABLE);
    //     if (! $this->createLogTable()) {
    //         $this->emDebug("Not able to create log table from script - perhaps db user doesn't have permissions");
    //         $config_errors[] = "Error creating log table automatically - check the control center API Allowlist link for instructions";
    //     } else {
    //         // Sanity check to make sure table creation worked
    //         if(! $this->tableExists(self::LOG_TABLE)) {
    //             $this->emError("Log table creation reported true but I'm not able to verify - this shouldn't happen");
    //             $config_errors[] = "Missing required table after table creation reported success - this shouldn't happen.  Is " . self::LOG_TABLE . " there or not?";
    //         } else {
    //             // Table was created
    //             $this->emLog("Created database table " . self::LOG_TABLE . " auto-magically");
    //         }
    //     }
    //
    // }


    /**
     * Function that dynamically creates and assigns a API Allowlist Redcap project using a supertoken
     * @return boolean success
     * @throws Exception
     */
    public function createAPIallowListRulesProject(){
        $odmFile = $this->getModulePath() . 'assets/APIAllowlistRulesProject.REDCap.xml';
        $this->emDebug("ODM FILE",$odmFile);
        $newProjectHelper = new createProjectFromXML($this);
        $superToken = $newProjectHelper->getSuperToken(USERID);

        if (empty($superToken)) {
            $this->emError("Unable to get SuperToken to create Rules project");
            return false;
        }

        // Import Project
        $newToken = $newProjectHelper->createProjectFromXMLfile($superToken, $odmFile);
        $this->emDebug('Obtained Super Token', $newToken);
        list($username, $newProjectID) = $this->getUserProjectFromToken($newToken);
        $this->emDebug('Project Created', $username, $newProjectID);

        // Set the config project id
        $this->setSystemSetting(self::KEY_CONFIG_PID, $newProjectID);

        // Fix dynamic SQL fields
        $newProjectHelper->convertDynamicSQLField(
            $newProjectID,
            'project_id',
            'select project_id, CONCAT_WS(" ",CONCAT("[", project_id, "]"), app_title) from redcap_projects;'
        );
        $newProjectHelper->convertDynamicSQLField(
            $newProjectID,
            'username',
            'select username, CONCAT_WS(" ", CONCAT("[",username,"]"),user_firstname, user_lastname) from redcap_user_information order by username;'
        );

        return $newProjectID;
    }


    /**
     * Screen the API request against the allowlist
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

            // Load all of the allowlist rules
            $this->loadRules($this->config_pid);

            // Debug post
            // $this->emDebug("POST", $_POST);

            // Get the project and user from the token
            $this->loadProjectUsername($this->token);

            if(empty($this->rules)){
                $this->emLog('No current rules are set in current allowlist config');
            }

            foreach ($this->rules as $rule) {
                //check all records if pass, else reject
                $this->rule_id = $rule['rule_id'];

                $check_ip = $rule['allowlist_type___1'];
                $check_user = $rule['allowlist_type___2'];
                $check_pid = $rule['allowlist_type___3'];

                // Verify rule has not expired
                $expires = $rule['expiration_date'];
                if (!empty($expires) && strtotime($expires) < time()) {
                    // The rule has expired!
                    // Is there an email for who registered the rule?
                    $emails = [];
                    if (!empty($rule['email'])) $emails[] = $rule['email'];

                    // Is there a different email address associated with the token?
                    $tokenEmail = $this->getUserEmail($this->username);
                    if (!empty($tokenEmail) && !in_array($tokenEmail,$emails)) $emails[] = $tokenEmail;

                    // Let's email the user(s)
                    $to = implode(", ", $emails);
                    $from = $this->getSystemSetting('rejection-email-from-address');
                    $subject = "REDCap API allowlist Rule #" . $this->rule_id . " Expiration Warning";
                    $message = "<p>Dear REDCap API User</p><p>" . self::EXPIRED_RULE_EMAIL . "</p>";
                    $message .= "<div><b>" . $subject . "</b></div>";
                    if (!empty($rule['request_notes'])) $message .= "<div><i>" . $rule['request_notes'] . "</i></div>";
                    if ($check_ip) $message   .= "<div> - Network Range: " . $rule['ip_address'] . "</div>";
                    if ($check_user) $message .= "<div> - Username: " . $rule['username'] . "</div>";
                    if ($check_pid) $message  .= "<div> - Project Id: " . $rule['project_id'] . "</div>";
                    REDCap::email($to, $from, $subject, $message);

                    // Inactivate the rule
                    $rule['enabled___1'] = 0;
                    $result = REDCap::saveData($this->config_pid, 'json', json_encode(array($rule)));
                    if (empty($result['errors'])) {
                        $this->emDebug("Inactivated expired rule " . $this->rule_id);
                    } else {
                        $this->emError("Errors deactivating expired rule!", $result, $rule);
                    }
                    continue;
                }


                if (!($check_ip || $check_user || $check_pid)) {
                    // NONE ARE CHECKED - SKIP THIS CONFIG
                    $this->emError("Rule " . $rule['rule_id'] . " does not have any filters checked!");
                    continue;
                }

                // If empty, we assume pass but require that at least one check must be defined
                $valid_ip   = $check_ip   ? $this->validIP($rule['ip_address'])  : true;
                $valid_user = $check_user ? $this->validUser($rule['username'])  : true;
                $valid_pid  = $check_pid  ? $this->validPid($rule['project_id']) : true;

                // $this->emDebug($valid_ip, $valid_user, $valid_pid);

                if ($valid_ip && $valid_user && $valid_pid) {
                    // APPROVE API REQUEST

                    // IN OLDER VERSIONS OF REDCAP, THE API WOULD ALLOW YOU TO SPECIFY THE EVENT NAME IN THE
                    // LIST OF FIELDS TO QUERY.  WE DEPLOYED A MOBILE APP THAT HAD THIS AND AFTER AN UPGRADE
                    // FOUND ALL API REQUESTS WERE REJECTED.  SINCE WE COULDN'T EASILY FIX THE APP, WE ADDED
                    // THIS FIX WHICH REMOVES redcap-event-name FROM THE QUERIED LIST OF FIELDS IN AN API RECORD
                    // QUERY.
                    if ($this->getSystemSetting('fix-redcap-event-name-error')) {
                        try {
                            $content = isset($_POST['content']) ? $_POST['content'] : false;
                            $fields = isset($_POST['fields'])   ? $_POST['fields']  : false;
                            if ($content === "record" && is_array($fields)) {
                                $key = array_search('redcap_event_name', $fields);
                                if ($key !== false) {
                                    // Find the key for the invalid field (if present)
                                    $this->emDebug("Found redcap_event_name in fields at $key", $_POST['fields'] );
                                    unset($_POST['fields'][$key]);
                                    $this->emDebug("Fixed redcap_event_name error at $key", $_POST['fields'] );
                                }
                            }
                        } catch (Exception $e) {
                            $this->emDebug("Error trying to do fix-redcap-event-name-error", $this->project_id, $this->token, $e->getMessage(), $e->getLine(), $e->getTraceAsString());
                        }
                    }

                    return "PASS";
                }

            } // End of rules

            // Fail request
            $this->rule_id = null;
            return "REJECT";

        } catch (Exception $e) {
            $this->emError("Errors", $e->getMessage(), $e->getLine(), $this->project_id, $this->token, $_REQUEST);
            $this->comment = "SCREEN REQUEST: " . $e->getMessage();
            return "ERROR";
        }
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
        // $this->emDebug($this->username, $username);

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
                // Log to REDCap Log Table (not implemented)
                $cm = json_encode(array(
                    "result"        => $this->result,
                    "content"       => $content,
                    "ip"            => $this->ip,
                    "username"      => $this->username,
                    "project_id"    => $this->project_id,
                    "rule_id"       => $this->rule_id,
                    "comment"       => $this->comment));

                // To override the username I'm using the direct method call instead of REDCap::logEvent
                Logging::logEvent("", self::LOG_TABLE, "OTHER", null, $cm, "API Allowlist Request $this->result", "", $this->username, $this->project_id);
                break;
        }
        // Log to EmLogger
        // $this->emDebug(array(
        //     "result"     => $this->result,
        //     "content"    => $content,
        //     "ip"         => $this->ip,
        //     "username"   => $this->username,
        //     "project_id" => $this->project_id,
        //     "rule_id"    => $this->rule_id,
        //     "comment"    => $this->comment));
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
            rule_id = %s,
            comment = '%s'",
            db_real_escape_string(self::LOG_TABLE),
            db_real_escape_string($this->ip),
            db_real_escape_string($this->username),
            db_real_escape_string($this->project_id),
            db_real_escape_string($this->result),
            db_real_escape_string(empty($this->rule_id) ? "NULL" : $this->rule_id),
            db_real_escape_string($comment)
        );
        $result = db_query($sql);
        $this->log_id = db_insert_id();
        $this->emDebug("Log Result: " . json_encode($result) . " - log id: " . json_encode($this->log_id));

        // Register a shutdown function to record the duration of the API call to the log database
        register_shutdown_function(array($this, "logToDatabaseUpdateDuration"));
    }


    /**
     * This function is called from a shutdown to update the database entry with the elapsed duration of the API call in the event
     * a local database is used for logging
     */
    public function logToDatabaseUpdateDuration() {
        $duration = round((microtime(true) - $this->ts_start) * 1000, 3);
        $sql = sprintf("UPDATE %s SET duration = %u where log_id = %d LIMIT 1",
            self::LOG_TABLE,
            $duration,
            $this->log_id
        );
        $q = $this->query($sql, []);
        // $this->emDebug($this->log_id, $this->ts_start, $sql, $q);
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
        $sql = $this->createLogTableSql();
        $q = $this->query($sql, []);
        return !($q === FALSE);
    }


    /**
     * Return the SQL to create the log table
     * @return string
     */
    public function createLogTableSql() {
        $sql="
            CREATE TABLE `" . self::LOG_TABLE . "` (
              `log_id` int NOT NULL AUTO_INCREMENT,
              `ip_address` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
              `username` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
              `project_id` int DEFAULT NULL,
              `ts` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
              `duration` float DEFAULT NULL,
              `result` enum('PASS','REJECT','ERROR') CHARACTER SET utf8 DEFAULT NULL,
              `rule_id` int DEFAULT NULL,
              `comment` text CHARACTER SET utf8,
              PRIMARY KEY (`log_id`),
              INDEX (`username`),
              INDEX (`project_id`)
            ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
        ";
        return $sql;
    }


    /**
     * Load enabled allowlist rules
     * @param $pid
     */
    function loadRules($pid) {
        $filter = "[enabled(1)] = '1'";
        $params = [
            'return_format' => 'json',
            'filterLogic'  => "[enabled(1)] = '1'",
            'project_id'    => $pid,
            'fields'        => self::REQUIRED_ALLOWLIST_FIELDS
        ];
        $q = REDCap::getData($params);
        // $q = REDCap::getData($pid, 'json', NULL, NULL, NULL, NULL, FALSE, FALSE, FALSE, $filter);
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
        list($this->username, $this->project_id) = $this->getUserProjectFromToken($token);
        $this->emDebug("Token belongs " . $this->username . " / pid " . $this->project_id);
    }


    /**
     * Fetch user information from corresponding API token
     * @param String $token
     * @return array [username, project_id]
     * @throws Exception
     */
    public function getUserProjectFromToken($token)
    {
        $sql = "
            SELECT username, project_id
            FROM redcap_user_rights
            WHERE api_token = ?";
        $q = $this->query($sql, $token);
        if ($row = $q->fetch_assoc()) {
            return array($row['username'], $row['project_id']);
        } else {
            throw new Exception ("Returned invalid number of rows (" . db_num_rows($q) . ") in " . __METHOD__ . " from token '$token'");
        }
    }


    /**
     * Check if valid API request
     * @return bool
     */
    static function isApiRequest() {
        return defined('API') && API === true;
    }


    // /**
    //  * Checks if the IP is valid given an IP or CIDR range
    //  * e.g. 192.168.123.1 = 192.168.123.1/30
    //  * @param $CIDR
    //  * @return bool
    //  */
    // public function ipCIDRCheck ($CIDR) {
    //     $IP = $this->ip;
    //     if(strpos($CIDR, "/") === false) $CIDR .= "/32";
    //     list ($net, $mask) = explode ('/', $CIDR);
    //     $ip_net = ip2long ($net);
    //     $ip_mask = ~((1 << (32 - $mask)) - 1);
    //     $ip_ip = ip2long ($IP);
    //
    //     $this->emDebug($net, $ip_net, $mask, $ip_mask, ($ip_ip & $ip_mask), ($ip_net & $ip_mask));
    //
    //     return (($ip_ip & $ip_mask) == ($ip_net & $ip_mask));
    // }


    /**
     * Taken from https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php
     * @param $ipv4
     * @param $format
     * @return array|int|int[]|string
     */
    public function cidr2range($ipv4, $format="decimal")
    {
        if ($ip = strpos($ipv4, '/')) {
            $n_ip = (1 << (32 - substr($ipv4, 1 + $ip))) - 1;
            $ip_dec = ip2long(substr($ipv4, 0, $ip));
        } else {
            $n_ip = 0;
            $ip_dec = ip2long($ipv4);
        }
        $ip_min = $ip_dec & ~$n_ip;
        $ip_max = $ip_min + $n_ip;

        switch($format) {
            case "decimal":
                #Array(2) of Decimal Values Range
                return [$ip_min, $ip_max];
            case "human":
                #Array(2) of Ipv4 Human Readable Range
                return [long2ip($ip_min),long2ip($ip_max)];
            case "subnet":
                #Array(2) of Ipv4 and Subnet Range
                return [long2ip($ip_min),long2ip(~$n_ip)];
            case "wildcard":
                #Array(2) of Ipv4 and Wildcard Bits
                return [long2ip($ip_min),long2ip($n_ip)];
            case "integer":
                #Integer Number of Ipv4 in Range
                return ++$n_ip;
            default:
                return "Invalid format!";
        }
    }

    /**
     * Intended to be a function to call to check -- CIDR can also be a plain IP
     * @param $ip
     * @param $cidr
     * @return bool
     */
    public function ipInCidr($ip, $cidr) {
        if(
            ($range=$this->cidr2range($cidr)) &&
            ($check=ip2long($ip))!==false &&
            $check>=$range[0] && $check<=$range[1]
        ) {
            return true;
        } else {
            return false;
        }
    }


    /**
     * Check if current user IP is valid under any of the specified rules
     * Param: String CIDR values
     * @return bool T/F
     */
    function validIP($cidr_list): bool
    {
        $cidrs = preg_split("/[\s,]+/", $cidr_list);
        // $this->emDebug($ips);

        //check if any of the ips are valid
        foreach($cidrs as $cidr){
            // if($this->ipCIDRCheck(trim($cidr)))
            if ($this->ipInCidr($this->ip, $cidr)) return true;
        }
        return false;
    }

}
