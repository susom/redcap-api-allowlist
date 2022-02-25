<?php
namespace Stanford\ApiAllowlist;

use \RedCapDB;

/**
 * Class createProjectFromXML
 * Helper class for dynamic creation of a REDCap projects
 * @package Stanford\ApiAllowlist
 * @property ApiAllowlist $module
 * @property RedCapDB $db
 */
class createProjectFromXML
{
    private $module;        // A link to the parent EM to be used for debugging
    private $db;            // A RedCapDB object

    public function __construct($module){
        $this->module = $module;
        $this->db = new RedCapDB();
    }


    /**
     * Get/Create a Super Token
     * @return string token, or null
     */
    public function getSuperToken(){
        $token = $this->db->getUserSuperToken(USERID);

        if(!$token){
            // Create a temporary token
            if($this->db->setAPITokenSuper(USERID)){
                $this->module->emDebug("Created token successfully");
                $token = $this->db->getUserSuperToken(USERID);

                // Remember to delete the temporary token
                register_shutdown_function(array($this, "deleteTempSuperToken"));
            } else {
                $this->module->emError("Failed in creating super token");
            }

        }
        $this->module->emDebug("token", $token);
        return $token;
    }


    /**
     * When importing an XML file, dynamic SQL is not added.  Use this method to convert an XML field back into
     * dynamic sql as:
     *      convertDynamicSQLField(
     *          $ProjectID,
     *          'username',
     *          'select username, CONCAT_WS(" ", CONCAT("[", username, "]"), user_firstname, user_lastname) from redcap_user_information;'
     *      );
     * @param $project_id
     * @param $fieldname
     * @param $sql
     */
    public function convertDynamicSQLField($project_id, $fieldname, $sql, $autocomplete=true){
        $sql = sprintf(
            "update redcap_metadata
            set element_type = 'sql' , element_enum = '%s'
            where project_id = %d and field_name = '%s' limit 1",
            db_real_escape_string($sql),
            db_real_escape_string($project_id),
            db_real_escape_string($fieldname)
        );
        $result = db_query($sql);
        if ($autocomplete && $result) {
            $sql = sprintf(
                "update redcap_metadata
                set element_validation_type = 'autocomplete'
                where project_id = %d and field_name = '%s' limit 1",
                db_real_escape_string($project_id),
                db_real_escape_string($fieldname)
            );
            $result = db_query($sql);
        }
        $this->module->emDebug("result", $result);
    }


    /**
     * Given API token & Filepath to XML, create Redcap project via POST
     * @param String $token : SuperAPI token
     * @param String $path : absolute path to XML doc
     * @return boolean $result
     */
    public function createProjectFromXMLfile($token, $path) {
        if (!file_exists($path)) {
            $this->module->emError("Unable to find $path");
            return false;
        }

        if (empty($token)) {
            $this->module->emError("Invalid/empty token");
            return false;
        }

        // Load File
        $odm = file_get_contents($path);
        $url = APP_PATH_WEBROOT_FULL . "api/";

        if(!isset($odm)){
            $this->module->emError('INVALID : Cannot get contents of odm');
        } else {
            $data = array(
                "project_title" => "API Allowlist EM Rules",
                "purpose"   => 4,
                "is_longitudinal" => 0
            );

            $package = array(
                "token" => $token,
                "content" => "project",
                "format" => "json",
                "data" => json_encode(array($data)),
                "returnFormat" => "json",
                "odm" => $odm
            );

            // $this->module->emDebug('POST TO ' . $url, $package);
            $result = http_post($url,$package, 30);
            $this->module->emDebug($result);
            return $result;
        }
        return null;

    }


    /**
     * Remove the temporary SuperUser Token if created solely for this purpose
     * @param void
     * @return void
     */
    public function deleteTempSuperToken() {
        // Remove the super token
        $this->db->deleteApiTokenSuper(USERID);
        $this->module->emDebug("Deleted temp SuperUser token");
    }

}
