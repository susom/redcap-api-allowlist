<?php
namespace Stanford\ApiWhitelist;
/** @var \Stanford\ApiWhitelist\ApiWhitelist $module */

require APP_PATH_DOCROOT . "ControlCenter/header.php";

if (!SUPER_USER) {
    ?>
    <div class="jumbotron text-center">
        <h3><span class="glyphicon glyphicon-exclamation-sign"></span> This utility is only available for REDCap Administrators</h3>
    </div>
    <?php

    exit();
}

// Validate setup
$module->validateSetup();

?>

<div class="container">
    <h5><?php echo $module->getModuleName()?></h5>
    <p>
        This module creates an additional filter on your public API endpoint. Rules must be added to allow API requests to succeed. These rules are managed by a REDCap API Whitelist Rules project.
    </p>


<?php

if ($module->config_valid != 1) {

    ?>
    <p>
        There are two ways to setup your REDCap API Whitelist Rules project.
        <ol>
        <li>The first is to check the first time setup option on the configuration page. </li>
        <li>The second is to manually setup your API Whitelist Configuration project by downloading the following XML REDCap project template.
            <br>
            Return to the EM setup and set the PID to match this newly created project.
            <br>
            <a href="<?php echo $module->getUrl("assets/ApiWhitelistRulesProject.xml") ?>">Download Project XML</a>
        </li>
        </ol>


    </p>
    <p>
        We recommend storing the API request logs in a separate database table. This table will be auto created when you generate a project using the first time setup option if your database
        user has create table privileges. Alternatively you can create this table manually using the following SQL
    <pre class="m-3"><code><?php echo str_replace("            ","",$module->createLogTableSql()) ?></code></pre></p>
    <p>
        The follow configuration errors need to be addressed:
    </p>

    <?php

    foreach ($module->config_errors as $error) {
        echo "<div class='alert alert-danger'>" . $error . "</div>";
    }
    exit();
}

$url = substr(APP_PATH_WEBROOT_FULL,0,-1);
$url .=  (APP_PATH_WEBROOT . 'ProjectSetup/index.php?pid=' . $module->config_pid);

?>
<button class = 'btn btn-primary' onclick="location.href='<?php echo $url ?>'">View API Whitelist Rules Project <span class="badge badge-secondary">PID: <?php echo $module->config_pid ?></span></button><hr>

<div class = 'alert alert-warning'>NOTE: Only API requests that contain a key of token will be filtered. External modules links routed through the API will not be filtered. </div>

    <?php
        $logOption = $module->getSystemSetting('whitelist-logging-option');
        if( $logOption == 1) {
    ?>
    <div>
        <p>For a succinct, table visualization showing common API usage statistics please enable the admin dashboard
            external module and configure custom reports using the examples below:</p>
        <ol>
            <li>
                <p>Cumulative API response duration by project/rule</p>
                <code>SELECT SUM(duration), project_id, rule_id FROM redcap_log_api_whitelist group by rule_id,
                    project_id ORDER BY SUM(duration) desc </code>
            </li>
            <li>
                <p>Most recent whitelist rejections</p>
                <code>SELECT project_id, ip_address, ts, comment FROM redcap_log_api_whitelist WHERE rule_id IS NULL
                    order by ts desc</code>
            </li>
        </ol>
    </div>
    <hr>
    </div>
    <?php
        }
    ?>