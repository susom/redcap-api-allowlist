<?php
namespace Stanford\ApiAllowlist;
/** @var \Stanford\ApiAllowlist\ApiAllowlist $module */

require APP_PATH_DOCROOT . "ControlCenter/header.php";

if (!SUPER_USER) {
    ?>
    <div class="jumbotron text-center">
        <h3><span class="glyphicon glyphicon-exclamation-sign"></span> This page is only available for REDCap Administrators</h3>
    </div>
    <?php
    exit();
}

// HEADER
?>
<div class="container">
    <h4>
        <i class="fas fa-door-open"></i> <?php echo $module->getModuleName() ?> Configuration Status
    </h4>
    <p>
        This external module, once configured and enabled, will block all API requests unless a specific rule exists
        to allow the request to pass.  Rules are managed via a separate REDCap project and can be configured
        by project_id, network address or range, and username.  Rejected requests will see a customized error message
        to help direct them to a request form.
    </p>
    <hr>
<?php

// Validate setup
$module->validateSetup();

?>
    <h5>REDCap API Allowlist Rule Project</h5>
    <p>
        A REDCap project is used to define all allowlist rules.
    </p>
<?php

if (empty($module->config_pid)) {
    ?>
    <p>
        This project is not currently created or defined in the module configuration.
        You can create the project from <a class="text-decoration-underline" download href="<?php
        echo $module->getUrl("assets/APIAllowlistRulesProject.REDCap.xml")
        ?>">this XML Project Definition file</a>
        or you can use the 'first time setup' option in the module configuration to create it for you<br>
        <!--div class="btn btn-primary btn-xs" id="createProject">Create Rule Project</div-->
    </p>
    <p>
        If you have a project already, then simply edit this module's configuration to select the project_id.
    </p>
    <?php
} else {
    $survey_url = $module->getRulesPublicSurveyUrl($module->config_pid);
    callJSfile("clipboard.js");
    ?>
    <div style="text-align:center;">
        <button class = 'btn btn-primaryrc' onclick="window.open('<?php echo $module->getProjectHomeUrl($module->config_pid) ?>')">View API Allowlist Rules Project
            <span class="badge badge-danger">PID <?php echo $module->config_pid ?></span>
        </button>
    </div>
    <div>
        <p>
            Your API Allowlist Rules project has a public survey url that can be used by end-users to request new
            Allowlist rules.  This url is likely part of your rejection message and email in the EM config already.
            You should review this project and ensure the questions asked meet your requirements.
        </p>
        <!-- Public survey URL -->
        <div style="padding:5px 0px 6px;">
            <div style="float:left;font-weight:bold;font-size:12px;line-height:1.8;"><?php echo $lang['survey_233'] ?></div>
            <input id="survey_url" value="<?php echo $survey_url ?>" onclick="this.select();"
                   readonly="readonly" class="staticInput mb-1 mr-1"
                   style="float:left;width:80%;max-width:350px;">
            <button class="btn btn-defaultrc btn-xs btn-clipboard" title="<?php print js_escape2($lang['global_137']) ?>"
                    data-clipboard-target="#survey_url" style="padding:3px 8px 3px 6px;"><i class="fas fa-paste"></i>
            </button>
            <button class="btn btn-defaultrc btn-xs" title="Open Survey"
                    onclick="window.open('<?php echo $survey_url ?>')"
                    style="padding:3px 8px 3px 6px;"><i class="fas fa-external-link-alt"></i>
            </button>
            <script type="text/javascript">
                $(document).ready( function() { new Clipboard('.btn-clipboard'); } );
            </script>
            <style>
                code { font-weight: bold; color: blue;}
            </stylE>
			</div>
			<div class="clear"></div>
    </div>
<?php
}


    $log_option = $module->getSystemSetting($module::KEY_LOGGING_OPTION);
    $table_exists = $module->tableExists($module::LOG_TABLE);
?>
    <hr>
    <h5>REDCap API Allowlist Request Logging</h5>
    <p>
        We recommend storing the API request logs in a new database table.
    </p>
<?php
    if ($table_exists && $log_option == 1) { ?>
    <p>
        You are using the recommended table-based logging: <code><?php echo $module::LOG_TABLE ?></code>.
    </p>
<?php
    } else {
?>
    <p>
        If you wish to use the recommended table-based logging, make sure the following table exists and your
        module configuration is set to table mode.
        <pre class="m-3 small"><?php echo str_replace("            ","",$module->createLogTableSql()) ?></pre>
    </p>
    <div class="hidden">
        <p>
            Or, we can try to manually create the table for you.
        <div class="btn btn-primary btn-xs" id="createLoggingTable">Create Request Logging Table</div>
        </p>
    </div>
<?php
    }

    if ($module->config_valid != 1) {
        echo "<hr><h5>The following configuration issues must be addressed:</h5>";
        foreach ($module->config_errors as $error) {
            echo "<div class='alert alert-danger'>" . $error . "</div>";
        }
    }

    if (! $module->getSystemSetting($module::KEY_ALLOWLIST_ACTIVE)) {
        ?>
        <hr>
        <h5>The API Allowlist module is not active</h5>
        <div class='alert alert-danger'>Resolve any configuration issues and activate in the module config to
            start using this module</div>
        <hr>
        <?php
    }


$logOption = $module->getSystemSetting($module::KEY_LOGGING_OPTION);
    if( $logOption == 1) {
?>
    <div>
        <h5>Monitoring your API Usage</h5>
        <p>The following queries may be useful to monitor your API usage either via your SQL query tool or using
            the Admin Dashboard external module or MySql Simply Admin from the <a href="https://redcap.vanderbilt.edu/consortium/modules/index.php"
                                                                                  target="_blank">REDCap Repo</a>.
        </p>
        <ol>
            <li>
                <p>Cumulative API response duration by project/rule</p>
                <code>SELECT SUM(duration), project_id, rule_id FROM redcap_log_api_allowlist group by rule_id,
                    project_id ORDER BY SUM(duration) desc </code>
            </li>
            <li>
                <p>Most recent allowlist rejections</p>
                <code>SELECT project_id, ip_address, ts, comment FROM redcap_log_api_allowlist WHERE rule_id IS NULL
                    order by ts desc</code>
            </li>
        </ol>
    </div>
    <hr>
    <div class = 'alert alert-warning'>
        <b>NOTE:</b> Only API requests that contain a key of token will be filtered.
        External modules links routed through the API will not be filtered unless the developer was unlucky enough
        to have chosen to use a parameter called 'token' in their code.
    </div>
</div>
<?php
    }

    // Show Control Center
    require_once APP_PATH_DOCROOT . 'ControlCenter/footer.php';

?>
