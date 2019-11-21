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
        This module blocks all API requests containing a 'token' unless they have been whitelisted via a rule.  Rules
        can be based on project_id, network address, and user.  Rejected requests will see an error message directing
        them to contact you for assistance.  You can customize these settings in the module configuration.
    </p>
    <hr>
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
        We recommend storing the API request logs in a separate database table. This table will be auto created when you
        first enable this external module on your server.  Alternatively you can create this table manually using the following SQL
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
$survey_url = $module->getRulesPublicSurveyUrl($module->config_pid);
callJSfile("clipboard.js");
?>
    <h6>The API Whitelist Rules Project</h6>
    <p>
        Upon activation, a new project was created to store your rules.  Typical rules include local IP ranges, VPN IP
        ranges, or projects that are using the REDCap Mobile App for remote data collection and sync.
    </p>
    <div style="text-align:center;">
        <button class = 'btn btn-primaryrc' onclick="window.open('<?php echo $url ?>')">View API Whitelist Rules Project
            <span class="badge badge-danger">PID <?php echo $module->config_pid ?></span>
        </button>
    </div>
    <div>
        <p>
            Your API Whitelist Rules project has a public survey url that can be used by end-users to request new
            Whitelist rules.  This url is likely part of your rejection message and email in the EM config already.
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
    if (! $module->getSystemSetting(self::KEY_WHITELIST_ACTIVE)) {
        echo "<div class='alert alert-danger text-center'>The API Whitelist is not activated.  Check the module config to activate filtering</div>";
    }
?>
    <hr>
<?php
    $logOption = $module->getSystemSetting('whitelist-logging-option');
    if( $logOption == 1) {
?>
    <div>
        <h6>Monitoring your API Usage</h6>
        <p>For a succinct, table visualization showing common API usage statistics you can use the following queries
            with the <code>Admin Dashboard</code> external module:</p>
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
    <div class = 'alert alert-warning'>
        <b>NOTE:</b> Only API requests that contain a key of token will be filtered.
        External modules links routed through the API will not be filtered unless the developer was unlucky enough
        to have chosen to use a parameter called 'token' in their code.
    </div>
</div>
<?php
    }
?>