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
        This module creates an additional filter on your public API.  All API requests that contain a valid 'token' in the body will be filtered through an additional whitelist once this module is configured.
    </p>

<?php

if ($module->config_valid == 1) {

    ?>

    <p>
        Currently, this module's configuration is: <h3><span class="badge badge-success text-success>"><i class="fas fa-check-circle"></i> Great</span></h3>
    </p>

    <?php
} else {
    ?>
    <p>
        The follow configuration errors need to be addressed:
    </p>
    <?php

    foreach ($module->config_errors as $error) {
        echo "<div class='alert alert-danger'>" . $error . "</div>";
    }
}


if (empty($module->config_pid)) {
    ?>

    <p>
        To setup your API Whitelist Configuration project, download the following XML redcap project and create a new project from it.  Return to the EM setup and set the PID to match this newly created project.
        <a href="<?php echo $module->getUrl("docs/api_whitelist_configuration_project.xml") ?>" class="btn btn-primaryrc">Download Project XML</a>

    </p>



    <?php

}
//echo' hello';
//$module->emDebug('inside');
//$module->createAPIWhiteListRulesProject();

?>

    <hr>
    <h6>Troubleshooting</h6>
    <p>
        If you are interested in using the local database option but running into troubles, the following is the SQL you should run with a user that has create table rights:
    <pre class="m-3"><code><?php echo str_replace("            ","",$module->createLogTableSql()) ?></code></pre>
    </p>

</div>

