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

}else{
    //build link to main page
    $url = substr(APP_PATH_WEBROOT_FULL,0,-1);
    $url .=  (APP_PATH_WEBROOT . 'ProjectSetup/index.php?pid=' . $module->config_pid);
    ?>
    <button class = 'btn btn-primary' onclick="location.href='<?php echo $url ?>'">Project Home</button>

    <?php
}
//echo' hello';
//$module->emDebug('inside');
//$module->createAPIWhiteListRulesProject();

?>
    <script src="<?php echo $module->getUrl('js/configDataTable.js') ?>"></script>
    <hr>
    <h6>Troubleshooting</h6>
    <p>
        If you are interested in using the local database option but running into troubles, the following is the SQL you should run with a user that has create table rights:
    <pre class="m-3"><code><?php echo str_replace("            ","",$module->createLogTableSql()) ?></code></pre>
    </p>
    <hr>

    <h5>Cumulative API Request Results</h5>
    <p class="d-inline">Query results by </p>
    <select class ="d-inline" id = "partition">
        <option value = 'HOUR'>Hour</option>
        <option value = "DAY">Day</option>
        <option value = "WEEK">Week</option>
        <option value = "MONTH">Month</option>
        <option value= "YEAR">Year</option>
        <option selected = "selected" value ="ALL">All-time</option>
    </select>
    <br>
    <br>

    <table class="dataTable" >
        <thead>
        <tr>
            <th scope="col">Project ID</th>
            <th scope="col">Included IPs</th>
            <th scope="col">Duration</th>
            <th scope="col">Pass</th>
            <th scope="col">Reject</th>
            <th scope="col">Error</th>
        </tr>
        </thead>
    </table>

    <input type="hidden" id="ApiWhitelistEndpoint" value="<?php echo $module->getUrl('routes.php'); ?>" class="hidden"/>

</div>

