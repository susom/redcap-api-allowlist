<?php

namespace Stanford\ApiWhitelist;
/** @var \Stanford\ApiWhitelist\ApiWhitelist $module */

require APP_PATH_DOCROOT . "ControlCenter/header.php";

$module->validateSetup(); //load module data

$url = substr(APP_PATH_WEBROOT_FULL,0,-1);
$url .=  (APP_PATH_WEBROOT . 'ProjectSetup/index.php?pid=' . $module->config_pid);


?>
<script src="<?php echo $module->getUrl('js/ruleTable.js') ?>"></script>
<div>
<!--  First table for cumulative duration of API requests  -->
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

    <table class="dataTable dataTable-record" >
        <thead>
        <tr>
            <th scope="col">Rule ID</th>
            <th scope="col">Project ID (Intended recipient)</th>
            <th scope="col">Cumulative Duration</th>
        </tr>
        </thead>
    </table>


<!-- Second table for recent notifications (15m) threshold min -->
    <hr>
    <h5>Most recent notifications sent</h5>
    <p class="d-inline">Query results by </p>
    <select class ="d-inline" id = "partition-notification">
        <option value = 'HOUR'>Hour</option>
        <option value = "DAY">Day</option>
        <option value = "WEEK">Week</option>
        <option value = "MONTH">Month</option>
        <option value= "YEAR">Year</option>
        <option selected = "selected" value ="ALL">All-time</option>
    </select>
    <br>
    <br>

    <table class="dataTable dataTable-notification" >
        <thead>
        <tr>
            <th scope="col">Timestamp</th>
            <th scope="col">Project ID</th>
            <th scope="col">User</th>
        </tr>
        </thead>
    </table>

    <!--  AJAX endpoint for JS  -->
    <input type="hidden" id="ApiWhitelistEndpoint" value="<?php echo $module->getUrl('routes.php'); ?>" class="hidden"/>

</div>
