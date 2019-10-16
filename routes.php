<?php
namespace Stanford\ApiWhitelist;

/** @var \Stanford\ApiWhitelist\ApiWhitelist $module */

/**
 * AJAX endpoint for datatable on Config page
 * @params :
 *  $timepartition = ("ALL" || "YEAR" || "MONTH" || "WEEK" || "DAY" || "HOUR")
 *  $task = ("ruleTable" || "notificationTable" || "baseTable")
 * @returns list of items formatted for datatable use
 */

$timePartition = isset($_POST['filter']) ? $_POST['filter'] : null;
$task = isset($_POST['task']) ? $_POST['task'] : null;

if($task && $timePartition){
    $payload = $module->fetchDataTableInfo($task, $timePartition);
    echo json_encode($payload);
}else {
    $module->emError('AJAX request returned an empty filter or task response');
}
