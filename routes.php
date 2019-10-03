<?php
namespace Stanford\ApiWhitelist;

/** @var \Stanford\ApiWhitelist\ApiWhitelist $module */

/**
 * AJAX endpoint for datatable on Config page
 *
 * @returns list of items formatted for datatable
 */
if(isset($_POST)){
    $timePartition = $_POST['filter'];
    if(isset($timePartition)){
        $payload = $module->fetchDataTableInfo($timePartition);
        echo json_encode($payload);
    } else {
        $module->emLog('DataTables has returned an empty filter response');

    }
}

