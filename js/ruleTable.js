//Script for managing the functionality of the second page of dataTables
$(document).ready(() => init());

const init = () => {
    let url = $('#ApiWhitelistEndpoint').val();
    var ruleTable = $('.dataTable-record').DataTable({
        autoWidth: false, //during pagination this will revert back to default row width
        ajax: {
            "url": url,
            "type": "POST",
            "data": function(){
                return {
                    task: 'ruleTable', //task is used to distinguish between tables @ php endpoint
                    filter : $('#partition option:selected').attr('value') //filter changes database call on each alteration
                };
            }
        },
    });

    var notificationTable = $('.dataTable-notification').DataTable({
        autoWidth: false,
        ajax: {
            "url": url,
            "type": "POST",
            "data": function(){
                return {
                    task: 'notificationTable',
                    filter : $('#partition-notification option:selected').attr('value')
                };
            }
        },
        order: [[0, 'desc']]
    });

    bindProperties();
}

const bindProperties = () => {
    $('#partition').on('change', function(){
        $('.dataTable-record').DataTable().ajax.reload();
    });
    $('#partition-notification').on('change', function(){
        $('.dataTable-notification').DataTable().ajax.reload();
    });
}
