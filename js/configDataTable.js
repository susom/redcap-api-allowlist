$(document).ready(() => init());

const init = () => {
    let url = $('#ApiWhitelistEndpoint').val();
    var docTable = $('.dataTable').DataTable({
        autoWidth: false, //during pagination this will revert back to default row width
        ajax: {
            "url": url,
            "type": "POST",
            "data": function(){
               return {filter : $('#partition option:selected').attr('value')};
            }
        },
    });

    bindProperties();
}

const bindProperties = () => {
    $('#partition').on('change', function(){
        $('.dataTable').DataTable().ajax.reload();
    });
}
