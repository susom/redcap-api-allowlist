var ApiWhitelist = ApiWhitelist || {};

ApiWhitelist.config = function() {

    // Remove two fields that don't apply in config for this module
    $('tr[field="enabled"]').addClass('hidden');
    $('tr[field="discoverable-in-project"]').addClass('hidden');


    // Display configuration errors a little differently
    let errors_tr = $('tr[field="configuration-validation-errors"]');
    //$('input', errors_tr).remove();
    let errors = JSON.parse($('input', errors_tr).val());

    $.each(errors, function(i, e) {
        errors_tr.after(
            $('<tr/>').append(
                $('<td colspan="3">').append(
                    $('<div/>').addClass('alert alert-danger text-center').html(e)
                )
            )
        );
        console.log(i,e);
    });

    setTimeout(function() { $('tr[field="configuration-validation-errors"]').hide() }, 100);

}

