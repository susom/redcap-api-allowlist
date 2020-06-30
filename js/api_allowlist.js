var ApiWhitelist = ApiWhitelist || {};

ApiWhitelist.config = function() {

    // Remove two fields that don't apply in config for this module
    $('tr[field="enabled"]').addClass('hidden');
    $('tr[field="discoverable-in-project"]').addClass('hidden');


    // Display configuration errors a little differently
    let errors_tr = $('tr[field="configuration-validation-errors"]');

    let errors = [];

    try {
        errors = JSON.parse($('input', errors_tr).val());
    } catch (err) {
        // No errors
    }

    if (errors.length) {

        let error_list = $('<ul/>').css({'margin-bottom':'0'});

        // Add errors
        $.each(errors, function(i, e) {
            error_list.append(
                $('<li/>').html(e)
            );
        });

        // Insert errors after errors_tr
        errors_tr.after(
            $('<tr/>').append(
                $('<td colspan="3">').append(
                ).append(
                    $('<div/>').addClass('alert alert-danger text-left').append(
                        $('<div><b>Configuration Errors</b></div>')
                    ).append(
                        error_list
                    )
                )
            )
        );


    }

    setTimeout(function() { $('tr[field="configuration-validation-errors"]').hide() }, 100);

}

