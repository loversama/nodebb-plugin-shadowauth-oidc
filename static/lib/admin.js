'use strict';

import { save, load } from 'settings';
import { alert } from 'alerts';

export function init() {
  load('shadowauth-oidc', $('#shadowauth-oidc-settings'));

  const saveForm = function (form) {
    save('shadowauth-oidc', form, function () {
      alert({
        type: 'success',
        alert_id: 'sso-oidc-saved',
        title: 'Settings Saved',
        message: 'Settings have been saved successfully.',
        clickfn: function () {
          socket.emit('admin.reload');
        },
      });
    });
  };

  $('#shadowauth-oidc-save').on('click', function () {
    const form = $('#shadowauth-oidc-settings');

    // Trim the fields
    form.find('input[data-trim="true"], textarea[data-trim="true"]').each(function () {
      $(this).val($.trim($(this).val()));
    });

    // Save the form without attempting to fetch the JWKS
    saveForm(form);
  });
}
