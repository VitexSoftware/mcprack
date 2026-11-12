(function () {
  document.addEventListener('DOMContentLoaded', function () {
    var form = document.getElementById('server-selection-form');
    var table = document.getElementById('server-selection-table');
    if (!form || !table || !window.jQuery || !jQuery.fn.DataTable) { return; }

    form.addEventListener('submit', function () {
      var dataTable = jQuery(table).DataTable();
      dataTable.$('input[name="server_id"]:checked:not(:disabled)', {
        page: 'all',
        search: 'none'
      }).each(function () {
        var hidden = document.createElement('input');
        hidden.type = 'hidden';
        hidden.name = 'server_id';
        hidden.value = this.value;
        form.appendChild(hidden);
        this.disabled = true;
      });
    });
  });
})();