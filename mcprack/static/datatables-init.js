// Turns every <table class="datatable"> into a DataTables listing
// (search, sort, paging). Per-table options come from data attributes:
//   data-dt-paging="false"      no paging
//   data-dt-page-length="50"    rows per page
//   data-dt-order="none"        keep server order (default: first column asc)
// Column options come from <th data-orderable="false" data-searchable="false">.
// External file: CSP script-src 'self' forbids inline scripts.
(function () {
  if (!window.jQuery || !jQuery.fn.DataTable) { return; }
  jQuery(function ($) {
    var cfg = document.getElementById('dt-i18n');
    var t = cfg ? cfg.dataset : {};
    var language = {
      search: t.search || 'Search:',
      lengthMenu: t.lengthMenu || 'Show _MENU_ rows',
      info: t.info || '_START_–_END_ of _TOTAL_',
      infoEmpty: t.infoEmpty || '0 rows',
      infoFiltered: t.infoFiltered || '(filtered from _MAX_)',
      zeroRecords: t.zeroRecords || 'No matching rows',
      paginate: {
        first: '«', last: '»',
        previous: t.previous || 'Previous', next: t.next || 'Next'
      }
    };

    $('table.datatable').each(function () {
      var $table = $(this);
      // An empty listing renders one colspan "nothing here" row, which
      // DataTables cannot parse — leave such tables as plain HTML.
      if ($table.find('tbody td[colspan]').length) { return; }

      var d = $table.data();
      var opts = {
        language: language,
        autoWidth: false,
        paging: d.dtPaging !== false,
        pageLength: d.dtPageLength || 25,
        lengthMenu: [10, 25, 50, 100]
      };
      if (d.dtOrder === 'none') { opts.order = []; }
      var rows = $table.find('tbody tr').length;
      if (rows <= 10 && !d.dtPageLength) {
        opts.lengthChange = false;
        opts.paging = false;
        opts.info = false;
      }
      $table.DataTable(opts);
    });
  });
})();
