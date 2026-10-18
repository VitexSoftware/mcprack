// Stepper for the admin server form: shows one .form-card[data-step] at a
// time, validates the current step before advancing, and validates every
// step before submit (jumping to the first invalid one). Without JS the nav
// stays hidden and all cards remain visible — the form degrades to the
// classic single-page layout. External file because the CSP's script-src
// 'self' blocks inline <script> blocks (see confirm-submit.js).
document.addEventListener('DOMContentLoaded', function () {
  var nav = document.getElementById('form-stepper');
  if (!nav) {
    return;
  }
  var form = nav.closest('form');
  var cards = Array.prototype.slice.call(form.querySelectorAll('.form-card[data-step]'));
  if (cards.length < 2) {
    return;
  }
  var actions = form.querySelector('.form-actions');
  var indicators = Array.prototype.slice.call(nav.querySelectorAll('.stepper-step'));
  var prevBtn = nav.querySelector('[data-step-prev]');
  var nextBtn = nav.querySelector('[data-step-next]');
  var maxStep = Math.max.apply(null, cards.map(function (card) {
    return parseInt(card.dataset.step, 10);
  }));
  var current = parseInt(nav.dataset.activeStep || '1', 10);

  nav.hidden = false;

  function cardsForStep(step) {
    return cards.filter(function (card) {
      return parseInt(card.dataset.step, 10) === step;
    });
  }

  function stepIsValid(step) {
    var ok = true;
    cardsForStep(step).forEach(function (card) {
      card.querySelectorAll('input, select, textarea').forEach(function (field) {
        if (field.disabled) {
          return;
        }
        var type = (field.type || '').toLowerCase();
        if (type === 'hidden' || type === 'button' || type === 'file' || type === 'submit') {
          return;
        }
        var valid = field.checkValidity();
        field.classList.toggle('input-error', !valid);
        if (!valid) {
          ok = false;
        }
      });
      // env-rows.js flags duplicate keys / missing required values with
      // these classes; both block the step.
      if (card.querySelector('.env-row-error, .env-row-missing')) {
        ok = false;
      }
    });
    // The live name-uniqueness check (server-name-check.js) marks a taken
    // slug with .input-error — but only once its fetch resolved, so the
    // server-side re-check on save remains the enforcement.
    var nameField = form.querySelector('#name');
    if (nameField && !nameField.readOnly && nameField.classList.contains('input-error')) {
      ok = false;
    }
    return ok;
  }

  function goTo(step) {
    current = Math.min(Math.max(step, 1), maxStep);
    cards.forEach(function (card) {
      card.hidden = parseInt(card.dataset.step, 10) !== current;
    });
    if (actions) {
      actions.hidden = current !== maxStep;
    }
    indicators.forEach(function (indicator) {
      var step = parseInt(indicator.dataset.step, 10);
      indicator.classList.toggle('active', step === current);
      indicator.classList.toggle('done', step < current);
    });
    prevBtn.hidden = current === 1;
    nextBtn.hidden = current === maxStep;
    var heading = cardsForStep(current)[0].querySelector('.form-card-title');
    if (heading) {
      heading.scrollIntoView({ block: 'nearest' });
    }
  }

  prevBtn.addEventListener('click', function () {
    goTo(current - 1);
  });

  nextBtn.addEventListener('click', function () {
    if (stepIsValid(current)) {
      goTo(current + 1);
      return;
    }
    var firstInvalid = cardsForStep(current)[0].querySelector('.input-error');
    if (firstInvalid) {
      firstInvalid.focus();
    }
  });

  form.addEventListener('submit', function (event) {
    for (var step = 1; step <= maxStep; step++) {
      if (!stepIsValid(step)) {
        event.preventDefault();
        goTo(step);
        var firstInvalid = cardsForStep(step)[0].querySelector('.input-error');
        if (firstInvalid) {
          firstInvalid.focus();
        }
        return;
      }
    }
  });

  goTo(current);
});
