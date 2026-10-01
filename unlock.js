'use strict';
const $ = id => document.getElementById(id);
const bytes = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
let reports = [];

function showReport(name) {
  const report = reports.find(item => item.name === name);
  if (!report) return;
  $('report').value = name;
  const doc = new DOMParser().parseFromString(report.html, 'text/html');
  doc.querySelectorAll('script,iframe,object,embed,base,link,form,meta[http-equiv]').forEach(el => el.remove());
  for (const el of doc.querySelectorAll('*')) {
    for (const attr of [...el.attributes]) {
      if (/^on/i.test(attr.name) || ['srcdoc', 'src', 'srcset', 'action'].includes(attr.name)) el.removeAttribute(attr.name);
    }
  }
  doc.querySelectorAll('a').forEach(a => {
    const href = a.getAttribute('href') || '';
    if (/^https:\/\//i.test(href)) { a.target = '_blank'; a.rel = 'noopener noreferrer'; }
    else if (href.startsWith('#')) { /* Keep document anchors. */ }
    else {
      const filename = href.split('#')[0].split('/').pop();
      if (reports.some(item => item.name === filename)) {
        a.dataset.report = filename; a.href = '#'; a.removeAttribute('target');
      } else { a.removeAttribute('href'); a.title = 'Referência não incluída nesta publicação'; }
    }
  });
  const csp = doc.createElement('meta');
  csp.httpEquiv = 'Content-Security-Policy';
  csp.content = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'";
  doc.head.prepend(csp);
  $('viewer').srcdoc = '<!doctype html>' + doc.documentElement.outerHTML;
}
$('viewer').addEventListener('load', () => {
  $('viewer').contentDocument?.querySelectorAll('a[data-report]').forEach(a => {
    a.addEventListener('click', event => { event.preventDefault(); showReport(a.dataset.report); });
  });
});
$('report').addEventListener('change', event => showReport(event.target.value));
$('unlock-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('unlock').disabled = true;
  $('message').textContent = 'Abrindo…';
  try {
    if (!crypto.subtle) throw new Error('Use HTTPS ou localhost para abrir esta página.');
    const response = await fetch('payload.json', { cache: 'no-store' });
    if (!response.ok) throw new Error('Não foi possível carregar os relatórios. Tente novamente.');
    const envelope = await response.json();
    if (envelope.version !== 1 || envelope.iterations !== 600000) throw new Error('Formato não reconhecido.');
    const password = new TextEncoder().encode($('password').value);
    $('password').value = '';
    const material = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveKey']);
    password.fill(0);
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: bytes(envelope.salt),
      iterations: envelope.iterations, hash: 'SHA-256' }, material,
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(envelope.iv) }, key, bytes(envelope.ciphertext));
    reports = JSON.parse(new TextDecoder().decode(plaintext)).reports;
    new Uint8Array(plaintext).fill(0);
    if (!Array.isArray(reports) || !reports.length) throw new Error('Nenhum relatório disponível.');
    $('report').replaceChildren(...reports.map(report => new Option(report.name.replace('.html', ''), report.name)));
    $('locked').hidden = true; $('opened').hidden = false;
    $('message').textContent = '';
    showReport(reports[0].name);
  } catch (error) {
    $('message').textContent = error.name === 'OperationError'
      ? 'Senha incorreta ou arquivo danificado.' : 'Não foi possível abrir. Confira a conexão e tente novamente.';
  } finally { $('unlock').disabled = false; }
});
$('lock').addEventListener('click', () => {
  reports = [];
  $('viewer').removeAttribute('srcdoc');
  $('report').replaceChildren(); $('password').value = '';
  $('opened').hidden = true; $('locked').hidden = false; $('password').focus();
});
window.addEventListener('pagehide', () => $('lock').click());
