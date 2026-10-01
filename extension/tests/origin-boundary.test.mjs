import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreResponse, scoreNavigation } from '../src/background/verifier.js';

for (const [loginUrl, destination] of [
  ['https://login.audit.co.uk/login', 'https://attacker.other.co.uk/dashboard'],
  ['https://alice.github.io/login', 'https://bob.github.io/dashboard'],
  ['http://localhost:3000/login', 'http://localhost:4000/dashboard'],
  ['https://login.example.com/login', 'https://app.example.com/dashboard'],
]) {
  test(`another origin cannot verify ${loginUrl}`, () => {
    const entry = { loginUrl };
    assert.equal(scoreNavigation(entry, { url: destination, transitionQualifiers: ['server_redirect'] }).points, 0);
    assert.equal(scoreResponse(entry, {
      url: loginUrl, statusCode: 303, responseHeaders: [{ name: 'Location', value: destination }]
    }).points, 0);
    const foreign = scoreResponse(entry, { url: destination, statusCode: 401 });
    assert.equal(foreign.rejected, false);
  });
}

test('same-origin successful navigation still verifies', () => {
  assert.ok(scoreNavigation({ loginUrl: 'https://app.example.com/login' }, {
    url: 'https://app.example.com/dashboard', transitionQualifiers: ['server_redirect']
  }).points >= 3);
});
