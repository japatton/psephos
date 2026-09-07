import { test } from 'node:test';
import assert from 'node:assert';
import { osFamily } from '../store/characterization.js';

/*
  Field-gap acknowledgement is scoped to the run. On a run that mixes OS
  families, acknowledging "shell not collected" covers Windows hosts, where the
  field is meaningless, as well as Linux hosts, where its absence is a real gap
  — so a genuine gap and a non-gap are silenced by one click. It errs toward
  silence rather than false alarms, which is the safer direction, but it is
  silence the operator did not knowingly choose.

  The store cannot fix that on its own. What it can do is stop the mix being
  invisible, which is what this classifies.
*/

test('the families that actually appear in an estate are recognised', () => {
  for (const os of ['Windows Server 2019', 'Windows 11 Pro', 'win10', 'Microsoft Windows']) {
    assert.equal(osFamily(os), 'windows', os);
  }
  for (const os of ['Ubuntu 22.04', 'Debian 12', 'RHEL 8', 'CentOS 7', 'Linux', 'Alpine']) {
    assert.equal(osFamily(os), 'linux', os);
  }
});

test('network gear is its own family, not an unknown', () => {
  for (const os of ['Cisco IOS', 'IOS-XE', 'JunOS', 'PAN-OS', 'FortiOS']) {
    assert.equal(osFamily(os), 'network', os);
  }
});

/*
  An unrecorded OS is the common case on a discovered host, and guessing one is
  exactly the mistake the terrain loader refuses to make. It reports unknown and
  says so.
*/
test('an absent or unrecognised OS is unknown rather than guessed', () => {
  for (const os of [null, '', '   ', 'N/A', 'appliance', 'ESXi-ish thing']) {
    assert.equal(osFamily(os), 'unknown', String(os));
  }
});

test('classification does not depend on case or surrounding words', () => {
  assert.equal(osFamily('  MICROSOFT WINDOWS SERVER 2016 STANDARD  '), 'windows');
  assert.equal(osFamily('server running ubuntu linux'), 'linux');
});
