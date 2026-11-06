import assert from 'node:assert/strict'
import test from 'node:test'
import {
  moduleForInvestigationKind,
  moduleFromHash,
  WORKSPACE_MODULES,
  workspaceHash,
} from '../src/services/workspaceNavigation.js'

test('module selection and direct links accept current and Phase 26B-B hashes', () => {
  assert.equal(WORKSPACE_MODULES.length, 8) // Seven workspace modules plus local operator utility.
  assert.equal(moduleFromHash('#workspace/events-analytics'), 'events-analytics')
  assert.equal(moduleFromHash('#module-overview'), 'overview')
  assert.equal(moduleFromHash('#module-remote-sensors'), 'remote-sensors')
  assert.equal(moduleFromHash('#workspace/unsupported'), 'overview')
  assert.equal(workspaceHash('operations'), '#workspace/operations')
  assert.throws(() => workspaceHash('unsupported'), TypeError)
})

test('investigation pivots map to the module containing their existing target', () => {
  assert.equal(moduleForInvestigationKind('LEGACY_EVENT'), 'events-analytics')
  assert.equal(moduleForInvestigationKind('SENSOR_TASK'), 'remote-sensors')
  assert.equal(moduleForInvestigationKind('SENSOR_TASK_DEVICE_FILTER'), 'remote-sensors')
  assert.equal(moduleForInvestigationKind('EXTERNAL_EXPOSURE_CHANGE'), 'perimeter')
  assert.equal(moduleForInvestigationKind('INCIDENT_REVIEW'), 'operations')
  assert.equal(moduleForInvestigationKind('THREAT_CORRELATION'), 'detections')
  assert.equal(moduleForInvestigationKind('DEVICE'), 'scope-discovery')
})
