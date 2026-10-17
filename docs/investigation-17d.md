# Phase 17D — Contextual Pivots and Workflow Validation

## Read-only workflow audit

The existing 17C typed lookup already opens device, scope, sensor, site, task, review, threat, perimeter, and exposure records in their existing panels. Within those panels, several IDs were visible but not actionable, so analysts still had to copy identifiers into Investigation Search or manually move through another panel. The current APIs and projections support a small set of exact-ID pivots without adding a relation or changing stored data.

| Source surface | Destination | Explicit relation | Finding | 17D decision |
| --- | --- | --- | --- | --- |
| Incident Review attribution | Site, scope, device | Review `site_id`, `scope_id`, `device_id` | Review detail already displays attribution | Implement |
| Incident Review linked evidence | Supported source detail | `evidence_type` + `evidence_id`, source status | Linked evidence list already resolves availability and stable source IDs | Implement Open evidence for available supported sources |
| Incident Review linked WEB_DETECTION | Web detection detail | `evidence_type` + `evidence_id` | No 17B destination contract | Defer |
| Task History selected detail | Sensor, site, scope | Task `sensor_id`, `site_id`, `scope_id` | All fields are in the bounded task row | Implement |
| Task History selected detail | Device | `target_device_id` | Explicit nullable target relation | Implement only when present |
| Device detail | Scope | Device `scope_id` | Explicit current scope relation where stored | Implement only when present |
| Device detail | Sensor task history | Task-history exact `device_id` filter matches `target_device_id` | Existing bounded endpoint supports the filter | Implement as a device-filtered history intent |
| Threat detection/correlation detail | Device, sensor | Stored `device_id`, `sensor_id` | Detail projection exposes explicit IDs | Implement only when present |
| Perimeter event/detection/policy correlation | Site | Stored `site_id` | Detail projection exposes site attribution | Implement only when present |
| Perimeter host correlation | Site, scope, device | Stored `site_id`, `scope_id`, `device_id` | Detail projection exposes these IDs | Implement only when present |
| External exposure/change | Scope, device, site | Stored/joined explicit scope/device/site fields | Detail projection exposes the available relations | Implement only when present |
| Source detail | Linked Incident Review | No loaded review ID or reverse link in these detail projections | Would require reverse evidence query | Defer |
| Device detail | Threat detections/correlations | Device ID exists, but current overview has no device filter or selected-record relation | Would require a new read contract | Defer |
| Device detail | Site | No direct site field on the device record | Site would require additional relationship resolution | Defer |
| Task target IP | Device | IP only when target device ID is absent | IP coincidence is not an identity relation | Not allowed |
| Hostname/IP/CIDR matches | Any entity | No explicit stored relation | Would be speculative identity or scope inference | Not allowed |

### Journey findings

- **Suspicious device/service:** Device selection opens existing ports, services, findings, and CVE details in Network Workspace. Moving to threat/correlation and review surfaces still requires a panel change and a separate lookup; there is no bounded device-filtered threat/review relation, so no reverse result list was added. The new pivots remove the ID-copy step to the device's explicit scope and a bounded task-history filter.
- **Incident Review evidence:** The analyst already opens a review and sees linked evidence type/ID and availability. `Open evidence` now opens the existing source detail for available supported evidence, removing manual ID copy. Review attribution now opens its explicitly recorded site, scope, or device.
- **Failed sensor task:** Task History already shows sensor, site, scope and optional target device. Four direct pivots now open those existing surfaces. The device action is omitted when `target_device_id` is absent.
- **Threat detection/correlation:** Detail already shows explicit device and sensor IDs. Direct pivots now open those records. A linked review cannot be shown without a reverse lookup, so it remains deferred.
- **Perimeter/exposure:** Existing selected-record details carry explicit context IDs. Available site/scope/device pivots now open those contexts; absent IDs do not produce actions. Review linkage is not present in these projections and remains deferred.

The exact number of clicks depends on which panels are already in view and whether records are on the current page. The concrete reduction is removal of manual identifier copying for the implemented pivots; no precise time or click metric is claimed.

## Implemented navigation

All pivots call the 17C App-level typed navigation dispatcher. It assigns a fresh nonce, including for repeated navigation to the same record. A narrow `SENSOR_TASK_DEVICE_FILTER` intent opens the existing Task History surface with its bounded exact `device_id` filter. It is an internal navigation intent, not a backend result type or API query expansion.

The pivots use only explicit IDs supplied by the currently selected record. No device is inferred from IP, hostname, MAC/vendor similarity, or CIDR containment. Review evidence actions are limited to available `THREAT_DETECTION`, `THREAT_CORRELATION`, `PERIMETER_DETECTION`, `PERIMETER_POLICY_CORRELATION`, `PERIMETER_HOST_CORRELATION`, and `EXTERNAL_EXPOSURE_CHANGE` records. Missing sources and WEB_DETECTION have no Open evidence action.

## Boundaries and completion

17D is read-only navigation. It adds no mutation controls, broad aggregate API, router, schema, or migration. It does not add task retry/cancel behavior, raw evidence display, reverse review search, or identity linking. Schema remains version 43. Phase 17 is complete when the bounded lookup and its existing destinations work, explicit high-value pivots remove manual ID-copy friction, and regression checks pass without inferred relationships or new mutation authority.
