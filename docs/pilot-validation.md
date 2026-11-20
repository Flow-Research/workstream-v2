# First work order: observed pilot (#138)

Status: awaiting participants. Use three new pilot users with separate test identities: sponsor, worker and independent reviewer. Start with clean browser profiles and a clean test chain. Give each participant their role, workspace URL, test wallet and a harmless sample asset. Do not give them developer RPC access or coach them through the task. An observer records where someone asks for help; an assisted step does not count as an unassisted pass.

| Role | Outcome for the participant to achieve | Evidence to record |
| --- | --- | --- |
| Sponsor | Publish a guide and release a task for the sample asset. | Elapsed time from opening the workspace to first verified receipt; receipt bookmark. |
| Worker | Claim and start the task, attach the sample and submit it. Disconnect before sending once; reconnect and recover. | Last visible status offline, recovery action, number of verified submissions. |
| Independent reviewer | Find the submission, inspect its evidence and record a decision. | Verified decision bookmark and the status perceived on return to the case. |

Repeat navigation without a mouse, with a real screen reader (record product/version), and at a 320 CSS-pixel viewport. Record whether each user can identify focus, operate the controls, perceive status changes, and recover their place after reconnect. Record actual observations, including failures. Browser automation and accessibility-tree inspections are supporting evidence only.

For each observation record: build SHA, clean setup, role alias, browser/assistive technology, task, elapsed time, expected and observed result, confusing text or control, assistance, and anonymized receipt or defect link. Never collect signing files, secrets, private uploads or personal identifiers. Link the redacted results on #138; retest blocking defects with the affected interaction before marking the pilot complete.
