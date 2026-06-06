# Traffic Timeline Evidence/YARA Integration Log - 2026-06-06

## Summary

Traffic Timeline was extended from a traffic-only peak chart into an Evidence/YARA-aware analysis timeline. The UI keeps the current traffic peak chart and traffic event track, then adds positioned Evidence/YARA markers, Community YARA badges, and summary counters for positioned and unplaced evidence.

The integration remains honest about scope: topology, protocol, conversation, and talker cards still show global statistics until backend time-window recomputation exists.

## Backend

- `model.ThreatHit` now carries `metadata` for YARA rule origin information.
- `model.EvidenceRecord` now carries `metadata` through `/api/evidence`.
- YARA rule metadata parsing supports `rule_pack`, `rule_origin`, `rule_source`, and `community_rule`.
- YARA hits preserve rule origin/source metadata when converted into unified evidence.
- Community YARA identification covers `community_rule=true`, `Neo23x0/signature-base`, `signature-base`, and `community` origin/source hints.

## Frontend

- Added timeline Evidence/YARA derivation for timestamped `UnifiedEvidenceRecord` items.
- Added an Evidence/YARA timeline track with severity markers and `COMMUNITY` badges.
- Extended Timeline Summary with Evidence, YARA, Community YARA, and unplaced evidence counts.
- Traffic Graph loads hunting evidence and passes it into the timeline panel.
- Untimed evidence is counted as unplaced instead of being fabricated onto timeline points.

## Verification

- `cd backend && go test ./internal/engine -run "Test.*Yara|Test.*YARA|TestGatherEvidence" -count=1`
- `cd backend && go test ./internal/transport -run "Test.*Evidence|Test.*Runtime|Test.*Yara|Test.*YARA" -count=1`
- `cd backend && go test ./...`
- `cd frontend && pnpm run test:run -- TrafficGraph trafficTimeline trafficMapper evidenceMapper`
- `cd frontend && pnpm run typecheck`
- `cd frontend && pnpm run lint`
- `cd frontend && pnpm run build`

## Known Limitations

- Timeline Evidence placement currently uses explicit evidence metadata timestamps.
- PacketID-to-time placement is future work unless a stable packet-time index is exposed.
- Time-window topology/protocol/conversation recomputation remains future backend work.
