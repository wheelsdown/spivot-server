// Package storage owns database schema metadata for Spivot Server.
//
// The first schema mirrors OpenCaravan protocol concepts directly: servers,
// accounts, devices, vehicles, journeys, invites, participants, segments, and
// position telemetry. Runtime storage uses SQLite with embedded migrations so
// the running binary owns the schema it applies.
package storage
