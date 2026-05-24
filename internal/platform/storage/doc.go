// Package storage owns database schema metadata for Spivot Server.
//
// The first schema mirrors OpenCaravan protocol concepts directly: servers,
// accounts, devices, vehicles, journeys, invites, participants, segments, and
// position telemetry. Runtime database wiring will live beside this package
// once the project commits to a concrete driver.
package storage
