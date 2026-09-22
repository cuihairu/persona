-- Migration 013: travel mode per-identity marks.
-- travel_marked = "remove this identity's data from this device while travel
-- mode is active" (1Password "remove vaults from devices" semantics).
-- Marked identities are packed into an encrypted sidecar and deleted from the
-- vault when travel mode is entered; restored verbatim on exit (core/src/travel.rs).
ALTER TABLE identities ADD COLUMN travel_marked BOOLEAN NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_identities_travel_marked
    ON identities(travel_marked) WHERE travel_marked = 1;
