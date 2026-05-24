package api

import (
	"encoding/json"

	"github.com/wheelsdown/spivot-server/internal/platform/buildinfo"
)

const openCaravanDraftVersion = "draft-0"

// ServerPolicySnapshot describes the policy snapshot advertised by this server.
type ServerPolicySnapshot struct {
	// ID is the server-local policy snapshot identifier.
	ID string `json:"id"`
	// Hash is the content hash of the canonical policy document.
	Hash string `json:"policy_hash"`
	// CreatedTime is the RFC3339 UTC time when the snapshot was first recorded.
	CreatedTime string `json:"created_time"`
	// Document is the canonical JSON policy document.
	Document json.RawMessage `json:"document"`
}

// ServerPolicyDocument is the default in-band policy advertised by Spivot
// Server until operator-configurable policy documents are added.
type ServerPolicyDocument struct {
	// Version identifies this policy document schema.
	Version string `json:"version"`
	// Registration describes how users join this server.
	Registration RegistrationPolicy `json:"registration"`
	// Journeys describes the journey behavior the server supports.
	Journeys JourneyPolicy `json:"journeys"`
	// Data describes privacy and persistence behavior.
	Data DataPolicy `json:"data"`
}

// RegistrationPolicy describes server-level account onboarding behavior.
type RegistrationPolicy struct {
	// Mode identifies the registration model.
	Mode string `json:"mode"`
	// InviteProvenanceRequired indicates whether invitation chains are retained.
	InviteProvenanceRequired bool `json:"invite_provenance_required"`
}

// JourneyPolicy describes server-level journey behavior.
type JourneyPolicy struct {
	// Visibility identifies the supported journey visibility model.
	Visibility string `json:"visibility"`
	// InviteLinks indicates whether journeys can create shareable invite links.
	InviteLinks bool `json:"invite_links"`
	// InviteUseLimits indicates whether invite use counts are supported.
	InviteUseLimits bool `json:"invite_use_limits"`
	// DeletionTimeImmutable indicates whether journey deletion time is immutable
	// after creation.
	DeletionTimeImmutable bool `json:"deletion_time_immutable"`
}

// DataPolicy describes data retention and republication behavior.
type DataPolicy struct {
	// RetentionControl describes how retained data deletion is selected.
	RetentionControl string `json:"retention_control"`
	// ProfileRepublication indicates whether profile data is republished to
	// fellow journey participants.
	ProfileRepublication bool `json:"profile_republication"`
	// ImageResourceCache indicates whether uploaded image resources are cached
	// and served by this server.
	ImageResourceCache bool `json:"image_resource_cache"`
}

type serverInfoResponse struct {
	Name           string               `json:"name"`
	PublicURL      string               `json:"public_url,omitempty"`
	Implementation implementationInfo   `json:"implementation"`
	Protocol       protocolInfo         `json:"protocol"`
	Capabilities   serverCapabilities   `json:"capabilities"`
	Policy         ServerPolicySnapshot `json:"policy"`
}

type implementationInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

type protocolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type serverCapabilities struct {
	Registration registrationCapabilities `json:"registration"`
	Journeys     journeyCapabilities      `json:"journeys"`
	Data         dataCapabilities         `json:"data"`
}

type registrationCapabilities struct {
	Mode string `json:"mode"`
}

type journeyCapabilities struct {
	InviteOnly          bool `json:"invite_only"`
	InviteLinks         bool `json:"invite_links"`
	InviteUseLimits     bool `json:"invite_use_limits"`
	DeletionTimePerItem bool `json:"deletion_time_per_item"`
}

type dataCapabilities struct {
	SQLiteStorage       bool `json:"sqlite_storage"`
	TelemetryStorage    bool `json:"telemetry_storage"`
	ImageResourceUpload bool `json:"image_resource_upload"`
}

// DefaultServerPolicyDocument returns the built-in policy document used until
// operator-managed policy configuration lands.
func DefaultServerPolicyDocument() ServerPolicyDocument {
	return ServerPolicyDocument{
		Version: "spivot-server-policy/v1alpha1",
		Registration: RegistrationPolicy{
			Mode:                     "invite_only",
			InviteProvenanceRequired: true,
		},
		Journeys: JourneyPolicy{
			Visibility:            "invite_only",
			InviteLinks:           false,
			InviteUseLimits:       true,
			DeletionTimeImmutable: true,
		},
		Data: DataPolicy{
			RetentionControl:     "journey_deletion_time",
			ProfileRepublication: false,
			ImageResourceCache:   false,
		},
	}
}

func (s *Server) serverInfo() serverInfoResponse {
	return serverInfoResponse{
		Name:      "Spivot Server",
		PublicURL: s.publicURLString(),
		Implementation: implementationInfo{
			Name:      "spivot-server",
			Version:   buildinfo.Version,
			Commit:    buildinfo.GitCommit,
			BuildTime: buildinfo.BuildTime,
		},
		Protocol: protocolInfo{
			Name:    "OpenCaravan",
			Version: openCaravanDraftVersion,
		},
		Capabilities: serverCapabilities{
			Registration: registrationCapabilities{
				Mode: "invite_only",
			},
			Journeys: journeyCapabilities{
				InviteOnly:          true,
				InviteLinks:         false,
				InviteUseLimits:     true,
				DeletionTimePerItem: true,
			},
			Data: dataCapabilities{
				SQLiteStorage:       true,
				TelemetryStorage:    false,
				ImageResourceUpload: false,
			},
		},
		Policy: s.cfg.PolicySnapshot,
	}
}
