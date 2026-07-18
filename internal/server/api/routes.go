package api

//go:generate go run github.com/wheelsdown/spivot-server/internal/tools/openapigen

import (
	"net/http"

	"github.com/opencaravan/opencaravan-go"
)

// AuthPosture identifies which authentication layer a route demands.
// The posture is enforced at registration time by [Server.Handler] and
// projected into the generated OpenAPI document as the operation's
// x-spivot-auth extension, so the documented contract and the enforced
// contract derive from the same table entry and cannot drift.
type AuthPosture string

const (
	// AuthPublic routes accept unauthenticated requests.
	AuthPublic AuthPosture = "public"
	// AuthIdentity routes require a client certificate that resolves
	// to an enrolled client app ([middleware.RequireIdentity]).
	AuthIdentity AuthPosture = "identity"
	// AuthSession routes require an Authorization: Macaroon session
	// token ([middleware.RequireSession]) whose caveats authorize
	// [Route.SessionAction] against the journey named by
	// [Route.JourneyPathParam].
	AuthSession AuthPosture = "session"
)

// Route describes one native API route: the mux registration pattern,
// the machine-readable OpenAPI operation metadata, and the auth
// posture applied at the registration site. The route table returned
// by [Routes] is the single source of truth for the HTTP surface —
// [Server.Handler] registers the mux from it and the openapigen tool
// (internal/tools/openapigen) projects openapi.json/openapi.yaml
// from it.
type Route struct {
	// Method is the HTTP method the route is registered under.
	Method string
	// Path is the net/http ServeMux pattern path, including any
	// {wildcard} segments (for example "/v1/journeys/{id}").
	Path string
	// OperationID is the stable OpenAPI operationId. Client
	// generators derive method names from it; treat a change as an
	// API-breaking event.
	OperationID string
	// Summary is the one-line OpenAPI operation summary.
	Summary string
	// Tags are the OpenAPI tags grouping the operation in rendered
	// documentation. Every route carries at least one.
	Tags []string
	// Auth is the authentication posture enforced for the route.
	Auth AuthPosture
	// SessionAction is the macaroon action= caveat an AuthSession
	// route demands. Zero for other postures.
	SessionAction opencaravan.SessionAction
	// JourneyPathParam names the path wildcard whose value must
	// match the macaroon's journey= caveat on an AuthSession route.
	// Zero for other postures.
	JourneyPathParam string
	// Request is a zero value of the request-body contract type,
	// nil when the operation takes no body. The generator walks it
	// with reflection to emit the requestBody schema.
	Request any
	// Response is a zero value of the success-response contract
	// type, nil when success carries no body (204).
	Response any
	// SuccessStatuses lists every success status the handler can
	// return, primary first. All share the Response schema.
	SuccessStatuses []int
	// handler binds the route to a server instance at registration
	// time. Unexported: tooling consumes the metadata above, only
	// [Server.Handler] needs the binding.
	handler func(*Server) http.Handler
}

// Route tags. One per domain cluster; the values become OpenAPI tags,
// so renames are documentation-breaking (they reorganize the rendered
// sidebar and any deep links into it).
const (
	tagSystem          = "System"
	tagIdentity        = "Identity"
	tagJourneys        = "Journeys"
	tagJourneyVehicles = "Journey Vehicles"
	tagGarages         = "Garages"
)

// bindHandler adapts a Server method expression to the route table's
// binder shape so table entries stay one line per route.
func bindHandler(m func(*Server, http.ResponseWriter, *http.Request)) func(*Server) http.Handler {
	return func(s *Server) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m(s, w, r) })
	}
}

// Routes returns the native API route table. The returned slice is
// freshly allocated on every call; callers may reorder or filter it
// freely. Tooling (openapigen, the route-coverage tests) consumes the
// exported metadata; [Server.Handler] additionally uses the unexported
// handler binding, so entries constructed outside this package cannot
// be registered.
func Routes() []Route {
	return []Route{
		{
			Method:          http.MethodGet,
			Path:            "/",
			OperationID:     "serverRoot",
			Summary:         "Server identity banner",
			Tags:            []string{tagSystem},
			Auth:            AuthPublic,
			Response:        RootResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleRoot),
		},
		{
			Method:          http.MethodGet,
			Path:            "/health",
			OperationID:     "healthCheck",
			Summary:         "Liveness probe",
			Tags:            []string{tagSystem},
			Auth:            AuthPublic,
			Response:        HealthResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleHealth),
		},
		{
			Method:          http.MethodGet,
			Path:            "/readyz",
			OperationID:     "readinessCheck",
			Summary:         "Readiness probe",
			Tags:            []string{tagSystem},
			Auth:            AuthPublic,
			Response:        ReadinessResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleReady),
		},
		{
			Method:          http.MethodGet,
			Path:            "/v1/server",
			OperationID:     "serverInfo",
			Summary:         "Server capabilities and policy snapshot",
			Tags:            []string{tagSystem},
			Auth:            AuthPublic,
			Response:        ServerInfoResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleServerInfo),
		},
		{
			Method:          http.MethodGet,
			Path:            "/v1/version",
			OperationID:     "serverVersion",
			Summary:         "Build and runtime version details",
			Tags:            []string{tagSystem},
			Auth:            AuthPublic,
			Response:        VersionResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleVersion),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/client-apps/enroll",
			OperationID:     "clientAppEnroll",
			Summary:         "Enroll a client app with a server-registration invite",
			Tags:            []string{tagIdentity},
			Auth:            AuthPublic,
			Request:         opencaravan.ClientAppEnrollmentRequest{},
			Response:        opencaravan.ClientAppEnrollmentResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleClientAppEnroll),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/sessions",
			OperationID:     "sessionCreate",
			Summary:         "Issue a session macaroon",
			Tags:            []string{tagIdentity},
			Auth:            AuthIdentity,
			Request:         opencaravan.SessionRequest{},
			Response:        opencaravan.SessionResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleSessionCreate),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/client-apps/invites",
			OperationID:     "clientAppInviteCreate",
			Summary:         "Mint a server-registration invite",
			Tags:            []string{tagIdentity},
			Auth:            AuthIdentity,
			Request:         ClientAppInviteCreateRequest{},
			Response:        ClientAppInviteResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleClientAppInviteCreate),
		},
		{
			Method:          http.MethodGet,
			Path:            "/v1/client-apps/invites",
			OperationID:     "clientAppInviteList",
			Summary:         "List invites minted by the caller",
			Tags:            []string{tagIdentity},
			Auth:            AuthIdentity,
			Response:        ClientAppInviteListResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleClientAppInviteList),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/journeys",
			OperationID:     "journeyCreate",
			Summary:         "Create a journey",
			Tags:            []string{tagJourneys},
			Auth:            AuthIdentity,
			Request:         JourneyCreateRequest{},
			Response:        JourneyResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleJourneyCreate),
		},
		{
			Method:           http.MethodGet,
			Path:             "/v1/journeys/{id}",
			OperationID:      "journeyGet",
			Summary:          "Fetch a journey",
			Tags:             []string{tagJourneys},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionJourneyRead,
			JourneyPathParam: "id",
			Response:         JourneyResponse{},
			SuccessStatuses:  []int{http.StatusOK},
			handler:          bindHandler((*Server).handleJourneyGet),
		},
		{
			Method:           http.MethodPost,
			Path:             "/v1/journeys/{id}/telemetry",
			OperationID:      "telemetryBatchRecord",
			Summary:          "Record a telemetry batch",
			Tags:             []string{tagJourneys},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionTelemetryWrite,
			JourneyPathParam: "id",
			Request:          TelemetryBatchRequest{},
			Response:         TelemetryBatchResponse{},
			SuccessStatuses:  []int{http.StatusAccepted},
			handler:          bindHandler((*Server).handleJourneyTelemetry),
		},
		{
			Method:           http.MethodPost,
			Path:             "/v1/journeys/{id}/vehicles",
			OperationID:      "journeyVehicleCreate",
			Summary:          "Upload a journey vehicle bundle",
			Tags:             []string{tagJourneyVehicles},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionJourneyWrite,
			JourneyPathParam: "id",
			Request:          JourneyVehicleCreateRequest{},
			Response:         JourneyVehicleResponse{},
			SuccessStatuses:  []int{http.StatusCreated},
			handler:          bindHandler((*Server).handleJourneyVehicleCreate),
		},
		{
			Method:           http.MethodGet,
			Path:             "/v1/journeys/{id}/vehicles",
			OperationID:      "journeyVehicleList",
			Summary:          "List journey vehicles",
			Tags:             []string{tagJourneyVehicles},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionJourneyRead,
			JourneyPathParam: "id",
			Response:         JourneyVehicleListResponse{},
			SuccessStatuses:  []int{http.StatusOK},
			handler:          bindHandler((*Server).handleJourneyVehicleList),
		},
		{
			Method:           http.MethodGet,
			Path:             "/v1/journeys/{id}/vehicles/{vid}",
			OperationID:      "journeyVehicleGet",
			Summary:          "Fetch a journey vehicle",
			Tags:             []string{tagJourneyVehicles},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionJourneyRead,
			JourneyPathParam: "id",
			Response:         JourneyVehicleResponse{},
			SuccessStatuses:  []int{http.StatusOK},
			handler:          bindHandler((*Server).handleJourneyVehicleGet),
		},
		{
			Method:           http.MethodPost,
			Path:             "/v1/journeys/{id}/vehicles/{vid}/acl-revisions",
			OperationID:      "journeyVehicleACLAppend",
			Summary:          "Append a signed vehicle ACL revision",
			Tags:             []string{tagJourneyVehicles},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionJourneyWrite,
			JourneyPathParam: "id",
			Request:          opencaravan.VehicleACL{},
			Response:         JourneyVehicleACLRevisionResponse{},
			SuccessStatuses:  []int{http.StatusCreated},
			handler:          bindHandler((*Server).handleJourneyVehicleACLAppend),
		},
		{
			Method:           http.MethodPost,
			Path:             "/v1/journeys/{id}/vehicles/{vid}/revisions",
			OperationID:      "journeyVehicleRevisionAppend",
			Summary:          "Append a signed vehicle metadata revision",
			Tags:             []string{tagJourneyVehicles},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionJourneyWrite,
			JourneyPathParam: "id",
			Request:          opencaravan.Vehicle{},
			Response:         JourneyVehicleRevisionResponse{},
			SuccessStatuses:  []int{http.StatusCreated},
			handler:          bindHandler((*Server).handleJourneyVehicleRevisionAppend),
		},
		{
			Method:           http.MethodPost,
			Path:             "/v1/journeys/{id}/vehicles/{vid}/driver-attestations",
			OperationID:      "driverAttestationRecord",
			Summary:          "Record a signed driver attestation",
			Tags:             []string{tagJourneyVehicles},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionJourneyWrite,
			JourneyPathParam: "id",
			Request:          opencaravan.DriverAttestation{},
			Response:         DriverAttestationResponse{},
			SuccessStatuses:  []int{http.StatusCreated, http.StatusOK},
			handler:          bindHandler((*Server).handleDriverAttestationRecord),
		},
		{
			Method:           http.MethodGet,
			Path:             "/v1/journeys/{id}/vehicles/{vid}/driver-attestations",
			OperationID:      "driverAttestationList",
			Summary:          "List driver attestations",
			Tags:             []string{tagJourneyVehicles},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionJourneyRead,
			JourneyPathParam: "id",
			Response:         DriverAttestationListResponse{},
			SuccessStatuses:  []int{http.StatusOK},
			handler:          bindHandler((*Server).handleDriverAttestationList),
		},
		{
			Method:           http.MethodGet,
			Path:             "/v1/journeys/{id}/vehicles/{vid}/current-driver",
			OperationID:      "currentDriverGet",
			Summary:          "Resolve the driver in effect at a point in time",
			Tags:             []string{tagJourneyVehicles},
			Auth:             AuthSession,
			SessionAction:    opencaravan.SessionActionJourneyRead,
			JourneyPathParam: "id",
			Response:         CurrentDriverResponse{},
			SuccessStatuses:  []int{http.StatusOK},
			handler:          bindHandler((*Server).handleCurrentDriver),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/garages",
			OperationID:     "garageCreate",
			Summary:         "Create a garage from a signed Garage payload",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Request:         opencaravan.Garage{},
			Response:        GarageResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleGarageCreate),
		},
		{
			Method:          http.MethodGet,
			Path:            "/v1/garages",
			OperationID:     "garageList",
			Summary:         "List the caller's garages",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Response:        GarageListResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleGarageList),
		},
		{
			Method:          http.MethodGet,
			Path:            "/v1/garages/{id}",
			OperationID:     "garageGet",
			Summary:         "Fetch a garage",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Response:        GarageResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleGarageGet),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/garages/{id}/revisions",
			OperationID:     "garageRevisionAppend",
			Summary:         "Append a signed garage revision",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Request:         opencaravan.Garage{},
			Response:        GarageRevisionAppendResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleGarageRevisionAppend),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/garages/{id}/ownership-acceptances",
			OperationID:     "garageOwnershipAccept",
			Summary:         "Accept garage ownership",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Request:         opencaravan.GarageOwnershipAcceptance{},
			Response:        GarageOwnershipAcceptanceResponse{},
			SuccessStatuses: []int{http.StatusCreated, http.StatusOK},
			handler:         bindHandler((*Server).handleGarageOwnershipAccept),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/garages/{id}/vehicles",
			OperationID:     "garageVehicleCreate",
			Summary:         "Add a signed garage vehicle",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Request:         opencaravan.GarageVehicle{},
			Response:        GarageVehicleResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleGarageVehicleCreate),
		},
		{
			Method:          http.MethodGet,
			Path:            "/v1/garages/{id}/vehicles",
			OperationID:     "garageVehicleList",
			Summary:         "List garage vehicles",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Response:        GarageVehicleListResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleGarageVehicleList),
		},
		{
			Method:          http.MethodGet,
			Path:            "/v1/garages/{id}/vehicles/{vid}",
			OperationID:     "garageVehicleGet",
			Summary:         "Fetch a garage vehicle",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Response:        GarageVehicleResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleGarageVehicleGet),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/garages/{id}/vehicles/{vid}/revisions",
			OperationID:     "garageVehicleRevisionAppend",
			Summary:         "Append a signed garage vehicle revision",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Request:         opencaravan.GarageVehicle{},
			Response:        GarageVehicleResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleGarageVehicleRevisionAppend),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/garages/{id}/invites",
			OperationID:     "garageInviteCreate",
			Summary:         "Mint a garage invite",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Request:         GarageInviteCreateRequest{},
			Response:        GarageInviteResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleGarageInviteCreate),
		},
		{
			Method:          http.MethodGet,
			Path:            "/v1/garages/{id}/invites",
			OperationID:     "garageInviteList",
			Summary:         "List garage invites",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Response:        GarageInviteListResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleGarageInviteList),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/garages/{id}/invites/{inviteId}/revoke",
			OperationID:     "garageInviteRevoke",
			Summary:         "Revoke a garage invite",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			SuccessStatuses: []int{http.StatusNoContent},
			handler:         bindHandler((*Server).handleGarageInviteRevoke),
		},
		{
			Method:          http.MethodPost,
			Path:            "/v1/garage-invites/redeem",
			OperationID:     "garageInviteRedeem",
			Summary:         "Redeem a garage invite token",
			Tags:            []string{tagGarages},
			Auth:            AuthIdentity,
			Request:         GarageInviteRedeemRequest{},
			Response:        GarageInviteRedeemResponse{},
			SuccessStatuses: []int{http.StatusCreated},
			handler:         bindHandler((*Server).handleGarageInviteRedeem),
		},
	}
}
