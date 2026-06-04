package logs

import "time"

type Level string
type Category string
type Event string
type EntityType string
type Actor string
type Source string

const (
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
)

const (
	CategorySystem   Category = "system"
	CategoryList     Category = "list"
	CategoryFirewall Category = "firewall"
	CategoryStorage  Category = "storage"
	CategoryNetwork  Category = "network"
	CategoryInspect  Category = "inspect"
)

const (
	EventServiceStarted Event = "service.started"
	EventConfigLoaded   Event = "config.loaded"

	EventWhitelistAdded   Event = "whitelist.added"
	EventWhitelistRemoved Event = "whitelist.removed"
	EventBlacklistAdded   Event = "blacklist.added"
	EventBlacklistRemoved Event = "blacklist.removed"
	EventOnlyLocalAdded   Event = "onlylocal.added"
	EventOnlyLocalRemoved Event = "onlylocal.removed"
	EventLocalNetAdded    Event = "localnet.added"
	EventLocalNetRemoved  Event = "localnet.removed"

	EventAPIError     Event = "api.error"
	EventStorageError Event = "storage.error"

	EventPacketInspectRequested Event = "packet.inspect.requested"
	EventGeoLookupSkipped       Event = "geo.lookup.skipped"
	EventGeoLookupSucceeded     Event = "geo.lookup.succeeded"
	EventGeoLookupFailed        Event = "geo.lookup.failed"
)

const (
	ActorSystem Actor = "system"
	ActorAPI    Actor = "api"
	ActorUser   Actor = "user"
)

const (
	SourceStartup     Source = "startup"
	SourceHTTP        Source = "http"
	SourceEbpf        Source = "ebpf"
	SourceStorage     Source = "storage"
	SourceListManager Source = "list_manager"
	SourceInspection  Source = "inspection"
)

const (
	EntityTypeIP        EntityType = "ip"
	EntityTypeCIDR      EntityType = "cidr"
	EntityTypeInterface EntityType = "interface"
	EntityTypeDevice    EntityType = "device"
	EntityTypePacket    EntityType = "packet"
)

type AppLog struct {
	ID           uint64
	CreatedAt    time.Time
	Level        Level
	Category     Category
	Event        Event
	Message      string
	EntityType   EntityType
	EntityID     string
	Actor        Actor
	Source       Source
	MetadataJSON string
}
