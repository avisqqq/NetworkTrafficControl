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
)

const (
	EventServiceStarted Event = "service.started"
	EventConfigLoaded   Event = "config.loaded"

	EventEbpfLoaded       Event = "ebpf.loaded"
	EventEbpfAttachFailed Event = "ebpf.attach_failed"

	EventWhitelistAdded   Event = "whitelist.added"
	EventWhitelistRemove  Event = "whitelist.removed"
	EventBlacklistAdded   Event = "blacklist.added"
	EventBlakclistRemoved Event = "blacklist.removed"
	EventOnlyLocalAdded   Event = "onlylocal.added"
	EnventOnlyLocalRemoed Event = "olnylocal.removed"

	EventStorageError Event = "storage.error"
)

const (
	ActorSystem Actor = "system"
	ActorApi    Actor = "api"
	AcotrUser   Actor = "user"
)

const (
	SourceStartup     Source = "startup"
	SourceHTTP        Source = "http"
	SourceEbpf        Source = "ebpf"
	SourceStorage     Source = "storage"
	SourceListManager Source = "list_manager"
)

const (
	EntityTypeIP         EntityType = "ip"
	EnitityTypeCIDR      EntityType = "cidr"
	EnitityTypeInterface EntityType = "interface"
	EnitityTypeDevice    EntityType = "Device"
)

type AppLog struct {
	ID           uint64
	CreatedAt     time.Time
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
