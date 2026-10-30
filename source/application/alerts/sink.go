package alerts

import (
	"context"

	"ntc/source/domain/alert"
)

type Sink interface {
	CreateAlert(context.Context, alert.Alert) error
}
