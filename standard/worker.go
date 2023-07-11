package standard

import (
	"context"
	"encoding/json"

	"github.com/golangid/candi/candihelper"
	"github.com/golangid/candi/candishared"
	"github.com/golangid/candi/tracer"
	"github.com/google/uuid"
)

// KafkaPayload : event & payload of kafka message
type KafkaPayload struct {
	Timestamp string      `json:"timestamp,omitempty"`
	EventType string      `json:"eventType"`
	Publisher string      `json:"publisher"`
	Payload   interface{} `json:"payload"`
}

// TaskQueueWorkerMaxRetryHandler handler func
func TaskQueueWorkerMaxRetryHandler(dashboardURL string) func(*candishared.EventContext) error {
	return func(eventContext *candishared.EventContext) error {
		if eventContext.Err() != nil {
			// Logging here
		}
		return nil
	}
}

// RedisMessage custom model for redis subscriber key
type RedisMessage struct {
	HandlerName string `json:"h"`
	Message     string `json:"message"`
	EventID     string `json:"id,omitempty"`
}

// CreateRedisPubSubMessage create new redis pubsub message
func CreateRedisPubSubMessage(ctx context.Context, topic string, message interface{}) string {
	trace := tracer.StartTrace(ctx, "RedisMessage:CreateRedisPubSubMessage")
	defer trace.Finish()

	redisMessage := RedisMessage{
		EventID: uuid.NewString(), HandlerName: topic, Message: string(candihelper.ToBytes(message)),
	}
	key, _ := json.Marshal(redisMessage)

	trace.SetTag("topic", topic)
	trace.SetTag("eventId", redisMessage.EventID)
	trace.Log("message", message)

	return string(key)
}

// DeleteRedisPubSubMessage delete redis key pubsub message pattern
func DeleteRedisPubSubMessage(ctx context.Context, topic string, message interface{}) string {
	trace := tracer.StartTrace(ctx, "RedisMessage:DeleteRedisPubSubMessage")
	defer trace.Finish()

	trace.SetTag("topic", topic)
	trace.Log("message", message)

	b, _ := json.Marshal(RedisMessage{
		HandlerName: topic, Message: string(candihelper.ToBytes(message)),
	})
	b[len(b)-1] = '*'
	return string(b)
}
