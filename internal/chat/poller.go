package chat

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dracoblue/atproto-push-gateway/internal/push"
	"github.com/dracoblue/atproto-push-gateway/internal/store"
)

const logCreateMessageType = "chat.bsky.convo.defs#logCreateMessage"
const deletedMessageType = "chat.bsky.convo.defs#deletedMessageView"
const directConversationType = "chat.bsky.convo.defs#directConvo"

type AccessTokenProvider interface {
	AccessToken(context.Context, string) (string, string, error)
	MarkNeedsReauth(string) error
	EncryptNotificationText(string) ([]byte, error)
	DecryptNotificationText([]byte) (string, error)
}

type Poller struct {
	store       *store.Store
	credentials AccessTokenProvider
	api         APIClient
	sender      push.Sender
}

func NewPoller(s *store.Store, credentials AccessTokenProvider, api APIClient, sender push.Sender) *Poller {
	return &Poller{store: s, credentials: credentials, api: api, sender: sender}
}

type logCreateMessage struct {
	Type            string    `json:"$type"`
	ConversationID  string    `json:"convoId"`
	Message         message   `json:"message"`
	RelatedProfiles []Profile `json:"relatedProfiles"`
}

type message struct {
	Type   string `json:"$type"`
	ID     string `json:"id"`
	Text   string `json:"text"`
	Sender struct {
		DID string `json:"did"`
	} `json:"sender"`
}

func (p *Poller) PollOnce(ctx context.Context, actorDID string) error {
	pdsHost, accessJWT, err := p.credentials.AccessToken(ctx, actorDID)
	if err != nil {
		return err
	}
	cursor, err := p.store.GetChatCursor(actorDID)
	if err != nil {
		return fmt.Errorf("load chat cursor: %w", err)
	}
	page, err := p.api.GetLog(ctx, pdsHost, accessJWT, cursor)
	if err != nil {
		var statusError *HTTPStatusError
		if errors.As(err, &statusError) && (statusError.StatusCode == http.StatusUnauthorized || statusError.StatusCode == http.StatusForbidden) {
			_ = p.credentials.MarkNeedsReauth(actorDID)
			return ErrNeedsReauth
		}
		return err
	}
	if page.Cursor == "" {
		return fmt.Errorf("chat log response omitted cursor")
	}
	if cursor == "" {
		return p.store.SaveChatPage(actorDID, page.Cursor, nil)
	}

	preferences, err := p.api.GetPreferences(ctx, pdsHost, accessJWT)
	if err != nil {
		return p.handleAPIError(actorDID, err)
	}
	messages, err := p.filterMessages(ctx, actorDID, pdsHost, accessJWT, page.Logs, preferences)
	if err != nil {
		return err
	}
	if err := p.store.SaveChatPage(actorDID, page.Cursor, messages); err != nil {
		return fmt.Errorf("persist chat page: %w", err)
	}
	return p.deliverPending(actorDID)
}

func (p *Poller) filterMessages(ctx context.Context, actorDID, pdsHost, accessJWT string, logs []json.RawMessage, preferences Preferences) ([]store.PendingChatMessage, error) {
	conversations := make(map[string]Conversation)
	var pending []store.PendingChatMessage
	for _, raw := range logs {
		var event logCreateMessage
		if err := json.Unmarshal(raw, &event); err != nil || event.Type != logCreateMessageType {
			continue
		}
		if event.Message.Type == deletedMessageType || event.Message.ID == "" || event.Message.Sender.DID == "" || event.Message.Sender.DID == actorDID {
			continue
		}
		conversation, ok := conversations[event.ConversationID]
		if !ok {
			var err error
			conversation, err = p.api.GetConversation(ctx, pdsHost, accessJWT, event.ConversationID)
			if err != nil {
				return nil, p.handleAPIError(actorDID, err)
			}
			conversations[event.ConversationID] = conversation
		}
		if conversation.Kind.Type != directConversationType || conversation.Muted {
			continue
		}
		preference := preferences.Chat
		if conversation.Status == "request" {
			preference = preferences.ChatRequest
		}
		if !preference.Push {
			continue
		}
		profile := findProfile(event.Message.Sender.DID, event.RelatedProfiles, conversation.Members)
		if preference.Include == "follows" && profile.Viewer.Following == "" {
			continue
		}
		encryptedBody, err := p.credentials.EncryptNotificationText(event.Message.Text)
		if err != nil {
			return nil, fmt.Errorf("encrypt notification text: %w", err)
		}
		pending = append(pending, store.PendingChatMessage{
			RecipientDID: actorDID, ActorDID: event.Message.Sender.DID,
			ConversationID: event.ConversationID, MessageID: event.Message.ID,
			ActorDisplayName: profile.DisplayName, ActorHandle: profile.Handle, ActorAvatar: profile.Avatar,
			EncryptedBody: encryptedBody,
		})
	}
	return pending, nil
}

func findProfile(actorDID string, profileLists ...[]Profile) Profile {
	result := Profile{DID: actorDID}
	for _, profiles := range profileLists {
		for _, profile := range profiles {
			if profile.DID == actorDID {
				if result.Handle == "" {
					result.Handle = profile.Handle
				}
				if result.DisplayName == "" {
					result.DisplayName = profile.DisplayName
				}
				if result.Avatar == "" {
					result.Avatar = profile.Avatar
				}
				if result.Viewer.Following == "" {
					result.Viewer.Following = profile.Viewer.Following
				}
			}
		}
	}
	return result
}

func (p *Poller) deliverPending(actorDID string) error {
	messages, err := p.store.GetPendingChatMessages(actorDID)
	if err != nil {
		return err
	}
	for _, message := range messages {
		body := "Open Aery to view it."
		if len(message.EncryptedBody) > 0 {
			body, err = p.credentials.DecryptNotificationText(message.EncryptedBody)
			if err != nil {
				return fmt.Errorf("decrypt notification text: %w", err)
			}
		}
		body = chatNotificationBody(body)
		if body == "" {
			body = "Open Aery to view it."
		}
		tokens, err := p.store.GetTokensForDID(actorDID)
		if err != nil {
			return err
		}
		for _, token := range tokens {
			tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(token.PushToken)))
			delivered, err := p.store.HasChatMessageTokenDelivery(actorDID, message.MessageID, tokenHash)
			if err != nil {
				return err
			}
			if delivered {
				continue
			}
			notification := push.Notification{
				Token: token.PushToken, Platform: token.Platform,
				Title: formatChatActorTitle(message.ActorDisplayName, message.ActorHandle), Body: body,
				Data: map[string]string{
					"reason": "chat", "recipientDid": message.RecipientDID,
					"actorDid": message.ActorDID, "convoId": message.ConversationID,
					"messageId": message.MessageID, "actorDisplayName": message.ActorDisplayName,
					"actorHandle": message.ActorHandle, "actorAvatar": message.ActorAvatar,
				},
			}
			if err := p.sender.Send(notification); err != nil {
				if errors.Is(err, push.ErrTokenInvalid) {
					if removeErr := p.store.UnregisterToken(token.ActorDID, token.Platform, token.PushToken, token.AppID); removeErr != nil {
						return removeErr
					}
					continue
				}
				return err
			}
			if err := p.store.MarkChatMessageTokenDelivered(actorDID, message.MessageID, tokenHash); err != nil {
				return err
			}
		}
		if err := p.store.MarkChatMessageDelivered(actorDID, message.MessageID); err != nil {
			return err
		}
		log.Printf("[chat] delivered message notification for %s from %s", actorDID, message.ActorDID)
	}
	return nil
}

func chatNotificationBody(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	runes := []rune(text)
	if len(runes) > 300 {
		return string(runes[:300]) + "…"
	}
	return text
}

func formatChatActorTitle(displayName, handle string) string {
	displayName = strings.TrimSpace(displayName)
	handle = strings.TrimPrefix(strings.TrimSpace(handle), "@")
	if displayName == "" && handle == "" {
		displayName = "Someone"
	}
	label := displayName
	if handle != "" {
		if label == "" {
			label = "@" + handle
		} else {
			label += " (@" + handle + ")"
		}
	}
	return "💬 " + label
}

func (p *Poller) handleAPIError(actorDID string, err error) error {
	var statusError *HTTPStatusError
	if errors.As(err, &statusError) && (statusError.StatusCode == http.StatusUnauthorized || statusError.StatusCode == http.StatusForbidden) {
		_ = p.credentials.MarkNeedsReauth(actorDID)
		return ErrNeedsReauth
	}
	return err
}
