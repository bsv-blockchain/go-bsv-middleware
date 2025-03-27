package httptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport/utils"
)

const (
	authHeaderPrefix  = "x-bsv-auth-"
	requestIDHeader   = authHeaderPrefix + "request-id"
	versionHeader     = authHeaderPrefix + "version"
	identityKeyHeader = authHeaderPrefix + "identity-key"
	nonceHeader       = authHeaderPrefix + "nonce"
	yourNonceHeader   = authHeaderPrefix + "your-nonce"
	signatureHeader   = authHeaderPrefix + "signature"
	messageTypeHeader = authHeaderPrefix + "message-type"
)

type Transport struct {
	//peer                 shared.PeerInterface
	wallet               wallet.Interface
	sessionManager       sessionmanager.Interface
	allowUnauthenticated bool
	logger               *slog.Logger
}

func New(wallet wallet.Interface, sessionManager sessionmanager.Interface, allowUnauthenticated bool, logger *slog.Logger) transport.Interface {
	transportLogger := logger.With("service", "HTTP TRANSPORT")
	transportLogger.Info(fmt.Sprintf("Creating HTTP transport with allowUnauthenticated = %t", allowUnauthenticated))

	return &Transport{
		wallet:               wallet,
		sessionManager:       sessionManager,
		allowUnauthenticated: allowUnauthenticated,
		logger:               transportLogger,
	}
}

// OnData implement Transport Interface
func (t *Transport) OnData(_ transport.MessageCallback) {}

// Send implement Transport Interface
func (t *Transport) Send(_ transport.AuthMessage) {}

func (t *Transport) HandleNonGeneralRequest(req *http.Request, w http.ResponseWriter, _ transport.OnCertificatesReceivedFunc) {
	requestData, err := parseAuthMessage(req)
	if err != nil {
		t.logger.Error("Invalid request body", slog.String("error", err.Error()))
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	t.logger.Debug("Received non general request request", slog.Any("data", requestData))

	// Get request ID or set it to initial nonce
	requestID := req.Header.Get(requestIDHeader)
	if requestID == "" {
		requestID = requestData.InitialNonce
	}

	response, err := t.handleIncomingMessage(requestData)
	if err != nil {
		t.logger.Error("Failed to process request", slog.String("error", err.Error()))
		http.Error(w, "failed to process request", http.StatusInternalServerError)
		return
	}

	t.setupHeaders(w, response, requestID)
	t.setupContent(w, response)
}

func (t *Transport) HandleGeneralRequest(req *http.Request, w http.ResponseWriter, _ transport.OnCertificatesReceivedFunc) error {
	requestID := req.Header.Get(requestIDHeader)
	if requestID == "" {
		t.logger.Error("Missing request ID, checking if unauthenticated requests are allowed")

		if t.allowUnauthenticated {
			return nil
		}

		return fmt.Errorf("missing request ID")
	}

	t.logger.Debug("Received general request", slog.String("requestID", requestID))

	requestData, err := t.buildAuthMessageFromRequest(req)
	if err != nil {
		t.logger.Error("Failed to build request data", slog.String("error", err.Error()))
		return err
	}

	response, err := t.handleIncomingMessage(requestData)
	if err != nil {
		t.logger.Error("Failed to process request", slog.String("error", err.Error()))
		return fmt.Errorf("failed to process request")
	}

	t.setupHeaders(w, response, requestID)

	return nil
}

func (t *Transport) handleIncomingMessage(msg *transport.AuthMessage) (*transport.AuthMessage, error) {
	if msg.Version != transport.AuthVersion {
		return nil, fmt.Errorf("unsupported version")
	}

	switch msg.MessageType {
	case transport.InitialRequest:
		return t.handleInitialRequest(msg)
	case transport.General:
		return t.handleGeneralRequest(msg)
	default:
		return nil, fmt.Errorf("unsupported message type")
	}
}

func (t *Transport) handleInitialRequest(msg *transport.AuthMessage) (*transport.AuthMessage, error) {
	if msg.IdentityKey == "" && msg.InitialNonce == "" {
		return nil, fmt.Errorf("missing required fields in initial request")
	}

	sessionNonce, err := t.wallet.CreateNonce(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create session nonce")
	}

	session := sessionmanager.PeerSession{
		IsAuthenticated: true,
		SessionNonce:    &sessionNonce,
		PeerNonce:       &msg.InitialNonce,
		PeerIdentityKey: &msg.IdentityKey,
		LastUpdate:      time.Now(),
	}
	t.sessionManager.AddSession(session)

	signature, err := createAuthSignature(t.wallet, msg.InitialNonce, sessionNonce, msg.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature")
	}

	identityKey, err := t.wallet.GetPublicKey(context.Background(), wallet.GetPublicKeyOptions{IdentityKey: true})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve identity key")
	}

	initialResponseMessage := transport.AuthMessage{
		Version:      transport.AuthVersion,
		MessageType:  "initialResponse",
		IdentityKey:  identityKey,
		InitialNonce: sessionNonce,
		YourNonce:    &msg.InitialNonce,
		//Certificates:          certificatesToInclude,
		//RequestedCertificates: certificatesToRequest,
		Signature: &signature,
	}

	return &initialResponseMessage, nil
}

func (t *Transport) handleGeneralRequest(msg *transport.AuthMessage) (*transport.AuthMessage, error) {
	valid, err := t.wallet.VerifyNonce(context.Background(), *msg.YourNonce)
	if err != nil || !valid {
		return nil, fmt.Errorf("unable to verify nonce")
	}

	session := t.sessionManager.GetSession(*msg.YourNonce)
	if session == nil {
		return nil, fmt.Errorf("session not found")
	}

	valid, err = t.wallet.VerifySignature(context.Background(), *msg.Payload, *msg.Signature, "auth message signature", fmt.Sprintf("%s %s", *msg.Nonce, *msg.YourNonce), *session.PeerIdentityKey)
	if err != nil || !valid {
		return nil, fmt.Errorf("unable to verify signature")
	}

	session.LastUpdate = time.Now()
	t.sessionManager.UpdateSession(*session)

	nonce, err := t.wallet.CreateNonce(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce")
	}

	//signature, err := createAuthSignature(t.wallet, msg.InitialNonce, sessionNonce, msg.IdentityKey)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to create signature")
	//}

	response := &transport.AuthMessage{
		Version:     transport.AuthVersion,
		MessageType: "general",
		IdentityKey: *session.PeerIdentityKey,
		Nonce:       &nonce,
		YourNonce:   session.PeerNonce,
	}

	return response, nil
}

func (t *Transport) setupHeaders(w http.ResponseWriter, response *transport.AuthMessage, requestID string) {
	responseHeaders := map[string]string{
		versionHeader:     response.Version,
		messageTypeHeader: response.MessageType.String(),
		identityKeyHeader: response.IdentityKey,
		requestIDHeader:   requestID,
	}

	if response.Nonce != nil {
		responseHeaders[nonceHeader] = *response.Nonce
	}

	if response.YourNonce != nil {
		responseHeaders[yourNonceHeader] = *response.YourNonce
	}

	if response.Signature != nil {
		responseHeaders[signatureHeader] = hex.EncodeToString(*response.Signature)
	}

	for k, v := range responseHeaders {
		w.Header().Set(k, v)
	}

	t.logger.Debug(fmt.Sprintf("Sending response: %+v", slog.Any("response", map[string]interface{}{
		"status":          200,
		"responseHeaders": responseHeaders,
	})))

	w.WriteHeader(http.StatusOK)
}

func (t *Transport) setupContent(w http.ResponseWriter, response *transport.AuthMessage) {
	w.Header().Set("Content-Type", "application/json")

	b, err := json.Marshal(response)
	if err != nil {
		t.logger.Error("Failed to marshal response", slog.String("error", err.Error()))
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(b)
	if err != nil {
		t.logger.Error("Failed to write response", slog.String("error", err.Error()))
	}

	t.logger.Debug(fmt.Sprintf("Sending response with content: %+v", slog.Any("response", map[string]interface{}{
		"messagePayload": response,
	})))
}

func (t *Transport) buildAuthMessageFromRequest(req *http.Request) (*transport.AuthMessage, error) {
	var writer bytes.Buffer

	// handle request ID
	requestNonce := req.Header.Get(requestIDHeader)
	var requestNonceBytes []byte
	if requestNonce != "" {
		requestNonceBytes, _ = base64.StdEncoding.DecodeString(requestNonce)
	}

	writer.Write(requestNonceBytes)

	// handle method
	utils.WriteVarIntNum(&writer, len(req.Method))
	writer.Write([]byte(req.Method))

	// handle path
	utils.WriteVarIntNum(&writer, len(req.URL.Path))
	writer.Write([]byte(req.URL.Path))

	// TODO: handle query params

	// handle headers
	includedHeaders := utils.ExtractHeaders(req.Header)
	utils.WriteVarIntNum(&writer, len(includedHeaders))

	for _, header := range includedHeaders {
		headerKeyBytes := []byte(header[0])
		utils.WriteVarIntNum(&writer, len(headerKeyBytes))
		writer.Write(headerKeyBytes)

		headerValueBytes := []byte(header[1])
		utils.WriteVarIntNum(&writer, len(headerValueBytes))
		writer.Write(headerValueBytes)
	}

	// handle body
	utils.WriteBodyToBuffer(req, &writer)

	payloadBytes := writer.Bytes()

	// Construct AuthMessage
	authMessage := &transport.AuthMessage{
		MessageType: "general",
		Version:     req.Header.Get(versionHeader),
		IdentityKey: req.Header.Get(identityKeyHeader),
		Payload:     &payloadBytes,
	}

	if nonce := req.Header.Get("x-bsv-auth-nonce"); nonce != "" {
		authMessage.Nonce = &nonce
	}
	if yourNonce := req.Header.Get("x-bsv-auth-your-nonce"); yourNonce != "" {
		authMessage.YourNonce = &yourNonce
	}

	if signature := req.Header.Get("x-bsv-auth-signature"); signature != "" {
		decodedBytes, err := hex.DecodeString(signature)
		if err != nil {
			fmt.Println("Error decoding hex:", err)
			return nil, fmt.Errorf("error decoding hex")
		}

		authMessage.Signature = &decodedBytes
	}

	return authMessage, nil
}

func parseAuthMessage(req *http.Request) (*transport.AuthMessage, error) {
	var requestData transport.AuthMessage
	if err := json.NewDecoder(req.Body).Decode(&requestData); err != nil {
		return nil, err
	}
	return &requestData, nil
}

func createAuthSignature(wallet wallet.Interface, peerNonce, sessionNonce, identityKey string) ([]byte, error) {
	combined := peerNonce + sessionNonce
	base64Data := base64.StdEncoding.EncodeToString([]byte(combined))

	return wallet.CreateSignature(
		context.Background(),
		[]byte(base64Data),
		"auth message signature",
		fmt.Sprintf("%s %s", peerNonce, sessionNonce),
		identityKey,
	)
}
