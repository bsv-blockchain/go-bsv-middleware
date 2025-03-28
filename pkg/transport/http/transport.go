package httptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/internal/logging"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport/utils"
)

// Constants for the auth headers used in the authorization process
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

// Transport implements the HTTP transport
type Transport struct {
	wallet               wallet.WalletInterface
	sessionManager       sessionmanager.SessionManagerInterface
	allowUnauthenticated bool
	logger               *slog.Logger
}

// New creates a new HTTP transport
func New(wallet wallet.WalletInterface, sessionManager sessionmanager.SessionManagerInterface, allowUnauthenticated bool, logger *slog.Logger) transport.TransportInterface {
	transportLogger := logging.Child(logger, "http-transport")
	transportLogger.Info(fmt.Sprintf("Creating HTTP transport with allowUnauthenticated = %t", allowUnauthenticated))

	return &Transport{
		wallet:               wallet,
		sessionManager:       sessionManager,
		allowUnauthenticated: allowUnauthenticated,
		logger:               transportLogger,
	}
}

// OnData implement Transport TransportInterface
func (t *Transport) OnData(_ transport.MessageCallback) {
	panic("Not implemented")
}

// Send implement Transport TransportInterface
func (t *Transport) Send(_ transport.AuthMessage) {
	panic("Not implemented")
}

// HandleNonGeneralRequest handles incoming non general requests
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

// HandleGeneralRequest handles incoming general requests
func (t *Transport) HandleGeneralRequest(req *http.Request, res http.ResponseWriter, _ transport.OnCertificatesReceivedFunc) (*http.Request, *transport.AuthMessage, error) {
	requestID := req.Header.Get(requestIDHeader)
	if requestID == "" {
		t.logger.Debug("Missing request ID, checking if unauthenticated requests are allowed")

		if t.allowUnauthenticated {
			t.logger.Debug("Unauthenticated requests are allowed, skipping auth")
			return nil, nil, nil
		}

		return nil, nil, errors.New("missing request ID")
	}

	t.logger.Debug("Received general request", slog.String("requestID", requestID))

	requestData, err := t.buildAuthMessageFromRequest(req)
	if err != nil {
		t.logger.Error("Failed to build request data", slog.String("error", err.Error()))
		return nil, nil, err
	}

	response, err := t.handleIncomingMessage(requestData)
	if err != nil {
		t.logger.Error("Failed to process request", slog.String("error", err.Error()))
		return nil, nil, err
	}

	req = setupContext(req, requestData, requestID)

	return req, response, nil
}

// HandleResponse sets up auth headers in the response object and generate signature for whole response
func (t *Transport) HandleResponse(req *http.Request, res http.ResponseWriter, body []byte, status int, msg *transport.AuthMessage) error {
	identityKey, requestID, err := getValuesFromContext(req)
	if err != nil {
		return err
	}

	payload := t.buildResponsePayload(requestID, status, body)

	session := t.sessionManager.GetSession(identityKey)
	if session == nil {
		return errors.New("session not found")
	}

	nonce, err := t.wallet.CreateNonce(req.Context())
	if err != nil {
		return fmt.Errorf("failed to create nonce, %w", err)
	}

	peerNonce := ""
	if session.PeerNonce != nil {
		peerNonce = *session.PeerNonce
	}
	signatureKey := fmt.Sprintf("%s %s", nonce, peerNonce)

	signature, err := t.wallet.CreateSignature(
		req.Context(),
		payload,
		"auth message signature",
		signatureKey,
		*session.PeerIdentityKey,
	)
	if err != nil {
		return fmt.Errorf("failed to create signature, %w", err)
	}

	msg.Signature = &signature

	t.setupHeaders(res, msg, requestID)
	return nil
}

func (t *Transport) handleIncomingMessage(msg *transport.AuthMessage) (*transport.AuthMessage, error) {
	if msg.Version != transport.AuthVersion {
		return nil, fmt.Errorf("unsupported version")
	}

	switch msg.MessageType {
	case transport.InitialRequest:
		return t.handleInitialRequest(msg)
	case transport.InitialResponse, transport.CertificateRequest, transport.CertificateResponse:
		return nil, errors.New("not implemented")
	case transport.General:
		return t.handleGeneralRequest(msg)
	default:
		return nil, errors.New("unsupported message type")
	}
}

func (t *Transport) handleInitialRequest(msg *transport.AuthMessage) (*transport.AuthMessage, error) {
	if msg.IdentityKey == "" && msg.InitialNonce == "" {
		return nil, errors.New("missing required fields in initial request")
	}

	sessionNonce, err := t.wallet.CreateNonce(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create session nonce, %w", err)
	}

	session := sessionmanager.PeerSession{
		IsAuthenticated: true,
		SessionNonce:    &sessionNonce,
		PeerNonce:       &msg.InitialNonce,
		PeerIdentityKey: &msg.IdentityKey,
		LastUpdate:      time.Now(),
	}
	t.sessionManager.AddSession(session)

	signature, err := createNonGeneralAuthSignature(t.wallet, msg.InitialNonce, sessionNonce, msg.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature, %w", err)
	}

	identityKey, err := t.wallet.GetPublicKey(context.Background(), wallet.GetPublicKeyOptions{IdentityKey: true})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve identity key, %w", err)
	}

	initialResponseMessage := transport.AuthMessage{
		Version:      transport.AuthVersion,
		MessageType:  "initialResponse",
		IdentityKey:  identityKey,
		InitialNonce: sessionNonce,
		YourNonce:    &msg.InitialNonce,
		Signature:    &signature,
	}

	return &initialResponseMessage, nil
}

func (t *Transport) handleGeneralRequest(msg *transport.AuthMessage) (*transport.AuthMessage, error) {
	valid, err := t.wallet.VerifyNonce(context.Background(), *msg.YourNonce)
	if err != nil || !valid {
		return nil, fmt.Errorf("unable to verify nonce, %w", err)
	}

	session := t.sessionManager.GetSession(*msg.YourNonce)
	if session == nil {
		return nil, errors.New("session not found")
	}

	valid, err = t.wallet.VerifySignature(context.Background(), *msg.Payload, *msg.Signature, "auth message signature", fmt.Sprintf("%s %s", *msg.Nonce, *msg.YourNonce), *session.PeerIdentityKey)
	if err != nil || !valid {
		return nil, fmt.Errorf("unable to verify signature, %w", err)
	}

	session.LastUpdate = time.Now()
	t.sessionManager.UpdateSession(*session)

	nonce, err := t.wallet.CreateNonce(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce, %w", err)
	}

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

	t.logger.Debug(fmt.Sprintf("Sending response: %+v", slog.Any("response", map[string]any{
		"status":          200,
		"responseHeaders": responseHeaders,
	})))
}

func (t *Transport) setupContent(w http.ResponseWriter, response *transport.AuthMessage) {
	w.Header().Set("Content-Type", "application/json")

	b, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(b)
	if err != nil {
		http.Error(w, "failed to write response", http.StatusInternalServerError)
		return
	}

	t.logger.Debug(fmt.Sprintf("Sending response with content: %+v", slog.Any("response", map[string]any{
		"messagePayload": *response,
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

	// TODO #19: handle query params

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
			return nil, errors.New("error decoding signature")
		}

		authMessage.Signature = &decodedBytes
	}

	return authMessage, nil
}

// buildResponsePayload constructs the response payload for signing
// The payload is constructed as follows:
// - Request ID (Base64)
// - Response status
// - Number of headers
// - Headers (key length, key, value length, value)
// - Body length and content
func (t *Transport) buildResponsePayload(
	requestID string,
	responseStatus int,
	responseBody []byte,
) []byte {
	t.logger.Debug("Building response payload",
		slog.String("requestID", requestID), slog.Int("responseStatus", responseStatus), slog.Int("responseBodyLength", len(responseBody)))

	var writer bytes.Buffer

	// Encode and write request ID (Base64)
	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return nil
	}
	writer.Write(requestIDBytes)

	// Write response status
	utils.WriteVarIntNum(&writer, responseStatus)

	// TODO: #14 - Collect and sort headers
	includedHeaders := make([][]string, 0)
	//includedHeaders := utils.FilterAndSortHeaders(responseHeaders)

	// Write number of headers
	utils.WriteVarIntNum(&writer, len(includedHeaders))

	// Write headers
	for _, header := range includedHeaders {
		// Write header key and value length and content
		utils.WriteVarIntNum(&writer, len(header[0]))
		writer.WriteString(header[0])

		utils.WriteVarIntNum(&writer, len(header[1]))
		writer.WriteString(header[1])
	}

	// Write body length and content
	if len(responseBody) > 0 {
		utils.WriteVarIntNum(&writer, len(responseBody))
		writer.Write(responseBody)
	} else {
		utils.WriteVarIntNum(&writer, -1)
	}

	return writer.Bytes()
}

func parseAuthMessage(req *http.Request) (*transport.AuthMessage, error) {
	var requestData transport.AuthMessage
	if err := json.NewDecoder(req.Body).Decode(&requestData); err != nil {
		return nil, errors.New("failed to decode request body")
	}
	return &requestData, nil
}

func createNonGeneralAuthSignature(wallet wallet.WalletInterface, initialNonce, sessionNonce, identityKey string) ([]byte, error) {
	combined := initialNonce + sessionNonce
	base64Data := base64.StdEncoding.EncodeToString([]byte(combined))

	signature, err := wallet.CreateSignature(
		context.Background(),
		[]byte(base64Data),
		"auth message signature",
		fmt.Sprintf("%s %s", initialNonce, sessionNonce),
		identityKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature, %w", err)
	}

	return signature, nil
}

func setupContext(req *http.Request, requestData *transport.AuthMessage, requestID string) *http.Request {
	ctx := context.WithValue(req.Context(), transport.IdentityKey, requestData.IdentityKey) //nolint:staticcheck // we want to use the key as a static string
	ctx = context.WithValue(ctx, transport.RequestID, requestID)                            //nolint:staticcheck // we want to use the key as a static string
	req = req.WithContext(ctx)
	return req
}

// getValuesFromContext extracts identity key and request ID from the request context
func getValuesFromContext(req *http.Request) (string, string, error) {
	identityKey, ok := req.Context().Value(transport.IdentityKey).(string)
	if !ok {
		return "", "", errors.New("identity key not found in context")
	}

	requestID, ok := req.Context().Value(transport.RequestID).(string)
	if !ok {
		return "", "", errors.New("request ID not found in context")
	}

	return identityKey, requestID, nil
}
