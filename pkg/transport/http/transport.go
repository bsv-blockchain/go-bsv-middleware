package httptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"log/slog"
	"net/http"
	"time"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/transport"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/utils"
	"github.com/bsv-blockchain/go-sdk/auth"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var (
	// DefaultAuthProtocol is the default protocol for authentication messages.
	DefaultAuthProtocol = wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: "auth message signature"}
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
	wallet                  wallet.KeyOperations
	sessionManager          auth.SessionManager
	allowUnauthenticated    bool
	logger                  *slog.Logger
	certificateRequirements *sdkUtils.RequestedCertificateSet
	onCertificatesReceived  func(
		senderPublicKey string,
		certs []*certificates.VerifiableCertificate,
		req *http.Request,
		res http.ResponseWriter,
		next func(),
	)
	messageCallback func(message auth.AuthMessage) error
	responseMessage *auth.AuthMessage
}

// New creates a new HTTP transport
func New(
	wallet wallet.KeyOperations,
	sessionManager auth.SessionManager,
	allowUnauthenticated bool, logger *slog.Logger,
	reqCerts *sdkUtils.RequestedCertificateSet,
	OnCertificatesReceived func(
		senderPublicKey string,
		certs *[]certificates.VerifiableCertificate,
		req *http.Request,
		res http.ResponseWriter,
		next func(),
	)) transport.TransportInterface {
	transportLogger := logging.Child(logger, "http-transport")
	transportLogger.Info(fmt.Sprintf("Creating HTTP transport with allowUnauthenticated = %t", allowUnauthenticated))

	return &Transport{
		wallet:                  wallet,
		sessionManager:          sessionManager,
		allowUnauthenticated:    allowUnauthenticated,
		logger:                  transportLogger,
		certificateRequirements: reqCerts,
		onCertificatesReceived:  OnCertificatesReceived,
	}
}

// OnData implement Transport TransportInterface
func (t *Transport) OnData(callback func(message auth.AuthMessage) error) error {
	t.messageCallback = callback
	return nil
}

// Send implement Transport TransportInterface
func (t *Transport) Send(message auth.AuthMessage) error {
	switch message.MessageType {
	case auth.MessageTypeInitialResponse, auth.MessageTypeCertificateResponse:
		if t.responseMessage == nil {
			t.responseMessage = &message
		}
	case auth.MessageTypeGeneral:
		t.responseMessage = &message
	}
	if t.messageCallback != nil {
		return t.messageCallback(message)
	}

	return nil
}

// HandleNonGeneralRequest handles incoming nongeneral requests
func (t *Transport) HandleNonGeneralRequest(req *http.Request, res http.ResponseWriter) error {
	requestData, err := parseAuthMessage(req)
	if err != nil {
		t.logger.Error("Invalid request body", slog.String("error", err.Error()))
		return err
	}

	t.logger.Debug("Received non general request request", slog.Any("data", requestData))

	requestID := req.Header.Get(requestIDHeader)
	if requestID == "" {
		requestID = requestData.InitialNonce
	}

	response, err := t.handleIncomingMessage(requestData, req, res)
	if err != nil {
		t.logger.Error("Failed to process request", slog.String("error", err.Error()))
		return err
	}

	if response == nil {
		return nil
	}

	setupHeaders(res, response, requestID)
	setupContent(res, response)

	return nil
}

// HandleGeneralRequest handles incoming general requests
func (t *Transport) HandleGeneralRequest(req *http.Request, res http.ResponseWriter) (*http.Request, *auth.AuthMessage, error) {
	requestID := req.Header.Get(requestIDHeader)
	if requestID == "" {
		if t.allowUnauthenticated {
			t.logger.Debug("Unauthenticated requests are allowed, skipping auth")
			return nil, nil, nil
		}
		t.logger.Debug("Missing request ID and unauthenticated requests are not allowed")

		return nil, nil, errors.New("missing request ID")
	}

	t.logger.Debug("Received general request", slog.String("requestID", requestID))

	err := checkHeaders(req)
	if err != nil {
		return nil, nil, err
	}

	requestData, err := buildAuthMessageFromRequest(req)
	if err != nil {
		t.logger.Error("Failed to build request data", slog.String("error", err.Error()))
		return nil, nil, err
	}

	response, err := t.handleIncomingMessage(requestData, req, res)
	if err != nil {
		t.logger.Error("Failed to process request", slog.String("error", err.Error()))
		return nil, nil, err
	}

	req = setupContext(req, requestData, requestID)

	return req, response, nil
}

// HandleResponse sets up auth headers in the response object and generate signature for whole response
func (t *Transport) HandleResponse(req *http.Request, res http.ResponseWriter, body []byte, status int, msg *auth.AuthMessage) error {
	if t.allowUnauthenticated {
		return nil
	}

	identityKey, requestID, err := getValuesFromContext(req)
	if err != nil {
		return err
	}

	session, err := t.sessionManager.GetSession(identityKey)
	if err != nil {
		return fmt.Errorf("failed to get session, %w", err)
	}
	if session == nil {
		return errors.New("session not found")
	}

	payload, err := buildResponsePayload(requestID, status, body)
	if err != nil {
		return err
	}

	counterparty := wallet.Counterparty{
		Type:         wallet.CounterpartyTypeSelf,
		Counterparty: session.PeerIdentityKey,
	}
	nonce, err := sdkUtils.CreateNonce(req.Context(), t.wallet, counterparty)
	if err != nil {
		return fmt.Errorf("failed to create nonce, %w", err)
	}

	peerNonce := ""
	if session.PeerNonce != "" {
		peerNonce = session.PeerNonce
	}
	signatureKey := fmt.Sprintf("%s %s", nonce, peerNonce)

	signature, err := t.createSignature(req.Context(), identityKey, signatureKey, payload)
	if err != nil {
		return err
	}

	msg.Signature = signature

	setupHeaders(res, msg, requestID)
	return nil
}

func (t *Transport) handleIncomingMessage(msg *auth.AuthMessage, req *http.Request, res http.ResponseWriter) (*auth.AuthMessage, error) {
	if msg.Version != transport.AuthVersion {
		return nil, errors.New("unsupported version")
	}

	switch msg.MessageType {
	case auth.MessageTypeInitialRequest:
		return t.handleInitialRequest(req.Context(), msg)
	case auth.MessageTypeCertificateResponse:
		result, err := t.handleCertificateResponse(msg, req, res)
		if err == nil && result == nil {
			return nil, nil
		}

		return result, err

	case auth.MessageTypeInitialResponse, auth.MessageTypeCertificateRequest:
		return nil, errors.New("not implemented")
	case auth.MessageTypeGeneral:
		return t.handleGeneralRequest(msg, req, res)
	default:
		return nil, errors.New("unsupported message type")
	}
}

func (t *Transport) handleInitialRequest(ctx context.Context, msg *auth.AuthMessage) (*auth.AuthMessage, error) {
	if msg.IdentityKey == nil && msg.InitialNonce == "" {
		return nil, errors.New("missing required fields in initial request")
	}

	sessionNonce, err := sdkUtils.CreateNonce(ctx, t.wallet, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil {
		return nil, fmt.Errorf("failed to create session nonce, %w", err)
	}

	authenticated := false
	if t.certificateRequirements == nil {
		authenticated = true
	}

	session := &auth.PeerSession{
		IsAuthenticated: authenticated,
		SessionNonce:    sessionNonce,
		PeerNonce:       msg.InitialNonce,
		PeerIdentityKey: msg.IdentityKey,
		LastUpdate:      time.Now().UnixMilli(),
	}
	err = t.sessionManager.AddSession(session)
	if err != nil {
		return nil, fmt.Errorf("failed to add session, %w", err)
	}

	signature, err := t.createNonGeneralAuthSignature(msg.InitialNonce, sessionNonce, msg.IdentityKey.ToDERHex())
	if err != nil {
		return nil, fmt.Errorf("failed to create signature, %w", err)
	}

	identityKey, err := t.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve identity key, %w", err)
	}

	initialResponseMessage := auth.AuthMessage{
		Version:      transport.AuthVersion,
		MessageType:  "initialResponse",
		IdentityKey:  identityKey.PublicKey,
		InitialNonce: sessionNonce,
		YourNonce:    msg.InitialNonce,
		Signature:    signature,
	}

	if t.certificateRequirements != nil {
		initialResponseMessage.RequestedCertificates = *t.certificateRequirements
	}

	return &initialResponseMessage, nil
}

func (t *Transport) handleCertificateResponse(msg *auth.AuthMessage, req *http.Request, res http.ResponseWriter) (*auth.AuthMessage, error) {
	valid, err := sdkUtils.VerifyNonce(req.Context(), msg.YourNonce, t.wallet, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil || !valid {
		return nil, fmt.Errorf("unable to verify nonce, %w", err)
	}

	if msg.Certificates == nil {
		return nil, fmt.Errorf("failed to retrieve certificates")
	}

	if msg.Nonce == "" {
		return nil, fmt.Errorf("failed to retrieve nonce")
	}

	payload, err := json.Marshal(msg.Certificates)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificates, %w", err)
	}

	session, err := t.sessionManager.GetSession(msg.IdentityKey.ToDERHex())
	if err != nil {
		return nil, fmt.Errorf("failed to get session, %w", err)
	}
	if session == nil {
		return nil, fmt.Errorf("no session found for identity key")
	}
	if session.PeerIdentityKey == nil {
		return nil, fmt.Errorf("failed to retrieve peer identity key")
	}

	signatureToVerify, err := ec.ParseSignature(msg.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature, %w", err)
	}

	key, err := ec.PublicKeyFromString(session.PeerIdentityKey.ToDERHex())
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity key, %w", err)
	}

	baseArgs := wallet.EncryptionArgs{
		ProtocolID: DefaultAuthProtocol,
		KeyID:      fmt.Sprintf("%s %s", msg.Nonce, msg.YourNonce),
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: key,
		},
	}
	args := wallet.VerifySignatureArgs{
		EncryptionArgs: baseArgs,
		Signature:      *signatureToVerify,
		Data:           payload,
	}
	result, err := t.wallet.VerifySignature(req.Context(), args, "")
	if err != nil || !result.Valid {
		return nil, fmt.Errorf("unable to verify signature, %w", err)
	}

	var sessionAuthenticated bool
	var authenticationDone bool

	if t.onCertificatesReceived != nil {
		authCallback := func() {
			sessionAuthenticated = true
			authenticationDone = true
		}

		t.onCertificatesReceived(
			session.PeerIdentityKey.ToDERHex(),
			msg.Certificates,
			req,
			res,
			authCallback,
		)

		if !authenticationDone {
			return nil, nil
		}

	} else {
		sessionAuthenticated = true
	}

	if sessionAuthenticated {
		session.IsAuthenticated = true
		session.LastUpdate = time.Now()
		t.sessionManager.UpdateSession(*session)
		t.logger.Debug("Certificate verification successful")
	}

	nonce, err := t.wallet.CreateNonce(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce")
	}

	signature, err := t.createNonGeneralAuthSignature(msg.InitialNonce, *session.SessionNonce, msg.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature, %w", err)
	}

	identityKey, err := t.wallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve identity key, %w", err)
	}

	response := &transport.AuthMessage{
		Version:     transport.AuthVersion,
		MessageType: transport.CertificateResponse,
		IdentityKey: identityKey.PublicKey.ToDERHex(),
		Nonce:       &nonce,
		YourNonce:   session.PeerNonce,
		Signature:   &signature,
	}
	return response, nil
}

func (t *Transport) handleGeneralRequest(msg *transport.AuthMessage, _ *http.Request, _ http.ResponseWriter) (*transport.AuthMessage, error) {
	valid, err := t.wallet.VerifyNonce(context.Background(), *msg.YourNonce)
	if err != nil || !valid {
		return nil, fmt.Errorf("unable to verify nonce, %w", err)
	}

	session := t.sessionManager.GetSession(*msg.YourNonce)
	if session == nil {
		return nil, errors.New("session not found")
	}

	if !session.IsAuthenticated && !t.allowUnauthenticated {
		if t.certificateRequirements != nil {
			// TODO code response should be set to 401
			return nil, errors.New("no certificates provided")
		}
		return nil, errors.New("session not authenticated")
	}

	signature, err := ec.ParseSignature(*msg.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature, %w", err)
	}

	key, err := ec.PublicKeyFromString(*session.PeerIdentityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity key, %w", err)
	}

	baseArgs := wallet.EncryptionArgs{
		ProtocolID: wallet.DefaultAuthProtocol,
		KeyID:      fmt.Sprintf("%s %s", *msg.Nonce, *msg.YourNonce),
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: key,
		},
	}
	verifySignatureArgs := &wallet.VerifySignatureArgs{
		EncryptionArgs: baseArgs,
		Signature:      *signature,
		Data:           *msg.Payload,
	}

	result, err := t.wallet.VerifySignature(verifySignatureArgs)
	if err != nil || !result.Valid {
		return nil, fmt.Errorf("unable to verify signature, %w", err)
	}

	session.LastUpdate = time.Now().UnixMilli()
	t.sessionManager.UpdateSession(*session)

	nonce, err := t.wallet.CreateNonce(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce, %w", err)
	}

	identityKey, err := t.wallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve identity key, %w", err)
	}

	response := &auth.AuthMessage{
		Version:     auth.AUTH_VERSION,
		MessageType: "general",
		IdentityKey: identityKey.PublicKey,
		Nonce:       &nonce,
		YourNonce:   session.PeerNonce,
	}

	return response, nil
}

func (t *Transport) createNonGeneralAuthSignature(ctx context.Context, initialNonce, sessionNonce, identityKey string) ([]byte, error) {
	combined := initialNonce + sessionNonce
	base64Data := base64.StdEncoding.EncodeToString([]byte(combined))

	signature, err := t.createSignature(ctx, identityKey, combined, []byte(base64Data))
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (t *Transport) createSignature(ctx context.Context, identityKey, keyID string, data []byte) ([]byte, error) {
	key, err := ec.PublicKeyFromString(identityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity key, %w", err)
	}

	baseArgs := wallet.EncryptionArgs{
		ProtocolID: DefaultAuthProtocol,
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: key,
		},
		KeyID: keyID,
	}
	createSignatureArgs := wallet.CreateSignatureArgs{
		EncryptionArgs: baseArgs,
		Data:           data,
	}

	signature, err := t.wallet.CreateSignature(ctx, createSignatureArgs, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create signature, %w", err)
	}

	return signature.Signature.Serialize(), nil
}

// buildResponsePayload constructs the response payload for signing
// The payload is constructed as follows:
// - Request ID (Base64)
// - Response status
// - Number of headers
// - Headers (key length, key, value length, value)
// - Body length and content
func buildResponsePayload(
	requestID string,
	responseStatus int,
	responseBody []byte,
) ([]byte, error) {
	var writer bytes.Buffer

	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return nil, errors.New("failed to decode request ID")
	}
	writer.Write(requestIDBytes)

	err = utils.WriteVarIntNum(&writer, responseStatus)
	if err != nil {
		return nil, errors.New("failed to write response status")
	}

	// TODO: #14 - Collect and sort headers
	includedHeaders := make([][]string, 0)
	//includedHeaders := utils.FilterAndSortHeaders(responseHeaders)

	if len(includedHeaders) > 0 {
		err = utils.WriteVarIntNum(&writer, len(includedHeaders))
		if err != nil {
			return nil, errors.New("failed to write headers length")
		}

		for _, header := range includedHeaders {
			err = utils.WriteVarIntNum(&writer, len(header[0]))
			if err != nil {
				return nil, errors.New("failed to write header key length")
			}
			writer.WriteString(header[0])

			err = utils.WriteVarIntNum(&writer, len(header[1]))
			if err != nil {
				return nil, errors.New("failed to write header value length")
			}
			writer.WriteString(header[1])
		}
	} else {
		err = utils.WriteVarIntNum(&writer, -1)
		if err != nil {
			return nil, errors.New("failed to write -1 as headers length")
		}
	}

	if len(responseBody) > 0 {
		err = utils.WriteVarIntNum(&writer, len(responseBody))
		if err != nil {
			return nil, errors.New("failed to write body length")
		}
		writer.Write(responseBody)
	} else {
		err = utils.WriteVarIntNum(&writer, -1)
		if err != nil {
			return nil, errors.New("failed to write -1 as body length")
		}
	}

	return writer.Bytes(), nil
}

func setupHeaders(w http.ResponseWriter, response *auth.AuthMessage, requestID string) {
	responseHeaders := map[string]string{
		versionHeader:     response.Version,
		messageTypeHeader: string(response.MessageType),
		identityKeyHeader: response.IdentityKey.ToDERHex(),
	}

	if response.MessageType == auth.MessageTypeGeneral {
		responseHeaders[requestIDHeader] = requestID
	}

	if response.Nonce != "" {
		responseHeaders[nonceHeader] = response.Nonce
	}

	if response.YourNonce != "" {
		responseHeaders[yourNonceHeader] = response.YourNonce
	}

	if response.Signature != nil {
		responseHeaders[signatureHeader] = hex.EncodeToString(response.Signature)
	}

	for k, v := range responseHeaders {
		w.Header().Set(k, v)
	}
}

func setupContent(w http.ResponseWriter, response *auth.AuthMessage) {
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
}

func buildAuthMessageFromRequest(req *http.Request) (*auth.AuthMessage, error) {
	var writer bytes.Buffer

	requestNonce := req.Header.Get(requestIDHeader)
	var requestNonceBytes []byte
	if requestNonce != "" {
		requestNonceBytes, _ = base64.StdEncoding.DecodeString(requestNonce)
	}

	writer.Write(requestNonceBytes)

	err := utils.WriteRequestData(req, &writer)
	if err != nil {
		return nil, errors.New("failed to write request data")
	}

	payloadBytes := writer.Bytes()

	pk, err := ec.PublicKeyFromString(req.Header.Get(identityKeyHeader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity key, %w", err)
	}

	authMessage := &auth.AuthMessage{
		MessageType: "general",
		Version:     req.Header.Get(versionHeader),
		IdentityKey: pk,
		Payload:     payloadBytes,
	}
	if nonce := req.Header.Get(nonceHeader); nonce != "" {
		authMessage.Nonce = nonce
	}

	if yourNonce := req.Header.Get(yourNonceHeader); yourNonce != "" {
		authMessage.YourNonce = yourNonce
	}

	if signature := req.Header.Get(signatureHeader); signature != "" {
		decodedBytes, err := hex.DecodeString(signature)
		if err != nil {
			return nil, errors.New("error decoding signature")
		}

		authMessage.Signature = decodedBytes
	}

	return authMessage, nil
}

func parseAuthMessage(req *http.Request) (*auth.AuthMessage, error) {
	var requestData auth.AuthMessage
	if err := json.NewDecoder(req.Body).Decode(&requestData); err != nil {
		return nil, errors.New("failed to decode request body")
	}
	return &requestData, nil
}

func setupContext(req *http.Request, requestData *auth.AuthMessage, requestID string) *http.Request {
	ctx := context.WithValue(req.Context(), transport.IdentityKey, requestData.IdentityKey)
	ctx = context.WithValue(ctx, transport.RequestID, requestID)
	req = req.WithContext(ctx)
	return req
}

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

func checkHeaders(req *http.Request) error {
	if req.Header.Get(versionHeader) == "" {
		return errors.New("missing version header")
	}

	if req.Header.Get(identityKeyHeader) == "" {
		return errors.New("missing identity key header")
	}

	if req.Header.Get(nonceHeader) == "" {
		return errors.New("missing nonce header")
	} else {
		if err := validateBase64(req.Header.Get(nonceHeader)); err != nil {
			return errors.New("invalid nonce header")
		}
	}

	if req.Header.Get(yourNonceHeader) == "" {
		return errors.New("missing your nonce header")
	} else {
		if err := validateBase64(req.Header.Get(yourNonceHeader)); err != nil {
			return errors.New("invalid your nonce header")
		}
	}

	if req.Header.Get(signatureHeader) == "" {
		return errors.New("missing signature header")
	} else {
		if !isHex(req.Header.Get(signatureHeader)) {
			return errors.New("invalid signature header")
		}
	}
	return nil
}

func validateBase64(input string) error {
	_, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return fmt.Errorf("invalid base64 string: %w", err)
	}
	return nil
}

func isHex(s string) bool {
	if len(s)%2 != 0 {
		return false
	}

	_, err := hex.DecodeString(s)
	return err == nil
}
