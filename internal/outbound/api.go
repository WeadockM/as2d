package outbound

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxWait caps the wait= parameter. The API server's write timeout must be
// longer.
const MaxWait = 10 * time.Minute

// APIHandler serves the local submission API:
//
//	POST /api/messages?partner=ID&filename=NAME[&subject=TEXT][&wait=120s]
//	     body = payload, optional X-Correlation-ID header; 202 + job, or with
//	     wait=, 200 + the final job once delivered or failed
//	GET  /api/messages[?state=failed][&kind=send|forward][&limit=N] recent jobs, newest first
//	GET  /api/messages/{id}                                        one job
//	POST /api/messages/{id}/retry                                  requeue a failed job
//
// When token is set, requests need "Authorization: Bearer <token>".
func (m *Manager) APIHandler(token string, maxBody int64) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/messages", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				apiError(w, http.StatusRequestEntityTooLarge, "payload too large")
				return
			}
			apiError(w, http.StatusBadRequest, "failed to read payload")
			return
		}
		if len(payload) == 0 {
			apiError(w, http.StatusBadRequest, "empty payload")
			return
		}
		contentType := r.Header.Get("Content-Type")
		switch mt, _, _ := mime.ParseMediaType(contentType); mt {
		case "multipart/form-data":
			apiError(w, http.StatusBadRequest, "send the file as the raw request body, not as a form upload")
			return
		case "application/x-www-form-urlencoded":
			// curl's default for --data-binary; not a real payload type.
			contentType = ""
		}
		var wait time.Duration
		if s := q.Get("wait"); s != "" {
			if wait, err = time.ParseDuration(s); err != nil || wait < 0 {
				apiError(w, http.StatusBadRequest, `wait must be a duration such as "120s"`)
				return
			}
			wait = min(wait, MaxWait)
		}

		corr := r.Header.Get("X-Correlation-Id")
		if corr != "" {
			w.Header().Set("X-Correlation-ID", corr)
		}
		job, err := m.Submit(Submission{
			Partner:       q.Get("partner"),
			Filename:      filepath.Base(q.Get("filename")),
			ContentType:   contentType,
			Subject:       q.Get("subject"),
			CorrelationID: corr,
			Payload:       payload,
		})
		switch {
		case errors.Is(err, ErrUnknownPartner):
			apiError(w, http.StatusNotFound, err.Error())
			return
		case err != nil:
			apiError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if wait == 0 {
			writeJSON(w, http.StatusAccepted, job.Status())
			return
		}
		// Hold the response until the partner's MDN settles the message.
		// 200 means the job is final (delivered or failed); 202 means the
		// wait ran out first and the job is still in progress.
		ctx, cancel := context.WithTimeout(r.Context(), wait)
		defer cancel()
		job, final := m.Wait(ctx, job.ID)
		status := http.StatusAccepted
		if final {
			status = http.StatusOK
		}
		writeJSON(w, status, job.Status())
	})
	mux.HandleFunc("GET /api/messages", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 {
			limit = 100
		}
		jobs := m.List(State(q.Get("state")), 0)
		if kind := q.Get("kind"); kind != "" {
			if kind == "send" {
				kind = KindSend
			}
			jobs = slices.DeleteFunc(jobs, func(j Job) bool { return j.Kind != kind })
		}
		if len(jobs) > limit {
			jobs = jobs[:limit]
		}
		out := make([]Status, len(jobs))
		for i, j := range jobs {
			out[i] = j.Status()
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /api/messages/{id}", func(w http.ResponseWriter, r *http.Request) {
		job, ok := m.Get(r.PathValue("id"))
		if !ok {
			apiError(w, http.StatusNotFound, "no such job")
			return
		}
		writeJSON(w, http.StatusOK, job.Status())
	})
	mux.HandleFunc("POST /api/messages/{id}/retry", func(w http.ResponseWriter, r *http.Request) {
		job, err := m.Retry(r.PathValue("id"))
		if err != nil {
			apiError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, job.Status())
	})

	if token == "" {
		return mux
	}
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			apiError(w, http.StatusUnauthorized, "missing or wrong API token")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ContentTypeFor guesses a payload's content type from its file name.
func ContentTypeFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".edi", ".x12":
		return "application/edi-x12"
	case ".edifact":
		return "application/edifact"
	case ".xml":
		return "application/xml"
	case ".json":
		return "application/json"
	case ".csv":
		return "text/csv"
	case ".txt":
		return "text/plain"
	}
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}
