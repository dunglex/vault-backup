package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

func sessionTokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *server) storeSession(token string, session sessionInfo) error {
	return s.storeSessionForRequest(nil, token, session)
}

func (s *server) storeSessionForRequest(r *http.Request, token string, session sessionInfo) error {
	if token == "" {
		return fmt.Errorf("session token is empty")
	}
	if session.ttl <= 0 {
		session.ttl = defaultSessionTTL
	}
	if session.expiresAt.IsZero() {
		session.expiresAt = time.Now().Add(session.ttl)
	}
	if session.createdAt.IsZero() {
		session.createdAt = time.Now()
	}
	session.expiresAt = session.createdAt.Add(session.ttl)
	db := s.accountDatabase(session.role)
	if db == nil {
		return fmt.Errorf("app database is unavailable")
	}
	_, err := measureDBQuery(r, func() (sql.Result, error) {
		return db.Exec(`
			INSERT INTO web_sessions(token_hash, username, expires_at, ttl_seconds, created_at)
			VALUES (?, ?, ?, ?, ?)`,
			sessionTokenHash(token),
			session.username,
			session.expiresAt.Unix(),
			int64(session.ttl/time.Second),
			session.createdAt.Unix(),
		)
	})
	if err != nil {
		return fmt.Errorf("store web session: %w", err)
	}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = make(map[string]sessionInfo)
	}
	s.sessions[token] = session
	s.mu.Unlock()
	return nil
}

func (s *server) deleteSession(token string) error {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
	if token == "" {
		return nil
	}
	var failures []error
	if s.db != nil {
		if _, err := s.db.Exec("DELETE FROM web_sessions WHERE token_hash = ?", sessionTokenHash(token)); err != nil {
			failures = append(failures, fmt.Errorf("delete admin web session: %w", err))
		}
	}
	if s.operatorDB != nil {
		if _, err := s.operatorDB.Exec("DELETE FROM web_sessions WHERE token_hash = ?", sessionTokenHash(token)); err != nil {
			failures = append(failures, fmt.Errorf("delete operator web session: %w", err))
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	return nil
}

func (s *server) sessionForToken(token string) (sessionInfo, bool) {
	return s.sessionForTokenForRequest(nil, token)
}

func (s *server) sessionForTokenForRequest(r *http.Request, token string) (sessionInfo, bool) {
	if token == "" {
		return sessionInfo{}, false
	}
	if s.db == nil {
		return s.cachedSessionForToken(token)
	}

	now := time.Now()
	var session sessionInfo
	var expiresAt, ttlSeconds, createdAtUnix int64
	var mustChangePassword int
	db := s.db
	_, err := measureDBQuery(r, func() (struct{}, error) {
		return struct{}{}, db.QueryRow(`
			SELECT accounts.username, accounts.role, web_sessions.expires_at, web_sessions.ttl_seconds, web_sessions.created_at,
				accounts.must_change_password
			FROM web_sessions
			JOIN accounts ON accounts.username = web_sessions.username
			WHERE web_sessions.token_hash = ? AND web_sessions.expires_at > ?
			  AND accounts.locked = 0 AND accounts.role = 'admin'`,
			sessionTokenHash(token),
			now.Unix(),
		).Scan(&session.username, &session.role, &expiresAt, &ttlSeconds, &createdAtUnix, &mustChangePassword)
	})
	if err == sql.ErrNoRows && s.operatorDB != nil {
		db = s.operatorDB
		_, err = measureDBQuery(r, func() (struct{}, error) {
			return struct{}{}, db.QueryRow(`
				SELECT accounts.username, accounts.role, web_sessions.expires_at, web_sessions.ttl_seconds, web_sessions.created_at,
					accounts.must_change_password
				FROM web_sessions
				JOIN accounts ON accounts.username = web_sessions.username
				WHERE web_sessions.token_hash = ? AND web_sessions.expires_at > ?
				  AND accounts.locked = 0 AND accounts.role = 'operator'`,
				sessionTokenHash(token),
				now.Unix(),
			).Scan(&session.username, &session.role, &expiresAt, &ttlSeconds, &createdAtUnix, &mustChangePassword)
		})
	}
	if err != nil {
		if err == sql.ErrNoRows {
			for _, sessionDB := range []*sql.DB{s.db, s.operatorDB} {
				if sessionDB == nil {
					continue
				}
				if _, cleanupErr := measureDBQuery(r, func() (sql.Result, error) {
					return sessionDB.Exec("DELETE FROM web_sessions WHERE token_hash = ?", sessionTokenHash(token))
				}); cleanupErr != nil {
					log.Printf("WARNING: could not delete invalid web session: %v", cleanupErr)
				}
			}
			s.removeSessionFromCache(token)
			return sessionInfo{}, false
		}
		log.Printf("ERROR: could not read web session: %v", err)
		return sessionInfo{}, false
	}
	if ttlSeconds <= 0 {
		log.Printf("ERROR: web session for %q has invalid TTL %d", session.username, ttlSeconds)
		s.removePersistentSessionForRequest(r, token)
		return sessionInfo{}, false
	}
	session.ttl = time.Duration(ttlSeconds) * time.Second
	session.createdAt = time.Unix(createdAtUnix, 0)
	session.expiresAt = session.createdAt.Add(session.ttl)
	if !session.expiresAt.After(now) {
		s.removePersistentSessionForRequest(r, token)
		return sessionInfo{}, false
	}
	session.mustChangePassword = mustChangePassword == 1
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = make(map[string]sessionInfo)
	}
	s.sessions[token] = session
	s.mu.Unlock()
	return session, true
}

func (s *server) cachedSessionForToken(token string) (sessionInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[token]
	if !ok || time.Now().After(session.expiresAt) {
		delete(s.sessions, token)
		return sessionInfo{}, false
	}
	if session.ttl <= 0 {
		session.ttl = defaultSessionTTL
	}
	if session.createdAt.IsZero() {
		session.createdAt = time.Now()
		session.expiresAt = session.createdAt.Add(session.ttl)
	}
	s.sessions[token] = session
	return session, true
}

func (s *server) removeSessionFromCache(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func (s *server) removePersistentSession(token string) {
	s.removePersistentSessionForRequest(nil, token)
}

func (s *server) removePersistentSessionForRequest(r *http.Request, token string) {
	for _, db := range []*sql.DB{s.db, s.operatorDB} {
		if db == nil {
			continue
		}
		if _, err := measureDBQuery(r, func() (sql.Result, error) {
			return db.Exec("DELETE FROM web_sessions WHERE token_hash = ?", sessionTokenHash(token))
		}); err != nil {
			log.Printf("ERROR: could not delete invalid web session: %v", err)
		}
	}
	s.removeSessionFromCache(token)
}
