package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

func sessionTokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *server) storeSession(token string, session sessionInfo) error {
	if token == "" {
		return fmt.Errorf("session token is empty")
	}
	if session.ttl <= 0 {
		session.ttl = defaultSessionTTL
	}
	if session.expiresAt.IsZero() {
		session.expiresAt = time.Now().Add(session.ttl)
	}
	if s.db == nil {
		return fmt.Errorf("app database is unavailable")
	}
	_, err := s.db.Exec(`
		INSERT INTO web_sessions(token_hash, username, expires_at, ttl_seconds, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		sessionTokenHash(token),
		session.username,
		session.expiresAt.Unix(),
		int64(session.ttl/time.Second),
		time.Now().Unix(),
	)
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
	if token == "" || s.db == nil {
		return nil
	}
	if _, err := s.db.Exec("DELETE FROM web_sessions WHERE token_hash = ?", sessionTokenHash(token)); err != nil {
		return fmt.Errorf("delete web session: %w", err)
	}
	return nil
}

func (s *server) sessionForToken(token string) (sessionInfo, bool) {
	if token == "" {
		return sessionInfo{}, false
	}
	if s.db == nil {
		return s.cachedSessionForToken(token)
	}

	now := time.Now()
	var session sessionInfo
	var expiresAt, ttlSeconds int64
	var mustChangePassword int
	err := s.db.QueryRow(`
		SELECT accounts.username, accounts.role, web_sessions.expires_at, web_sessions.ttl_seconds,
			accounts.must_change_password
		FROM web_sessions
		JOIN accounts ON accounts.username = web_sessions.username
		WHERE web_sessions.token_hash = ? AND web_sessions.expires_at > ? AND accounts.locked = 0`,
		sessionTokenHash(token),
		now.Unix(),
	).Scan(&session.username, &session.role, &expiresAt, &ttlSeconds, &mustChangePassword)
	if err != nil {
		if err == sql.ErrNoRows {
			if _, cleanupErr := s.db.Exec(
				"DELETE FROM web_sessions WHERE token_hash = ?",
				sessionTokenHash(token),
			); cleanupErr != nil {
				log.Printf("WARNING: could not delete invalid web session: %v", cleanupErr)
			}
			s.removeSessionFromCache(token)
			return sessionInfo{}, false
		}
		log.Printf("ERROR: could not read web session: %v", err)
		return sessionInfo{}, false
	}
	if ttlSeconds <= 0 {
		log.Printf("ERROR: web session for %q has invalid TTL %d", session.username, ttlSeconds)
		s.removePersistentSession(token)
		return sessionInfo{}, false
	}
	session.ttl = time.Duration(ttlSeconds) * time.Second
	session.expiresAt = now.Add(session.ttl)
	session.mustChangePassword = mustChangePassword == 1
	result, err := s.db.Exec(
		"UPDATE web_sessions SET expires_at = ? WHERE token_hash = ? AND expires_at > ?",
		session.expiresAt.Unix(),
		sessionTokenHash(token),
		now.Unix(),
	)
	if err != nil {
		log.Printf("ERROR: could not refresh web session: %v", err)
		return sessionInfo{}, false
	}
	updated, err := result.RowsAffected()
	if err != nil {
		log.Printf("ERROR: could not verify refreshed web session: %v", err)
		return sessionInfo{}, false
	}
	if updated != 1 {
		s.removeSessionFromCache(token)
		return sessionInfo{}, false
	}
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
	session.expiresAt = time.Now().Add(session.ttl)
	s.sessions[token] = session
	return session, true
}

func (s *server) removeSessionFromCache(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func (s *server) removePersistentSession(token string) {
	if _, err := s.db.Exec("DELETE FROM web_sessions WHERE token_hash = ?", sessionTokenHash(token)); err != nil {
		log.Printf("ERROR: could not delete invalid web session: %v", err)
	}
	s.removeSessionFromCache(token)
}
