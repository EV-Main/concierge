-- The legacy governance tables, as 0009 and 0015 left them. Lossless: the up migration ran
-- only over empty tables.
SET LOCAL lock_timeout = '3s';

CREATE TABLE owner_removal (
    id                UUID PRIMARY KEY,
    target_user_id    UUID NOT NULL REFERENCES users (id),
    initiator_user_id UUID NOT NULL REFERENCES users (id),
    reason            TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'open',
    owner_count       INTEGER NOT NULL,
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    decided_at        BIGINT,
    void_reason       TEXT NOT NULL DEFAULT '',
    version           BIGINT NOT NULL DEFAULT 0,
    target_decision   TEXT NOT NULL DEFAULT 'pending',
    target_decided_at BIGINT,
    target_notified   BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT owner_removal_not_self CHECK (target_user_id <> initiator_user_id),
    CONSTRAINT owner_removal_state CHECK (state IN ('open', 'executed', 'rejected', 'expired', 'cancelled', 'void')),
    CONSTRAINT owner_removal_target_decision CHECK (target_decision IN ('pending', 'remove', 'keep')),
    CONSTRAINT owner_removal_reason_len CHECK (char_length(reason) BETWEEN 1 AND 500),
    CONSTRAINT owner_removal_void_reason_len CHECK (char_length(void_reason) <= 200),
    CONSTRAINT owner_removal_floor CHECK (owner_count >= 3),
    CONSTRAINT owner_removal_ttl CHECK (expires_at > created_at),
    CONSTRAINT owner_removal_decided CHECK ((state = 'open') = (decided_at IS NULL)),
    CONSTRAINT owner_removal_target_decided CHECK ((target_decision = 'pending') = (target_decided_at IS NULL)),
    CONSTRAINT owner_removal_void_reason_only_void CHECK (state = 'void' OR void_reason = '')
);

CREATE UNIQUE INDEX owner_removal_open_target_idx ON owner_removal (target_user_id) WHERE state = 'open';
CREATE INDEX owner_removal_open_idx ON owner_removal (expires_at) WHERE state = 'open';
CREATE INDEX owner_removal_recent_idx ON owner_removal (created_at DESC);

CREATE TABLE owner_removal_peer (
    removal_id UUID NOT NULL REFERENCES owner_removal (id),
    user_id    UUID NOT NULL REFERENCES users (id),
    vote       TEXT NOT NULL DEFAULT 'pending',
    voted_at   BIGINT,
    PRIMARY KEY (removal_id, user_id),
    CONSTRAINT owner_removal_peer_vote CHECK (vote IN ('pending', 'remove', 'keep')),
    CONSTRAINT owner_removal_peer_voted CHECK ((vote = 'pending') = (voted_at IS NULL))
);

CREATE INDEX owner_removal_peer_pending_idx ON owner_removal_peer (user_id) WHERE vote = 'pending';

CREATE TABLE owner_removal_token (
    removal_id UUID PRIMARY KEY REFERENCES owner_removal (id),
    token_hash BYTEA NOT NULL,
    code_hash  BYTEA NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    burned_at  BIGINT,
    expires_at BIGINT NOT NULL,
    used_at    BIGINT,
    CONSTRAINT owner_removal_token_digest CHECK (octet_length(token_hash) = 32 AND octet_length(code_hash) = 32),
    CONSTRAINT owner_removal_token_attempts CHECK (attempts BETWEEN 0 AND 5),
    CONSTRAINT owner_removal_token_burn CHECK (burned_at IS NULL OR attempts >= 5)
);

CREATE UNIQUE INDEX owner_removal_token_hash_idx ON owner_removal_token (token_hash);

CREATE TABLE owner_admission (
    id                UUID PRIMARY KEY,
    candidate_user_id UUID NOT NULL REFERENCES users (id),
    initiator_user_id UUID NOT NULL REFERENCES users (id),
    reason            TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'open',
    owner_count       INTEGER NOT NULL,
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    decided_at        BIGINT,
    void_reason       TEXT NOT NULL DEFAULT '',
    version           BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT owner_admission_not_self CHECK (candidate_user_id <> initiator_user_id),
    CONSTRAINT owner_admission_state CHECK (state IN ('open', 'executed', 'rejected', 'expired', 'cancelled', 'void')),
    CONSTRAINT owner_admission_reason_len CHECK (char_length(reason) BETWEEN 1 AND 500),
    CONSTRAINT owner_admission_void_reason_len CHECK (char_length(void_reason) <= 200),
    CONSTRAINT owner_admission_needs_a_peer CHECK (owner_count >= 2),
    CONSTRAINT owner_admission_ttl CHECK (expires_at > created_at),
    CONSTRAINT owner_admission_decided CHECK ((state = 'open') = (decided_at IS NULL)),
    CONSTRAINT owner_admission_void_reason_only_void CHECK (state = 'void' OR void_reason = '')
);

CREATE UNIQUE INDEX owner_admission_open_candidate_idx ON owner_admission (candidate_user_id) WHERE state = 'open';
CREATE INDEX owner_admission_open_idx ON owner_admission (expires_at) WHERE state = 'open';
CREATE INDEX owner_admission_recent_idx ON owner_admission (created_at DESC);

CREATE TABLE owner_admission_peer (
    admission_id UUID NOT NULL REFERENCES owner_admission (id),
    user_id      UUID NOT NULL REFERENCES users (id),
    vote         TEXT NOT NULL DEFAULT 'pending',
    voted_at     BIGINT,
    PRIMARY KEY (admission_id, user_id),
    CONSTRAINT owner_admission_peer_vote CHECK (vote IN ('pending', 'admit', 'reject')),
    CONSTRAINT owner_admission_peer_voted CHECK ((vote = 'pending') = (voted_at IS NULL))
);

CREATE INDEX owner_admission_peer_pending_idx ON owner_admission_peer (user_id) WHERE vote = 'pending';

CREATE TABLE user_proposal (
    id                UUID PRIMARY KEY,
    kind              TEXT NOT NULL,
    subject_user_id   UUID NOT NULL REFERENCES users (id),
    initiator_user_id UUID NOT NULL REFERENCES users (id),
    reason            TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'open',
    owner_count       INTEGER NOT NULL,
    threshold         INTEGER NOT NULL,
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    decided_at        BIGINT,
    void_reason       TEXT NOT NULL DEFAULT '',
    version           BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT user_proposal_kind CHECK (kind IN ('suspension', 'reinstatement', 'admin_admission')),
    CONSTRAINT user_proposal_not_self CHECK (subject_user_id <> initiator_user_id),
    CONSTRAINT user_proposal_state CHECK (state IN ('open', 'executed', 'rejected', 'expired', 'cancelled', 'void')),
    CONSTRAINT user_proposal_reason_len CHECK (char_length(reason) BETWEEN 1 AND 500),
    CONSTRAINT user_proposal_void_reason_len CHECK (char_length(void_reason) <= 200),
    CONSTRAINT user_proposal_needs_a_peer CHECK (owner_count >= 2),
    CONSTRAINT user_proposal_threshold CHECK (threshold BETWEEN 1 AND owner_count - 1),
    CONSTRAINT user_proposal_ttl CHECK (expires_at > created_at),
    CONSTRAINT user_proposal_decided CHECK ((state = 'open') = (decided_at IS NULL)),
    CONSTRAINT user_proposal_void_reason_only_void CHECK (state = 'void' OR void_reason = '')
);

CREATE UNIQUE INDEX user_proposal_open_subject_idx ON user_proposal (subject_user_id, kind) WHERE state = 'open';
CREATE INDEX user_proposal_open_idx ON user_proposal (expires_at) WHERE state = 'open';
CREATE INDEX user_proposal_recent_idx ON user_proposal (created_at DESC);

CREATE TABLE user_proposal_peer (
    proposal_id UUID NOT NULL REFERENCES user_proposal (id),
    user_id     UUID NOT NULL REFERENCES users (id),
    vote        TEXT NOT NULL DEFAULT 'pending',
    voted_at    BIGINT,
    PRIMARY KEY (proposal_id, user_id),
    CONSTRAINT user_proposal_peer_vote CHECK (vote IN ('pending', 'for', 'against')),
    CONSTRAINT user_proposal_peer_voted CHECK ((vote = 'pending') = (voted_at IS NULL))
);

CREATE INDEX user_proposal_peer_pending_idx ON user_proposal_peer (user_id) WHERE vote = 'pending';

CREATE TABLE governance_event (
    position         BIGSERIAL PRIMARY KEY,
    removal_id       UUID REFERENCES owner_removal (id),
    admission_id     UUID REFERENCES owner_admission (id),
    kind             TEXT NOT NULL,
    actor_user_id    UUID REFERENCES users (id),
    version          BIGINT NOT NULL,
    occurred_at      BIGINT NOT NULL,
    client_ip        TEXT NOT NULL DEFAULT '',
    user_agent       TEXT NOT NULL DEFAULT '',
    user_proposal_id UUID REFERENCES user_proposal (id),
    CONSTRAINT governance_event_kind_len CHECK (char_length(kind) <= 64),
    CONSTRAINT governance_event_client_ip_len CHECK (char_length(client_ip) <= 64),
    CONSTRAINT governance_event_user_agent_len CHECK (char_length(user_agent) <= 256),
    CONSTRAINT governance_event_one_subject CHECK (num_nonnulls(removal_id, admission_id, user_proposal_id) = 1)
);

CREATE INDEX governance_event_removal_idx ON governance_event (removal_id, position);
CREATE INDEX governance_event_admission_idx ON governance_event (admission_id, position);
CREATE INDEX governance_event_user_proposal_idx ON governance_event (user_proposal_id, position);

ALTER TABLE admin_action ADD CONSTRAINT admin_action_proposal_id_fkey FOREIGN KEY (proposal_id) REFERENCES user_proposal (id);
