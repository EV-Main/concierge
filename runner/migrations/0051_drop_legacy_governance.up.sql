-- The legacy consilia go (`GovernanceService`, `OwnerRemovalApprovalService`): the decisions
-- about people live in `approvals` alone. Contracting.
--
-- REFUSES while any of the tables holds a row — an open proposal OR a decided one: who held
-- a seat, and by whose decision, is not this migration's to discard. The boot fails with the
-- tables named and the transaction drops nothing. A disposable database that ran the old
-- suites is cleared by hand (`TRUNCATE governance_event, owner_removal_token,
-- owner_removal_peer, owner_removal, owner_admission_peer, owner_admission,
-- user_proposal_peer, user_proposal`, after nulling `admin_action.proposal_id`).
--
-- `admin_action.proposal_id` loses its foreign key and keeps the column: a binary from before
-- this migration names it in every `admin_action` INSERT (always NULL by then). It is dropped
-- by a later migration, once no such binary runs. `governance_revision` stays: it orders
-- every write of a seat.
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    holding TEXT;
BEGIN
    SELECT string_agg(name, ', ') INTO holding FROM (
        SELECT 'owner_removal' AS name WHERE EXISTS (SELECT 1 FROM owner_removal)
        UNION ALL SELECT 'owner_removal_peer' WHERE EXISTS (SELECT 1 FROM owner_removal_peer)
        UNION ALL SELECT 'owner_removal_token' WHERE EXISTS (SELECT 1 FROM owner_removal_token)
        UNION ALL SELECT 'owner_admission' WHERE EXISTS (SELECT 1 FROM owner_admission)
        UNION ALL SELECT 'owner_admission_peer' WHERE EXISTS (SELECT 1 FROM owner_admission_peer)
        UNION ALL SELECT 'user_proposal' WHERE EXISTS (SELECT 1 FROM user_proposal)
        UNION ALL SELECT 'user_proposal_peer' WHERE EXISTS (SELECT 1 FROM user_proposal_peer)
        UNION ALL SELECT 'governance_event' WHERE EXISTS (SELECT 1 FROM governance_event)
        UNION ALL SELECT 'admin_action.proposal_id' WHERE EXISTS (SELECT 1 FROM admin_action WHERE proposal_id IS NOT NULL)
    ) AS t;
    IF holding IS NOT NULL THEN
        RAISE EXCEPTION 'the legacy governance tables still hold rows (%); they are dropped only empty', holding;
    END IF;
END
$$;

ALTER TABLE admin_action DROP CONSTRAINT admin_action_proposal_id_fkey;

DROP TABLE governance_event, owner_removal_token, owner_removal_peer, owner_removal, owner_admission_peer, owner_admission, user_proposal_peer, user_proposal;
