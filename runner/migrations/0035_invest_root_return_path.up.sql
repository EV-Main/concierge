-- `invest` lists `/` among its return paths. Signing out on a scope host goes through
-- `/auth/logout/confirm?return_to=<host origin>/` — the account chip (`web/`) and
-- `@evinvest/concierge` (`sdk/`) send the host's root — and that page takes `return_to`
-- only when its path is byte for byte one of the scope's `return_paths`. 0031 seeded
-- `invest` with `/cabinet` alone, so signing out on invest.evinvest.ltd answered 400 and
-- left the evinvest.ltd session alive. `sa` has had `/` since 0031.
--
-- DATA only, no DDL: the previous binary reads `return_paths` as it is and keeps working.
-- APPENDED, never assigned: a path added to the row by hand since stays where it is. The
-- WHERE skips a row that already lists `/` (no version bump, no SCOPE_CHANGED for
-- nothing) and one already holding 16 paths, where the append would break
-- `tenants_return_paths` and turn this migration into a crash loop on boot — such a row
-- needs a hand edit, and the logout page keeps answering 400 for it until then. `/` passes
-- `scope_return_paths_valid` by its own branch.
--
-- The update bumps `invest`'s version (0031's trigger), and 0034's trigger appends one
-- SCOPE_CHANGED carrying the new `return_paths` to `scope_outbox`, as any registry edit does.
--
-- `lock_timeout`: the UPDATE takes a row lock on `invest` and ROW EXCLUSIVE on `tenants`,
-- which every `GetMe` reads, and the 0034 trigger takes the scope-outbox advisory lock;
-- migrations run ON BOOT. SET LOCAL: a session SET would outlive this migration on the
-- pooled connection.
--
-- REVERSIBILITY: `0035_invest_root_return_path.down.sql` removes `/` from `invest`.
SET LOCAL lock_timeout = '3s';

UPDATE tenants
SET return_paths = array_append(return_paths, '/')
WHERE id = 'invest'
  AND NOT ('/' = ANY (return_paths))
  AND cardinality(return_paths) < 16;
