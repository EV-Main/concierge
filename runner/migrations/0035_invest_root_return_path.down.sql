-- Removes `/` from `invest` and leaves every other path where it stands. Nothing records
-- whether `/` arrived by 0035 or by a hand edit made before it (0035 then skipped the
-- row), so the down cannot tell them apart; it removes `/` either way. That is safe:
-- no code reads `invest`'s `/` beyond the returnTo and logout checks, and the only reason
-- to have added it by hand is the one 0035 fixes. After this, signing out on
-- invest.evinvest.ltd answers 400 again until `/` is back.
SET LOCAL lock_timeout = '3s';

UPDATE tenants
SET return_paths = array_remove(return_paths, '/')
WHERE id = 'invest'
  AND '/' = ANY (return_paths);
