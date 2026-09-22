-- Write-once receipts: SELECT to replay, INSERT to
-- record. NO UPDATE — a receipt whose stored outcome could be rewritten would
-- let a second submission change what the first one is replayed as. NO DELETE —
-- expiry is `manage cleanup`'s job, under the maintenance role.
GRANT SELECT, INSERT ON TABLE public.mutation_receipts TO {grant_to}
