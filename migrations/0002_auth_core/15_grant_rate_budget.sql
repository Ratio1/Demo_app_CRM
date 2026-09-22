-- Same counter read-modify-write as login_throttle, same reasoning: SELECT to
-- read the post-increment value back in the same transaction, UPDATE to
-- increment, INSERT for the first request of a window. No DELETE.
GRANT SELECT, INSERT, UPDATE ON TABLE public.rate_budget TO {grant_to}
