-- Email lookup and email-prefix search inside an agent's scope. It also
-- indexes the `owner_id` foreign key (§2.3 rule 5), which step 02 already
-- satisfies on its own.
CREATE INDEX ix_contacts_owner_email ON public.contacts (owner_id, email_lower)
