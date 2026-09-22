-- The runtime role reads, creates and edits contacts.
--
-- NO DELETE: the product archives, it never deletes. The absence is
-- the control — `archive_contact` could not be written as a DELETE even by
-- mistake, because the privilege is not there.
GRANT SELECT, INSERT, UPDATE ON TABLE public.contacts TO {grant_to}
