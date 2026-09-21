-- The runtime role may use the public schema.
--
-- `pg create-app` grants the runtime role CONNECT on the database and nothing
-- else, and the scratch-database reset drops and recreates this schema, so
-- schema USAGE is an explicit migration step rather than an inherited default.
-- {grant_to} is composed as an identifier by the runner, never formatted.
GRANT USAGE ON SCHEMA public TO {grant_to}
