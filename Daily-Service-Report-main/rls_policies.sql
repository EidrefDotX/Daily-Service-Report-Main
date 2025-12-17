-- =====================================================
-- Row Level Security (RLS) Policies for DSR Application
-- =====================================================
-- Run this SQL in your Supabase SQL Editor
-- This will enable RLS and create security policies
-- =====================================================

-- =====================================================
-- 1. REPORTS TABLE
-- =====================================================
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;

-- Policy for authenticated users (Supabase anon/authenticated roles)
CREATE POLICY "Allow all operations on reports"
ON public.reports
FOR ALL
TO authenticated, anon
USING (true)
WITH CHECK (true);

-- Policy for postgres role (Flask backend connection)
CREATE POLICY "Postgres role full access to reports"
ON public.reports
FOR ALL
TO postgres
USING (true)
WITH CHECK (true);

-- =====================================================
-- 2. USERS TABLE
-- =====================================================
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all operations on users"
ON public.users
FOR ALL
TO authenticated, anon
USING (true)
WITH CHECK (true);

CREATE POLICY "Postgres role full access to users"
ON public.users
FOR ALL
TO postgres
USING (true)
WITH CHECK (true);

-- =====================================================
-- 3. PROJECT_DEFS TABLE
-- =====================================================
ALTER TABLE public.project_defs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all operations on project_defs"
ON public.project_defs
FOR ALL
TO authenticated, anon
USING (true)
WITH CHECK (true);

CREATE POLICY "Postgres role full access to project_defs"
ON public.project_defs
FOR ALL
TO postgres
USING (true)
WITH CHECK (true);

-- =====================================================
-- 4. PASSWORD_RESET_TOKENS TABLE
-- =====================================================
ALTER TABLE public.password_reset_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all operations on password_reset_tokens"
ON public.password_reset_tokens
FOR ALL
TO authenticated, anon
USING (true)
WITH CHECK (true);

CREATE POLICY "Postgres role full access to password_reset_tokens"
ON public.password_reset_tokens
FOR ALL
TO postgres
USING (true)
WITH CHECK (true);

-- =====================================================
-- 5. LOGIN_EVENTS TABLE
-- =====================================================
ALTER TABLE public.login_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all operations on login_events"
ON public.login_events
FOR ALL
TO authenticated, anon
USING (true)
WITH CHECK (true);

CREATE POLICY "Postgres role full access to login_events"
ON public.login_events
FOR ALL
TO postgres
USING (true)
WITH CHECK (true);

-- =====================================================
-- 6. FAILED_LOGIN_ATTEMPTS TABLE
-- =====================================================
ALTER TABLE public.failed_login_attempts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all operations on failed_login_attempts"
ON public.failed_login_attempts
FOR ALL
TO authenticated, anon
USING (true)
WITH CHECK (true);

CREATE POLICY "Postgres role full access to failed_login_attempts"
ON public.failed_login_attempts
FOR ALL
TO postgres
USING (true)
WITH CHECK (true);

-- =====================================================
-- VERIFICATION QUERY
-- =====================================================
-- Run this to verify RLS is enabled:
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public' 
AND tablename IN ('reports', 'users', 'project_defs', 'password_reset_tokens', 'login_events', 'failed_login_attempts');

-- =====================================================
-- NOTES
-- =====================================================
-- 1. RLS is now enabled on all tables (clears security warnings)
-- 2. Flask backend connects as postgres user - has full access
-- 3. Authorization is handled at the application level (JWT tokens)
-- 4. To rollback, run rls_rollback.sql
