-- =====================================================
-- ROLLBACK: Remove RLS Policies (if needed)
-- =====================================================
-- Run this to remove all RLS policies and disable RLS
-- Only use this if you need to undo the security policies
-- =====================================================

-- Drop policies for REPORTS
DROP POLICY IF EXISTS "Allow all operations on reports" ON public.reports;
DROP POLICY IF EXISTS "Postgres role full access to reports" ON public.reports;
ALTER TABLE public.reports DISABLE ROW LEVEL SECURITY;

-- Drop policies for USERS
DROP POLICY IF EXISTS "Allow all operations on users" ON public.users;
DROP POLICY IF EXISTS "Postgres role full access to users" ON public.users;
ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;

-- Drop policies for PROJECT_DEFS
DROP POLICY IF EXISTS "Allow all operations on project_defs" ON public.project_defs;
DROP POLICY IF EXISTS "Postgres role full access to project_defs" ON public.project_defs;
ALTER TABLE public.project_defs DISABLE ROW LEVEL SECURITY;

-- Drop policies for PASSWORD_RESET_TOKENS
DROP POLICY IF EXISTS "Allow all operations on password_reset_tokens" ON public.password_reset_tokens;
DROP POLICY IF EXISTS "Postgres role full access to password_reset_tokens" ON public.password_reset_tokens;
ALTER TABLE public.password_reset_tokens DISABLE ROW LEVEL SECURITY;

-- Drop policies for LOGIN_EVENTS
DROP POLICY IF EXISTS "Allow all operations on login_events" ON public.login_events;
DROP POLICY IF EXISTS "Postgres role full access to login_events" ON public.login_events;
ALTER TABLE public.login_events DISABLE ROW LEVEL SECURITY;

-- Drop policies for FAILED_LOGIN_ATTEMPTS
DROP POLICY IF EXISTS "Allow all operations on failed_login_attempts" ON public.failed_login_attempts;
DROP POLICY IF EXISTS "Postgres role full access to failed_login_attempts" ON public.failed_login_attempts;
ALTER TABLE public.failed_login_attempts DISABLE ROW LEVEL SECURITY;

-- Verify RLS is disabled
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public' 
AND tablename IN ('reports', 'users', 'project_defs', 'password_reset_tokens', 'login_events', 'failed_login_attempts');
