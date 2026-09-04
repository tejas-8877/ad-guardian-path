import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { ApiError, api, AUTH_EXPIRED_EVENT, setToken, toSessionUser } from "./api";
import { DEMO_ACCOUNTS, type Role, type SessionUser } from "./data";

const STORAGE_KEY = "adshield.session";

/** "live" = data comes from the FastAPI backend. "demo" = local fixtures. */
export type DataMode = "live" | "demo";

interface StoredSession {
  user: SessionUser;
  mode: DataMode;
}

interface AuthValue {
  user: SessionUser | null;
  mode: DataMode;
  ready: boolean;
  login: (username: string, password: string) => Promise<SessionUser>;
  logout: () => void;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthValue | null>(null);

export const ROLE_LABEL: Record<Role, string> = {
  standard_user: "Standard User",
  it_support: "IT Support",
  security_admin: "Security Admin",
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<StoredSession | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as StoredSession | SessionUser;
        // Backwards compatible with the pre-backend session shape.
        setSession(
          "user" in parsed ? parsed : { user: parsed as SessionUser, mode: "demo" },
        );
      }
    } catch {
      /* corrupted session — start signed out */
    }
    setReady(true);
  }, []);

  const logout = useCallback(() => {
    window.localStorage.removeItem(STORAGE_KEY);
    setToken(null);
    setSession(null);
  }, []);

  // A 401 from any API call invalidates the local session immediately.
  useEffect(() => {
    const handler = () => logout();
    window.addEventListener(AUTH_EXPIRED_EVENT, handler);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, handler);
  }, [logout]);

  const persist = useCallback((next: StoredSession) => {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    setSession(next);
  }, []);

  const login = useCallback(
    async (username: string, password: string) => {
      try {
        const res = await api.login(username.trim(), password);
        setToken(res.access_token);
        const user = toSessionUser(res.user);
        persist({ user, mode: "live" });
        return user;
      } catch (error) {
        const unreachable = error instanceof ApiError && error.kind === "network";
        if (!unreachable) throw error;

        // Backend offline: allow the documented demo fixtures so the UI can be
        // reviewed without FastAPI running. The mode flag makes this visible.
        const account = DEMO_ACCOUNTS[username.trim().toLowerCase()];
        if (!account || account.password !== password) throw error;
        setToken(null);
        persist({ user: account.user, mode: "demo" });
        return account.user;
      }
    },
    [persist],
  );

  const value = useMemo<AuthValue>(
    () => ({
      user: session?.user ?? null,
      mode: session?.mode ?? "demo",
      ready,
      login,
      logout,
      can: (permission: string) => !!session?.user.permissions.includes(permission),
    }),
    [session, ready, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}

/** True when the app should call the backend instead of using fixtures. */
export function useLive(): boolean {
  return useAuth().mode === "live";
}
