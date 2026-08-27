import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { DEMO_ACCOUNTS, type Role, type SessionUser } from "./data";

const STORAGE_KEY = "adshield.session";

interface AuthValue {
  user: SessionUser | null;
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
  const [user, setUser] = useState<SessionUser | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (raw) setUser(JSON.parse(raw) as SessionUser);
    } catch {
      /* corrupted session — start signed out */
    }
    setReady(true);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    await new Promise((r) => setTimeout(r, 450)); // simulated LDAP bind latency
    const account = DEMO_ACCOUNTS[username.trim().toLowerCase()];
    // Constant response for unknown user vs. bad password — no user enumeration.
    if (!account || account.password !== password) {
      throw new Error("Invalid domain credentials.");
    }
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(account.user));
    setUser(account.user);
    return account.user;
  }, []);

  const logout = useCallback(() => {
    window.localStorage.removeItem(STORAGE_KEY);
    setUser(null);
  }, []);

  const value = useMemo<AuthValue>(
    () => ({
      user,
      ready,
      login,
      logout,
      can: (permission: string) => !!user?.permissions.includes(permission),
    }),
    [user, ready, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
