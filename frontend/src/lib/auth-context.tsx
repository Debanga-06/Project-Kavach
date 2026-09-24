import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { fetchMe, loginUser, registerUser, type UserOut } from "./api";

interface AuthState {
  user: UserOut | null;
  accessToken: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

const STORAGE_KEY = "kavachai_access_token";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserOut | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(() =>
    localStorage.getItem(STORAGE_KEY)
  );
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function hydrate() {
      if (!accessToken) {
        setLoading(false);
        return;
      }
      try {
        const me = await fetchMe(accessToken);
        if (!cancelled) setUser(me);
      } catch {
        if (!cancelled) {
          setAccessToken(null);
          localStorage.removeItem(STORAGE_KEY);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    hydrate();
    return () => {
      cancelled = true;
    };
  }, [accessToken]);

  async function login(email: string, password: string) {
    const tokens = await loginUser(email, password);
    localStorage.setItem(STORAGE_KEY, tokens.access_token);
    setAccessToken(tokens.access_token);
    const me = await fetchMe(tokens.access_token);
    setUser(me);
  }

  async function register(name: string, email: string, password: string) {
    await registerUser(name, email, password);
    await login(email, password);
  }

  function logout() {
    localStorage.removeItem(STORAGE_KEY);
    setAccessToken(null);
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, accessToken, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
