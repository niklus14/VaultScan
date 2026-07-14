/**
 * Client-side auth session — token stays in localStorage so users stay signed in.
 */

const TOKEN_KEY = "vaultscan_auth_token_v1";
const USER_KEY = "vaultscan_auth_user_v1";
const REMEMBER_USER_KEY = "vaultscan_remember_username_v1";

export type AuthSession = {
  token: string;
  username: string;
  display_name: string;
  role?: string;
  expires_at?: string;
  remember?: boolean;
};

export function saveSession(session: AuthSession) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(TOKEN_KEY, session.token);
    localStorage.setItem(
      USER_KEY,
      JSON.stringify({
        username: session.username,
        display_name: session.display_name,
        role: session.role,
        expires_at: session.expires_at,
        remember: session.remember,
      }),
    );
    if (session.remember !== false) {
      localStorage.setItem(REMEMBER_USER_KEY, session.username);
    }
  } catch {
    /* private mode */
  }
}

export function clearSession() {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  } catch {
    /* ignore */
  }
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getStoredUser(): Omit<AuthSession, "token"> | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(USER_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as Omit<AuthSession, "token">;
  } catch {
    return null;
  }
}

export function getRememberedUsername(): string {
  if (typeof window === "undefined") return "";
  try {
    return localStorage.getItem(REMEMBER_USER_KEY) || "";
  } catch {
    return "";
  }
}

export function isLoggedIn(): boolean {
  return Boolean(getToken());
}
