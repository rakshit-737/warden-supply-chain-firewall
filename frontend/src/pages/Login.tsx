import { useEffect, useState, type FormEvent } from "react";
import { toApiError } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { BrandMark } from "../components/BrandMark";

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    document.title = "Sign in | Warden X";
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email.trim(), password);
    } catch (err) {
      const apiError = toApiError(err);
      // A bare 401 from the login endpoint means the credentials were refused, not an expired session.
      setError(apiError.status === 401 && apiError.code === null ? "The email or password is incorrect." : apiError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-full items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <BrandMark size="lg" />
        <h1 className="mt-8 font-condensed text-2xl font-semibold text-ink">Sign in</h1>
        <p className="mt-1 text-ink-secondary">Use the account your Warden administrator created for you.</p>
        <form
          onSubmit={(event) => void submit(event)}
          className="mt-5 flex flex-col gap-4 rounded-md border border-line bg-panel p-5"
        >
          <div>
            <label htmlFor="login-email" className="label">
              Email
            </label>
            <input
              id="login-email"
              name="email"
              type="email"
              required
              autoComplete="username"
              className="input h-9"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="login-password" className="label">
              Password
            </label>
            <input
              id="login-password"
              name="password"
              type="password"
              required
              autoComplete="current-password"
              className="input h-9"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>
          {error && (
            <p role="alert" className="rounded-r border-l-2 border-sev-critical bg-sunken px-3 py-2 text-ink">
              {error}
            </p>
          )}
          <button type="submit" className="btn-primary h-9 w-full" disabled={busy}>
            {busy ? "Signing in" : "Sign in"}
          </button>
        </form>
      </div>
    </main>
  );
}
