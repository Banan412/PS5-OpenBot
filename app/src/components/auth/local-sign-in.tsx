import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export type LocalSignInValues = {
  email: string;
  password: string;
  setupCode?: string;
  name?: string;
};

type LocalSignInProps = {
  /** Setup mode must only be advertised when the server allows first-admin setup. */
  setup: boolean;
  requireSetupCode?: boolean;
  pending: boolean;
  error?: string | null;
  onSubmit: (values: LocalSignInValues) => Promise<void>;
};

/** UI only. The caller is responsible for server capability checks and session handling. */
export function LocalSignIn({
  setup,
  requireSetupCode = true,
  pending,
  error,
  onSubmit,
}: LocalSignInProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [setupCode, setSetupCode] = useState("");
  const [name, setName] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const values: LocalSignInValues = {
      email: email.trim(),
      password,
      ...(setup
        ? {
            name: name.trim(),
            ...(requireSetupCode ? { setupCode: setupCode.trim() } : {}),
          }
        : {}),
    };
    setSubmitError(null);
    try {
      await onSubmit(values);
    } catch {
      setSubmitError("Could not sign in. Please try again.");
    } finally {
      setPassword("");
      setSetupCode("");
    }
  }

  return (
    <form className="flex flex-col gap-3" onSubmit={submit}>
      {setup ? (
        <>
          <label className="text-sm" htmlFor="local-name">
            Name
          </label>
          <Input
            autoComplete="name"
            disabled={pending}
            id="local-name"
            maxLength={200}
            onChange={(event) => setName(event.target.value)}
            required
            value={name}
          />
        </>
      ) : null}
      <label className="text-sm" htmlFor="local-email">
        Email
      </label>
      <Input
        autoComplete="username"
        disabled={pending}
        id="local-email"
        onChange={(event) => setEmail(event.target.value)}
        required
        type="email"
        value={email}
      />
      <label className="text-sm" htmlFor="local-password">
        Password
      </label>
      <Input
        autoComplete={setup ? "new-password" : "current-password"}
        disabled={pending}
        id="local-password"
        minLength={setup ? 12 : undefined}
        onChange={(event) => setPassword(event.target.value)}
        placeholder={setup ? "At least 12 characters" : undefined}
        required
        type="password"
        value={password}
      />
      {setup && requireSetupCode ? (
        <>
          <label className="text-sm" htmlFor="local-setup-code">
            Setup code
          </label>
          <Input
            autoComplete="off"
            disabled={pending}
            id="local-setup-code"
            onChange={(event) => setSetupCode(event.target.value)}
            required
            type="text"
            value={setupCode}
          />
        </>
      ) : null}
      {error || submitError ? (
        <p className="text-sm text-destructive" role="alert">
          {error || submitError}
        </p>
      ) : null}
      <Button disabled={pending} type="submit">
        {pending ? "Please wait…" : setup ? "Create administrator" : "Sign in"}
      </Button>
    </form>
  );
}
