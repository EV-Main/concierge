import { DialogDescription, DialogHeader, DialogTitle } from "@evinvest/uikit";
import { createContext, useContext, type FormEvent, type ReactNode } from "react";

// Proportions are openmarket's sign-in form (the reference the cabinet dialog was drawn
// from), on our tokens; the off-scale steps are the `--sign-in-*` properties in
// styles/element-tokens.css.
export const FIELD =
  "h-12 rounded-(--sign-in-radius) border-ink/10 bg-ink/2 px-3.5 text-(length:--sign-in-text-body) shadow-none transition-[background-color,border-color] hover:border-ink/14 focus-visible:border-ink/18 focus-visible:bg-ink/4 focus-visible:ring-0 md:text-(length:--sign-in-text-body)";
export const PRIMARY =
  "h-11.5 w-full rounded-(--sign-in-radius) bg-ink text-sm font-bold tracking-[-0.01em] text-background hover:bg-ink/90 disabled:bg-ink/4 disabled:text-ink-soft disabled:opacity-100";
export const SECONDARY =
  "inline-flex h-11.5 w-full cursor-pointer items-center justify-center gap-2.5 rounded-(--sign-in-radius) border border-transparent bg-ink/4 px-3.5 text-(length:--sign-in-text-body) font-semibold tracking-[-0.01em] text-ink no-underline transition-colors hover:border-ink/14 hover:bg-ink/6 disabled:cursor-default disabled:hover:border-transparent";

/**
 * The dialog's `aria-labelledby` target. The kit's Dialog does not wire its title to the
 * content, and every screen draws its own heading, so the id travels by context.
 */
export const TitleIdContext = createContext<string | undefined>(undefined);

export function Heading({ title, description }: { title: string; description?: string }) {
  const id = useContext(TitleIdContext);
  return (
    <DialogHeader className="gap-1.5 text-center sm:text-center">
      <DialogTitle id={id} className="text-(length:--sign-in-text-title) leading-normal tracking-[-0.01em]">{title}</DialogTitle>
      {description && <DialogDescription className="text-(length:--sign-in-text-body) leading-snug">{description}</DialogDescription>}
    </DialogHeader>
  );
}

/** A quiet text action under a form ("Sign in with a password instead"). */
export function TextAction({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} className="cursor-pointer bg-transparent p-0 text-xs font-medium text-ink-soft transition-colors hover:text-ink">
      {children}
    </button>
  );
}

export function looksLikeEmail(raw: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw.trim());
}

export function submitWith(handler: () => void) {
  return (event: FormEvent) => {
    event.preventDefault();
    handler();
  };
}
