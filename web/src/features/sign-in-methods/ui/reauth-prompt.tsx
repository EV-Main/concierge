import { ReauthBody } from "./reauth-body";
import { ReauthStep } from "./reauth-step";

interface ReauthPromptProps {
  sub: string;
  onConfirmed: () => void;
  onCancel: () => void;
}

/** The inline confirmation step for an act of another feature, composed in by the page. */
export function ReauthPrompt({ sub, onConfirmed, onCancel }: ReauthPromptProps) {
  return (
    <ReauthStep sub={sub} onCancel={onCancel}>
      <ReauthBody onConfirmed={onConfirmed} />
    </ReauthStep>
  );
}
