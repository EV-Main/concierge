import { useT } from "@evinvest/i18n/react";
import { DialogClose } from "@evinvest/uikit";
import { X } from "lucide-react";

/**
 * The dialog's corner close, in the reader's language. shortcut: the kit's `DialogContent`
 * names its own close "Close" in every language and takes no label; render it again
 * (`showCloseButton`) once it does.
 */
export function DialogCloseButton() {
  const t = useT();
  return (
    <DialogClose
      type="button"
      className="absolute top-4 right-4 rounded-xs opacity-70 transition-opacity hover:opacity-100 focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:outline-hidden"
    >
      <X className="size-4" aria-hidden />
      <span className="sr-only">{t("ui.close", "Close")}</span>
    </DialogClose>
  );
}
