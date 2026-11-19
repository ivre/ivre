import { toast } from "sonner";

export async function copyText(
  text: string,
  label = "Copied to clipboard",
): Promise<void> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      toast.success(label);
      return;
    }
  } catch {
    // An insecure context or browser permission may deny clipboard access.
  }
  toast.message("Copy manually", { description: text, duration: 15_000 });
}
