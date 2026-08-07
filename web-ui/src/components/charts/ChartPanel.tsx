import { X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface ChartPanelProps {
  title: string;
  onClose?: () => void;
  children: React.ReactNode;
  className?: string;
}

/** Framed chart slot with optional dismiss (legacy ``.chart`` panel). */
export function ChartPanel({
  title,
  onClose,
  children,
  className,
}: ChartPanelProps) {
  return (
    <div
      className={cn(
        "rounded-md border border-border bg-card p-3 shadow-sm",
        className,
      )}
    >
      <div className="mb-2 flex items-center justify-center gap-2">
        <span className="text-sm font-medium">{title}</span>
        {onClose ? (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-7"
            onClick={onClose}
            aria-label="Hide charts"
          >
            <X className="size-4" />
          </Button>
        ) : null}
      </div>
      {children}
    </div>
  );
}
