import { ChevronDown, ChevronUp, Plus, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  type ReportColor,
  type ReportElement,
  REPORT_COLORS,
  REPORT_ELEMENT_TYPES,
  swapReportElements,
} from "@/lib/report-elements";

export interface ReportElementEditorProps {
  elements: ReportElement[];
  onChange: (elements: ReportElement[]) => void;
  curType: ReportElement["type"];
  onCurTypeChange: (type: ReportElement["type"]) => void;
  curTitle: string;
  onCurTitleChange: (title: string) => void;
  curParam: string;
  onCurParamChange: (param: string) => void;
  curColor: number;
  onCurColorChange: (color: number) => void;
  onAdd: () => void;
}

/**
 * Configuration table for report chart rows (legacy report.html
 * configuration section).
 */
export function ReportElementEditor({
  elements,
  onChange,
  curType,
  onCurTypeChange,
  curTitle,
  onCurTitleChange,
  curParam,
  onCurParamChange,
  curColor,
  onCurColorChange,
  onAdd,
}: ReportElementEditorProps) {
  return (
    <div className="space-y-4">
      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/40 text-left">
              <th className="px-3 py-2 font-medium">Type</th>
              <th className="px-3 py-2 font-medium">Parameters</th>
              <th className="px-3 py-2 font-medium">Text</th>
              <th className="px-3 py-2 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {elements.map((element, index) => (
              <ReportElementRow
                key={`${index}-${element.parameters}`}
                element={element}
                index={index}
                total={elements.length}
                onRemove={() =>
                  onChange(elements.filter((_, i) => i !== index))
                }
                onMoveUp={() =>
                  onChange(swapReportElements(elements, index, index - 1))
                }
                onMoveDown={() =>
                  onChange(swapReportElements(elements, index, index + 1))
                }
              />
            ))}
            <tr className="border-t border-border">
              <td className="px-3 py-2">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm" className="gap-1">
                      {curType}
                      <ChevronDown className="size-3" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start">
                    {REPORT_ELEMENT_TYPES.map((type) => (
                      <DropdownMenuItem
                        key={type}
                        onSelect={() => onCurTypeChange(type)}
                      >
                        {type}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              </td>
              <td className="px-3 py-2">
                <Input
                  placeholder="Parameters"
                  value={curParam}
                  onChange={(e) => onCurParamChange(e.target.value)}
                  aria-label="New element parameters"
                />
              </td>
              <td className="px-3 py-2">
                <Input
                  placeholder="Title"
                  value={curTitle}
                  onChange={(e) => onCurTitleChange(e.target.value)}
                  aria-label="New element title"
                />
              </td>
              <td className="px-3 py-2">
                <div className="flex items-center gap-1">
                  <ColorPicker value={curColor} onChange={onCurColorChange} />
                  <Button
                    type="button"
                    size="icon"
                    variant="outline"
                    onClick={onAdd}
                    aria-label="Add element"
                  >
                    <Plus className="size-4" />
                  </Button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ReportElementRow({
  element,
  index,
  total,
  onRemove,
  onMoveUp,
  onMoveDown,
}: {
  element: ReportElement;
  index: number;
  total: number;
  onRemove: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
}) {
  const palette = REPORT_COLORS[element.color] ?? REPORT_COLORS[0];
  return (
    <tr style={{ backgroundColor: palette.bg, color: palette.fg }}>
      <td className="px-3 py-2">{element.type}</td>
      <td className="px-3 py-2 font-mono text-xs">{element.parameters}</td>
      <td className="px-3 py-2">{element.text}</td>
      <td className="px-3 py-2">
        <div className="flex gap-1">
          <Button
            type="button"
            size="icon"
            variant="outline"
            onClick={onRemove}
            aria-label="Remove element"
          >
            <Trash2 className="size-4" />
          </Button>
          <Button
            type="button"
            size="icon"
            variant="outline"
            disabled={index === 0}
            onClick={onMoveUp}
            aria-label="Move up"
          >
            <ChevronUp className="size-4" />
          </Button>
          <Button
            type="button"
            size="icon"
            variant="outline"
            disabled={index === total - 1}
            onClick={onMoveDown}
            aria-label="Move down"
          >
            <ChevronDown className="size-4" />
          </Button>
        </div>
      </td>
    </tr>
  );
}

function ColorPicker({
  value,
  onChange,
}: {
  value: number;
  onChange: (index: number) => void;
}) {
  const current = REPORT_COLORS[value] ?? REPORT_COLORS[0];
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="outline"
          size="sm"
          style={{ backgroundColor: current.bg, color: current.fg }}
        >
          Color
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        {REPORT_COLORS.map((color: ReportColor, index) => (
          <DropdownMenuItem
            key={index}
            onSelect={() => onChange(index)}
            style={{ backgroundColor: color.bg, color: color.fg }}
          >
            Use it
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
