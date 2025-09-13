import { useState } from "react";
import { CalendarDays, ChevronDown, AlertCircle } from "lucide-react";
import { format, subDays, subMonths, subYears, isAfter, isBefore, differenceInDays } from "date-fns";
import { DateRange } from "react-day-picker";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface DateRangePickerProps {
  className?: string;
  value?: DateRange;
  onChange: (range: DateRange | undefined) => void;
  placeholder?: string;
  maxDays?: number; // Maximum number of days allowed in range
  minDate?: Date; // Earliest selectable date
  maxDate?: Date; // Latest selectable date
}

interface PresetOption {
  label: string;
  value: string;
  getRange: () => DateRange;
}

export function DateRangePicker({
  className,
  value,
  onChange,
  placeholder = "Select date range",
  maxDays = 1825, // 5 years max
  minDate,
  maxDate = new Date(),
}: DateRangePickerProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [validationMessage, setValidationMessage] = useState<string | null>(null);

  const presets: PresetOption[] = [
    {
      label: "Last 7 days",
      value: "7d",
      getRange: () => ({
        from: subDays(new Date(), 7),
        to: new Date(),
      }),
    },
    {
      label: "Last 30 days",
      value: "30d",
      getRange: () => ({
        from: subDays(new Date(), 30),
        to: new Date(),
      }),
    },
    {
      label: "Last 3 months",
      value: "3m",
      getRange: () => ({
        from: subMonths(new Date(), 3),
        to: new Date(),
      }),
    },
    {
      label: "Last 6 months",
      value: "6m",
      getRange: () => ({
        from: subMonths(new Date(), 6),
        to: new Date(),
      }),
    },
    {
      label: "Last 1 year",
      value: "1y",
      getRange: () => ({
        from: subYears(new Date(), 1),
        to: new Date(),
      }),
    },
    {
      label: "Last 2 years",
      value: "2y",
      getRange: () => ({
        from: subYears(new Date(), 2),
        to: new Date(),
      }),
    },
    {
      label: "Last 3 years",
      value: "3y",
      getRange: () => ({
        from: subYears(new Date(), 3),
        to: new Date(),
      }),
    },
    {
      label: "Last 5 years",
      value: "5y",
      getRange: () => ({
        from: subYears(new Date(), 5),
        to: new Date(),
      }),
    },
  ];

  const handlePresetSelect = (presetValue: string) => {
    const preset = presets.find((p) => p.value === presetValue);
    if (preset) {
      const range = preset.getRange();
      onChange(range);
    }
  };

  const handleDateRangeSelect = (range: DateRange | undefined) => {
    // Clear any existing validation message
    setValidationMessage(null);
    
    if (!range) {
      onChange(undefined);
      return;
    }

    // Validate date range
    if (range.from && range.to) {
      // Check if start is after end
      if (isAfter(range.from, range.to)) {
        setValidationMessage("Start date must be before end date");
        return;
      }

      // Check maximum days limit
      const daysDiff = differenceInDays(range.to, range.from);
      if (daysDiff > maxDays) {
        setValidationMessage(`Maximum range is ${maxDays} days (${Math.round(maxDays/365)} years). Selected: ${daysDiff} days.`);
        return;
      }

      // Check date bounds
      if (minDate && isBefore(range.from, minDate)) {
        setValidationMessage(`Start date cannot be before ${format(minDate, "MMM d, yyyy")}`);
        return;
      }
      if (maxDate && isAfter(range.to, maxDate)) {
        setValidationMessage(`End date cannot be after ${format(maxDate, "MMM d, yyyy")}`);
        return;
      }
    }

    onChange(range);
  };

  const formatRange = (range: DateRange | undefined) => {
    if (!range?.from) {
      return placeholder;
    }
    
    if (!range.to) {
      return format(range.from, "MMM d, yyyy") + " -";
    }
    
    if (range.from.getTime() === range.to.getTime()) {
      return format(range.from, "MMM d, yyyy");
    }
    
    return `${format(range.from, "MMM d, yyyy")} - ${format(range.to, "MMM d, yyyy")}`;
  };

  const getCurrentPreset = () => {
    if (!value?.from || !value?.to) return "";
    
    return presets.find(preset => {
      const presetRange = preset.getRange();
      return (
        format(value.from!, "yyyy-MM-dd") === format(presetRange.from!, "yyyy-MM-dd") &&
        format(value.to!, "yyyy-MM-dd") === format(presetRange.to!, "yyyy-MM-dd")
      );
    })?.value || "";
  };

  return (
    <div className={cn("grid gap-2", className)}>
      <Popover open={isOpen} onOpenChange={setIsOpen}>
        <PopoverTrigger asChild>
          <Button
            id="date-range-picker"
            variant="outline"
            className={cn(
              "w-full justify-start text-left font-normal",
              !value && "text-muted-foreground"
            )}
            data-testid="button-date-range-picker"
          >
            <CalendarDays className="mr-2 h-4 w-4" />
            {formatRange(value)}
            <ChevronDown className="ml-auto h-4 w-4 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-auto p-0" align="start">
          <div className="flex">
            {/* Preset Options */}
            <div className="border-r p-3 w-48">
              <div className="mb-3">
                <label htmlFor="preset-select" className="text-sm font-medium">Quick Presets</label>
              </div>
              <Select value={getCurrentPreset()} onValueChange={handlePresetSelect}>
                <SelectTrigger id="preset-select" className="w-full" data-testid="select-preset">
                  <SelectValue placeholder="Choose preset" />
                </SelectTrigger>
                <SelectContent>
                  {presets.map((preset) => (
                    <SelectItem key={preset.value} value={preset.value}>
                      {preset.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              
              <div className="mt-4 space-y-1">
                {presets.slice(0, 4).map((preset) => (
                  <Button
                    key={preset.value}
                    variant="ghost"
                    className="w-full justify-start text-sm"
                    onClick={() => handlePresetSelect(preset.value)}
                    data-testid={`button-preset-${preset.value}`}
                  >
                    {preset.label}
                  </Button>
                ))}
              </div>
            </div>
            
            {/* Calendar */}
            <div className="p-3">
              <Calendar
                initialFocus
                mode="range"
                defaultMonth={value?.from}
                selected={value}
                onSelect={handleDateRangeSelect}
                numberOfMonths={2}
                disabled={(date) => {
                  if (minDate && isBefore(date, minDate)) return true;
                  if (maxDate && isAfter(date, maxDate)) return true;
                  return false;
                }}
                data-testid="calendar-date-range"
              />
              
              {/* Validation Message */}
              {validationMessage && (
                <div className="pt-3 border-t mt-3">
                  <div className="flex items-center gap-2 text-sm text-destructive">
                    <AlertCircle className="h-4 w-4" />
                    {validationMessage}
                  </div>
                </div>
              )}
              
              {/* Range Info */}
              {value?.from && value?.to && !validationMessage && (
                <div className="pt-3 border-t mt-3">
                  <div className="text-sm text-muted-foreground">
                    Selected range: {differenceInDays(value.to, value.from) + 1} days
                  </div>
                  {maxDays && differenceInDays(value.to, value.from) > maxDays && (
                    <div className="text-sm text-destructive mt-1">
                      Range too large (max {maxDays} days)
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </PopoverContent>
      </Popover>
    </div>
  );
}