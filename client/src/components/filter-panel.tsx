import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Star, Eye, EyeOff } from "lucide-react";
import type { CveFilters } from "@/types/cve";

interface FilterPanelProps {
  filters: CveFilters;
  onFiltersChange: (filters: CveFilters) => void;
  onApplyFilters: () => void;
  onClearFilters: () => void;
}

export function FilterPanel({ filters, onFiltersChange, onApplyFilters, onClearFilters }: FilterPanelProps) {
  const handleSeverityChange = (severity: string, checked: boolean) => {
    const currentSeverity = filters.severity || [];
    if (checked) {
      onFiltersChange({ ...filters, severity: [...currentSeverity, severity] });
    } else {
      onFiltersChange({ ...filters, severity: currentSeverity.filter(s => s !== severity) });
    }
  };

  const handleTechnologyChange = (technology: string, checked: boolean) => {
    const currentTechnology = filters.technology || [];
    if (checked) {
      onFiltersChange({ ...filters, technology: [...currentTechnology, technology] });
    } else {
      onFiltersChange({ ...filters, technology: currentTechnology.filter(t => t !== technology) });
    }
  };

  const handleStatusChange = (status: string, checked: boolean) => {
    const currentStatus = filters.status || [];
    if (checked) {
      onFiltersChange({ ...filters, status: [...currentStatus, status] });
    } else {
      onFiltersChange({ ...filters, status: currentStatus.filter(s => s !== status) });
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'new': return '🆕 New';
      case 'in_progress': return '⏳ In Progress';
      case 'done': return '✅ Done';
      case 'unlisted': return '📥 Unlisted';
      default: return status;
    }
  };

  return (
    <div className="lg:w-80 bg-card p-6 rounded-lg border border-border" data-testid="filter-panel">
      <h3 className="text-lg font-semibold mb-4">Filters</h3>
      
      {/* Timeframe */}
      <div className="mb-4">
        <Label className="block text-sm font-medium mb-2">Timeframe</Label>
        <Select defaultValue="3" onValueChange={(value) => console.log('Timeframe:', value)} data-testid="select-timeframe">
          <SelectTrigger className="w-full">
            <SelectValue placeholder="Select timeframe" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="3">Last 3 years</SelectItem>
            <SelectItem value="2">Last 2 years</SelectItem>
            <SelectItem value="1">Last year</SelectItem>
            <SelectItem value="0.5">Last 6 months</SelectItem>
          </SelectContent>
        </Select>
      </div>
      
      {/* Severity */}
      <div className="mb-4">
        <Label className="block text-sm font-medium mb-2">Severity</Label>
        <div className="space-y-2">
          {[
            { value: 'CRITICAL', label: 'Critical (9.0-10.0)', checked: filters.severity?.includes('CRITICAL') },
            { value: 'HIGH', label: 'High (7.0-8.9)', checked: filters.severity?.includes('HIGH') },
            { value: 'MEDIUM', label: 'Medium (4.0-6.9)', checked: filters.severity?.includes('MEDIUM') },
            { value: 'LOW', label: 'Low (0.1-3.9)', checked: filters.severity?.includes('LOW') }
          ].map((severity) => (
            <div key={severity.value} className="flex items-center space-x-2">
              <Checkbox
                id={`severity-${severity.value}`}
                checked={severity.checked || false}
                onCheckedChange={(checked) => handleSeverityChange(severity.value, checked as boolean)}
                data-testid={`checkbox-severity-${severity.value.toLowerCase()}`}
              />
              <Label htmlFor={`severity-${severity.value}`} className="text-sm">
                {severity.label}
              </Label>
            </div>
          ))}
        </div>
      </div>
      
      {/* Technology */}
      <div className="mb-4">
        <Label className="block text-sm font-medium mb-2">Technology</Label>
        <div className="space-y-2">
          {[
            { value: 'web-servers', label: 'Web Servers', checked: filters.technology?.includes('web-servers') },
            { value: 'cms', label: 'CMS/Frameworks', checked: filters.technology?.includes('cms') },
            { value: 'database', label: 'Database Systems', checked: filters.technology?.includes('database') },
            { value: 'network', label: 'Network Services', checked: filters.technology?.includes('network') }
          ].map((tech) => (
            <div key={tech.value} className="flex items-center space-x-2">
              <Checkbox
                id={`tech-${tech.value}`}
                checked={tech.checked || false}
                onCheckedChange={(checked) => handleTechnologyChange(tech.value, checked as boolean)}
                data-testid={`checkbox-technology-${tech.value}`}
              />
              <Label htmlFor={`tech-${tech.value}`} className="text-sm">
                {tech.label}
              </Label>
            </div>
          ))}
        </div>
      </div>
      
      {/* CVE Status */}
      <div className="mb-4">
        <Label className="block text-sm font-medium mb-2">Status</Label>
        <div className="space-y-2">
          {[
            { value: 'new', label: getStatusLabel('new'), checked: filters.status?.includes('new') },
            { value: 'in_progress', label: getStatusLabel('in_progress'), checked: filters.status?.includes('in_progress') },
            { value: 'done', label: getStatusLabel('done'), checked: filters.status?.includes('done') },
            { value: 'unlisted', label: getStatusLabel('unlisted'), checked: filters.status?.includes('unlisted') }
          ].map((status) => (
            <div key={status.value} className="flex items-center space-x-2">
              <Checkbox
                id={`status-${status.value}`}
                checked={status.checked || false}
                onCheckedChange={(checked) => handleStatusChange(status.value, checked as boolean)}
                data-testid={`checkbox-status-${status.value}`}
              />
              <Label htmlFor={`status-${status.value}`} className="text-sm">
                {status.label}
              </Label>
            </div>
          ))}
        </div>
        
        {/* Quick Filter: Hide Done */}
        <div className="mt-3 pt-3 border-t border-border">
          <div className="flex items-center space-x-2">
            <Checkbox
              id="hide-done"
              checked={filters.hideDone || false}
              onCheckedChange={(checked) => onFiltersChange({ ...filters, hideDone: checked as boolean })}
              data-testid="checkbox-hide-done"
            />
            <Label htmlFor="hide-done" className="text-sm flex items-center gap-1">
              {filters.hideDone ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
              Hide Done CVEs
            </Label>
          </div>
        </div>
      </div>

      {/* Priority & Organization */}
      <div className="mb-4">
        <Label className="block text-sm font-medium mb-2">Priority & Organization</Label>
        <div className="space-y-2">
          <div className="flex items-center space-x-2">
            <Checkbox
              id="priority-only"
              checked={filters.isPriority || false}
              onCheckedChange={(checked) => onFiltersChange({ ...filters, isPriority: checked as boolean })}
              data-testid="checkbox-priority-only"
            />
            <Label htmlFor="priority-only" className="text-sm flex items-center gap-1">
              <Star className="h-3 w-3 text-yellow-500" />
              Priority CVEs Only
            </Label>
          </div>
        </div>
      </div>

      {/* PoC Availability */}
      <div className="mb-6">
        <Label className="block text-sm font-medium mb-2">PoC Availability</Label>
        <div className="space-y-2">
          <div className="flex items-center space-x-2">
            <Checkbox
              id="has-poc"
              checked={filters.hasPublicPoc || false}
              onCheckedChange={(checked) => onFiltersChange({ ...filters, hasPublicPoc: checked as boolean })}
              data-testid="checkbox-has-poc"
            />
            <Label htmlFor="has-poc" className="text-sm">
              Public PoC Available
            </Label>
          </div>
          <div className="flex items-center space-x-2">
            <Checkbox
              id="docker-deployable"
              checked={filters.isDockerDeployable || false}
              onCheckedChange={(checked) => onFiltersChange({ ...filters, isDockerDeployable: checked as boolean })}
              data-testid="checkbox-docker-deployable"
            />
            <Label htmlFor="docker-deployable" className="text-sm">
              Docker Deployable
            </Label>
          </div>
          <div className="flex items-center space-x-2">
            <Checkbox
              id="curl-testable"
              checked={filters.isCurlTestable || false}
              onCheckedChange={(checked) => onFiltersChange({ ...filters, isCurlTestable: checked as boolean })}
              data-testid="checkbox-curl-testable"
            />
            <Label htmlFor="curl-testable" className="text-sm">
              Curl/Nmap Testable
            </Label>
          </div>
        </div>
      </div>
      
      <div className="space-y-2">
        <Button 
          onClick={onApplyFilters} 
          className="w-full"
          data-testid="button-apply-filters"
        >
          Apply Filters
        </Button>
        <Button 
          onClick={onClearFilters} 
          variant="outline" 
          className="w-full"
          data-testid="button-clear-filters"
        >
          Clear All
        </Button>
      </div>
    </div>
  );
}
