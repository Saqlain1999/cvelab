import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { RefreshCw, Search } from "lucide-react";
import { Navigation } from "@/components/navigation";
import { StatsGrid } from "@/components/stats-grid";
import { FilterPanel } from "@/components/filter-panel";
import { CveTable } from "@/components/cve-table";
import { CveDetailModal } from "@/components/cve-detail-modal";
import { useToast } from "@/hooks/use-toast";
import type { Cve, CveFilters } from "@/types/cve";

export default function Dashboard() {
  const [searchTerm, setSearchTerm] = useState("");
  const [filters, setFilters] = useState<CveFilters>({
    severity: ['CRITICAL', 'HIGH'],
    limit: 50,
    offset: 0
  });
  const [selectedCve, setSelectedCve] = useState<Cve | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const { toast } = useToast();

  const { data: cves = [], isLoading, refetch } = useQuery<Cve[]>({
    queryKey: ["/api/cves", filters],
  });

  const handleSearch = () => {
    setFilters({ ...filters, search: searchTerm, offset: 0 });
  };

  const handleApplyFilters = () => {
    setFilters({ ...filters, offset: 0 });
    toast({
      title: "Filters Applied",
      description: "CVE results have been updated based on your filters.",
    });
  };

  const handleClearFilters = () => {
    setFilters({
      severity: ['CRITICAL', 'HIGH'],
      limit: 50,
      offset: 0
    });
    setSearchTerm("");
    toast({
      title: "Filters Cleared",
      description: "All filters have been reset to default values.",
    });
  };

  const handleViewDetails = (cve: Cve) => {
    setSelectedCve(cve);
    setIsModalOpen(true);
  };

  const handleRefresh = async () => {
    try {
      await refetch();
      toast({
        title: "Data Refreshed",
        description: "CVE data has been updated from the latest sources.",
      });
    } catch (error) {
      toast({
        title: "Refresh Failed",
        description: "Failed to refresh CVE data. Please try again.",
        variant: "destructive",
      });
    }
  };

  const handleExport = () => {
    // Export filtered CVEs as CSV
    const headers = [
      'CVE ID', 'Severity', 'CVSS Score', 'Published Date', 'Technology', 
      'Category', 'Description', 'Has Public PoC', 'Docker Deployable', 
      'Curl/Nmap Testable', 'PoC URLs', 'Attack Vector', 'Affected Versions'
    ];
    
    const csvData = [
      headers,
      ...cves.map(cve => [
        cve.cveId,
        cve.severity,
        cve.cvssScore?.toString() || 'N/A',
        new Date(cve.publishedDate).toLocaleDateString(),
        cve.technology || cve.affectedProduct || 'Unknown',
        cve.category || 'Other',
        cve.description.substring(0, 200) + '...',
        cve.hasPublicPoc ? 'Yes' : 'No',
        cve.isDockerDeployable ? 'Yes' : 'No',
        cve.isCurlTestable ? 'Yes' : 'No',
        (cve.pocUrls || []).join('; '),
        cve.attackVector || 'Unknown',
        (cve.affectedVersions || []).join('; ')
      ])
    ];

    const csvContent = csvData.map(row => 
      row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(',')
    ).join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `cve-lab-results-${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    toast({
      title: "Export Complete",
      description: `Exported ${cves.length} CVEs to CSV file.`,
    });
  };

  const handleExportToSheets = async () => {
    try {
      // Create a new spreadsheet first
      const createResponse = await fetch('/api/export/sheets/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          title: `CVE Lab Results - ${new Date().toLocaleDateString()}` 
        })
      });

      if (!createResponse.ok) {
        throw new Error('Failed to create spreadsheet');
      }

      const { spreadsheetId, url } = await createResponse.json();

      // Export the filtered CVEs to the new spreadsheet
      const exportResponse = await fetch('/api/export/sheets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          spreadsheetId,
          sheetName: 'CVE Results',
          filters
        })
      });

      if (!exportResponse.ok) {
        throw new Error('Failed to export to spreadsheet');
      }

      const result = await exportResponse.json();
      
      toast({
        title: "Export Successful",
        description: `${result.message}. View at: ${url}`,
      });

      // Open the spreadsheet in a new tab
      window.open(url, '_blank');
    } catch (error) {
      toast({
        title: "Export Failed", 
        description: "Please configure Google Sheets API key in settings.",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="flex h-screen">
      <Navigation />
      
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="bg-card border-b border-border p-4" data-testid="dashboard-header">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-semibold">Dashboard</h2>
              <p className="text-muted-foreground">Automated CVE discovery and lab deployment</p>
            </div>
            <div className="flex items-center gap-4">
              {/* Search Bar */}
              <div className="relative">
                <Input
                  type="text"
                  placeholder="Search CVEs..."
                  className="w-80 pl-10"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                  data-testid="input-search"
                />
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              </div>
              {/* Refresh Button */}
              <Button onClick={handleRefresh} data-testid="button-refresh">
                <RefreshCw className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </header>
        
        {/* Content Area */}
        <main className="flex-1 p-6 overflow-auto">
          <StatsGrid cves={cves} isLoading={isLoading} />
          
          {/* Filters and Results */}
          <div className="flex flex-col lg:flex-row gap-6">
            <FilterPanel
              filters={filters}
              onFiltersChange={setFilters}
              onApplyFilters={handleApplyFilters}
              onClearFilters={handleClearFilters}
            />
            
            <CveTable
              cves={cves}
              isLoading={isLoading}
              onViewDetails={handleViewDetails}
              onExport={handleExport}
              onExportToSheets={handleExportToSheets}
            />
          </div>
        </main>
      </div>

      <CveDetailModal
        cve={selectedCve}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
      />
    </div>
  );
}
