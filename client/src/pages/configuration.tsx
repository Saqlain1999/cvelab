import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Play, Save, TestTube } from "lucide-react";
import { Navigation } from "@/components/navigation";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { CveScan } from "@/types/cve";

export default function Configuration() {
  const [timeframeYears, setTimeframeYears] = useState(3);
  const [googleSheetsId, setGoogleSheetsId] = useState("");
  const { toast } = useToast();

  const { data: scans = [] } = useQuery<CveScan[]>({
    queryKey: ["/api/scans"],
  });

  const startScanMutation = useMutation({
    mutationFn: async (timeframe: number) => {
      const response = await apiRequest("POST", "/api/scans", { timeframeYears: timeframe });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scans"] });
      toast({
        title: "CVE Scan Started",
        description: `Started scanning CVEs for the last ${timeframeYears} years.`,
      });
    },
    onError: (error) => {
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const testSheetsMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/export/sheets/create", { 
        title: "CVE Lab Test Sheet" 
      });
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Google Sheets Connected",
        description: `Test spreadsheet created: ${data.spreadsheetId}`,
      });
      setGoogleSheetsId(data.spreadsheetId);
    },
    onError: (error) => {
      toast({
        title: "Connection Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleStartScan = () => {
    startScanMutation.mutate(timeframeYears);
  };

  const handleTestSheets = () => {
    testSheetsMutation.mutate();
  };

  const latestScan = scans[0];

  return (
    <div className="flex h-screen">
      <Navigation />
      
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="bg-card border-b border-border p-4" data-testid="config-header">
          <div>
            <h2 className="text-2xl font-semibold">Configuration</h2>
            <p className="text-muted-foreground">Configure CVE scanning and integration settings</p>
          </div>
        </header>
        
        {/* Content Area */}
        <main className="flex-1 p-6 overflow-auto">
          <div className="max-w-4xl mx-auto space-y-6">
            
            {/* CVE Scanning Configuration */}
            <Card data-testid="card-cve-scanning">
              <CardHeader>
                <CardTitle>CVE Scanning</CardTitle>
                <CardDescription>
                  Configure automatic CVE discovery from NIST NVD database
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="timeframe">Scanning Timeframe</Label>
                    <Select 
                      value={timeframeYears.toString()} 
                      onValueChange={(value) => setTimeframeYears(Number(value))}
                      data-testid="select-timeframe-config"
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select timeframe" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1">Last 1 year</SelectItem>
                        <SelectItem value="2">Last 2 years</SelectItem>
                        <SelectItem value="3">Last 3 years</SelectItem>
                        <SelectItem value="5">Last 5 years</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-end">
                    <Button 
                      onClick={handleStartScan}
                      disabled={startScanMutation.isPending}
                      className="w-full"
                      data-testid="button-start-scan"
                    >
                      <Play className="w-4 h-4 mr-2" />
                      {startScanMutation.isPending ? "Starting..." : "Start CVE Scan"}
                    </Button>
                  </div>
                </div>
                
                {latestScan && (
                  <div className="mt-4 p-4 bg-muted rounded-lg" data-testid="latest-scan-info">
                    <h4 className="font-medium mb-2">Latest Scan Status</h4>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <div className="text-muted-foreground">Status</div>
                        <div className="font-medium capitalize">{latestScan.status}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Total Found</div>
                        <div className="font-medium">{latestScan.totalFound}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Lab Ready</div>
                        <div className="font-medium">{latestScan.labDeployable}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">With PoC</div>
                        <div className="font-medium">{latestScan.withPoc}</div>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Google Sheets Integration */}
            <Card data-testid="card-google-sheets">
              <CardHeader>
                <CardTitle>Google Sheets Integration</CardTitle>
                <CardDescription>
                  Configure Google Sheets for CVE data export
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="md:col-span-2">
                    <Label htmlFor="sheets-id">Spreadsheet ID</Label>
                    <Input
                      id="sheets-id"
                      placeholder="Enter Google Sheets ID"
                      value={googleSheetsId}
                      onChange={(e) => setGoogleSheetsId(e.target.value)}
                      data-testid="input-sheets-id"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      You can find the spreadsheet ID in the URL of your Google Sheet
                    </p>
                  </div>
                  <div className="flex items-end">
                    <Button 
                      onClick={handleTestSheets}
                      disabled={testSheetsMutation.isPending}
                      variant="outline"
                      className="w-full"
                      data-testid="button-test-sheets"
                    >
                      <TestTube className="w-4 h-4 mr-2" />
                      {testSheetsMutation.isPending ? "Testing..." : "Test Connection"}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* API Configuration */}
            <Card data-testid="card-api-config">
              <CardHeader>
                <CardTitle>API Configuration</CardTitle>
                <CardDescription>
                  Configure external API integrations
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="github-token">GitHub API Token</Label>
                    <Input
                      id="github-token"
                      type="password"
                      placeholder="ghp_..."
                      data-testid="input-github-token"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Required for PoC discovery and rate limit increases
                    </p>
                  </div>
                  <div>
                    <Label htmlFor="google-api-key">Google API Key</Label>
                    <Input
                      id="google-api-key"
                      type="password"
                      placeholder="AIza..."
                      data-testid="input-google-api-key"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Required for Google Sheets integration
                    </p>
                  </div>
                </div>
                <Button className="w-full md:w-auto" data-testid="button-save-config">
                  <Save className="w-4 h-4 mr-2" />
                  Save Configuration
                </Button>
              </CardContent>
            </Card>

            {/* Filtering Criteria */}
            <Card data-testid="card-filtering">
              <CardHeader>
                <CardTitle>Lab Suitability Criteria</CardTitle>
                <CardDescription>
                  Configure criteria for lab-suitable CVEs
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="min-cvss">Minimum CVSS Score</Label>
                    <Select defaultValue="7.0" data-testid="select-min-cvss">
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="4.0">4.0 (Medium)</SelectItem>
                        <SelectItem value="7.0">7.0 (High)</SelectItem>
                        <SelectItem value="9.0">9.0 (Critical)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="attack-vector">Required Attack Vector</Label>
                    <Select defaultValue="Network" data-testid="select-attack-vector">
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Network">Network</SelectItem>
                        <SelectItem value="Adjacent">Adjacent Network</SelectItem>
                        <SelectItem value="Local">Local</SelectItem>
                        <SelectItem value="Any">Any</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardContent>
            </Card>

          </div>
        </main>
      </div>
    </div>
  );
}
