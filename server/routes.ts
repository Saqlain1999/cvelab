import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertCveSchema, insertCveScanSchema } from "@shared/schema";
import { CveService } from "./services/cveService";
import { GitHubService } from "./services/githubService";
import { GoogleSheetsService } from "./services/googleSheetsService";

export async function registerRoutes(app: Express): Promise<Server> {
  const cveService = new CveService();
  const githubService = new GitHubService();
  const googleSheetsService = new GoogleSheetsService();

  // CVE endpoints
  app.get("/api/cves", async (req, res) => {
    try {
      const filters = {
        severity: req.query.severity ? String(req.query.severity).split(',') : undefined,
        technology: req.query.technology ? String(req.query.technology).split(',') : undefined,
        hasPublicPoc: req.query.hasPublicPoc ? req.query.hasPublicPoc === 'true' : undefined,
        isDockerDeployable: req.query.isDockerDeployable ? req.query.isDockerDeployable === 'true' : undefined,
        isCurlTestable: req.query.isCurlTestable ? req.query.isCurlTestable === 'true' : undefined,
        minCvssScore: req.query.minCvssScore ? Number(req.query.minCvssScore) : undefined,
        maxCvssScore: req.query.maxCvssScore ? Number(req.query.maxCvssScore) : undefined,
        search: req.query.search ? String(req.query.search) : undefined,
        limit: req.query.limit ? Number(req.query.limit) : 50,
        offset: req.query.offset ? Number(req.query.offset) : 0
      };

      const cves = await storage.getCves(filters);
      res.json(cves);
    } catch (error) {
      console.error('Error fetching CVEs:', error);
      res.status(500).json({ message: 'Failed to fetch CVEs' });
    }
  });

  app.get("/api/cves/:id", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }
      res.json(cve);
    } catch (error) {
      console.error('Error fetching CVE:', error);
      res.status(500).json({ message: 'Failed to fetch CVE' });
    }
  });

  app.get("/api/stats", async (req, res) => {
    try {
      const stats = await storage.getCveStats();
      res.json(stats);
    } catch (error) {
      console.error('Error fetching stats:', error);
      res.status(500).json({ message: 'Failed to fetch stats' });
    }
  });

  // CVE scan endpoints
  app.post("/api/scans", async (req, res) => {
    try {
      const scanData = insertCveScanSchema.parse(req.body);
      const scan = await storage.createCveScan(scanData);
      
      // Start background scan process
      performCveScan(scan.id, scanData.timeframeYears || 3);
      
      res.json(scan);
    } catch (error) {
      console.error('Error starting CVE scan:', error);
      res.status(500).json({ message: 'Failed to start CVE scan' });
    }
  });

  app.get("/api/scans", async (req, res) => {
    try {
      const scans = await storage.getCveScans();
      res.json(scans);
    } catch (error) {
      console.error('Error fetching scans:', error);
      res.status(500).json({ message: 'Failed to fetch scans' });
    }
  });

  app.get("/api/scans/:id", async (req, res) => {
    try {
      const scan = await storage.getCveScan(req.params.id);
      if (!scan) {
        return res.status(404).json({ message: 'Scan not found' });
      }
      res.json(scan);
    } catch (error) {
      console.error('Error fetching scan:', error);
      res.status(500).json({ message: 'Failed to fetch scan' });
    }
  });

  // Export endpoints
  app.post("/api/export/sheets", async (req, res) => {
    try {
      const { spreadsheetId, sheetName = 'CVE Results', filters } = req.body;
      
      if (!spreadsheetId) {
        return res.status(400).json({ message: 'Spreadsheet ID is required' });
      }

      const cves = await storage.getCves(filters);
      const success = await googleSheetsService.exportToSheets(spreadsheetId, sheetName, cves);
      
      res.json({ success, message: `Exported ${cves.length} CVEs to Google Sheets` });
    } catch (error) {
      console.error('Error exporting to Google Sheets:', error);
      res.status(500).json({ message: 'Failed to export to Google Sheets', error: error.message });
    }
  });

  app.post("/api/export/sheets/create", async (req, res) => {
    try {
      const { title = `CVE Lab Results - ${new Date().toLocaleDateString()}` } = req.body;
      const spreadsheetId = await googleSheetsService.createSpreadsheet(title);
      res.json({ spreadsheetId, url: `https://docs.google.com/spreadsheets/d/${spreadsheetId}` });
    } catch (error) {
      console.error('Error creating Google Sheet:', error);
      res.status(500).json({ message: 'Failed to create Google Sheet', error: error.message });
    }
  });

  // Background scan function
  async function performCveScan(scanId: string, timeframeYears: number) {
    try {
      await storage.updateCveScan(scanId, { status: 'running' });

      // Fetch CVEs from NIST
      console.log(`Starting CVE scan for ${timeframeYears} years...`);
      const nistCves = await cveService.fetchCvesFromNist(timeframeYears);
      
      let totalFound = 0;
      let labDeployable = 0;
      let withPoc = 0;
      let criticalSeverity = 0;

      // Process each CVE
      for (const cveData of nistCves) {
        try {
          // Check if CVE is lab suitable
          if (!cveService.isLabSuitable(cveData)) {
            continue;
          }

          totalFound++;

          // Search for PoCs on GitHub
          const pocResults = await githubService.searchPoCs(cveData.cveId);
          if (pocResults.length > 0) {
            withPoc++;
            cveData.hasPublicPoc = true;
            cveData.pocUrls = pocResults.map(repo => repo.html_url);

            // Check Docker deployability
            const isDockerDeployable = await Promise.all(
              pocResults.slice(0, 3).map(repo => githubService.checkDockerDeployability(repo.html_url))
            );
            cveData.isDockerDeployable = isDockerDeployable.some(Boolean);
            if (cveData.isDockerDeployable) {
              labDeployable++;
            }
          }

          // Determine if curl/nmap testable (network services)
          cveData.isCurlTestable = cveData.attackVector === 'Network' && 
            ['Web Server', 'Network Service', 'CMS'].includes(cveData.category);

          // Calculate lab suitability score
          cveData.labSuitabilityScore = calculateLabSuitabilityScore(cveData);

          if (cveData.severity === 'CRITICAL') {
            criticalSeverity++;
          }

          // Save CVE to storage
          await storage.createCve(cveData);

          // Add small delay to avoid overwhelming APIs
          await new Promise(resolve => setTimeout(resolve, 100));
        } catch (error) {
          console.error(`Error processing CVE ${cveData.cveId}:`, error);
        }
      }

      // Update scan with results
      await storage.updateCveScan(scanId, {
        status: 'completed',
        totalFound,
        labDeployable,
        withPoc,
        criticalSeverity,
        completedAt: new Date()
      });

      console.log(`CVE scan completed: ${totalFound} total, ${labDeployable} deployable, ${withPoc} with PoC`);
    } catch (error) {
      console.error('CVE scan failed:', error);
      await storage.updateCveScan(scanId, {
        status: 'failed',
        errorMessage: error.message,
        completedAt: new Date()
      });
    }
  }

  function calculateLabSuitabilityScore(cve: any): number {
    let score = 0;

    // CVSS score weight (40%)
    if (cve.cvssScore) {
      score += (cve.cvssScore / 10) * 4;
    }

    // PoC availability (25%)
    if (cve.hasPublicPoc) {
      score += 2.5;
    }

    // Docker deployability (20%)
    if (cve.isDockerDeployable) {
      score += 2;
    }

    // Network testability (15%)
    if (cve.isCurlTestable) {
      score += 1.5;
    }

    return Math.min(score, 10);
  }

  const httpServer = createServer(app);
  return httpServer;
}
