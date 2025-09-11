import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertCveSchema, insertCveScanSchema, advancedScoringConfigSchema } from "@shared/schema";
import { CveService } from "./services/cveService";
import { GitHubService } from "./services/githubService";
import { GoogleSheetsService } from "./services/googleSheetsService";
import { advancedScoringService } from "./services/advancedScoringService";
import { multiSourceDiscoveryService } from "./services/multiSourceDiscoveryService";
import { dockerDeploymentService } from "./services/dockerDeploymentService";

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
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      res.status(500).json({ message: 'Failed to export to Google Sheets', error: errorMessage });
    }
  });

  app.post("/api/export/sheets/create", async (req, res) => {
    try {
      const { title = `CVE Lab Results - ${new Date().toLocaleDateString()}` } = req.body;
      const spreadsheetId = await googleSheetsService.createSpreadsheet(title);
      res.json({ spreadsheetId, url: `https://docs.google.com/spreadsheets/d/${spreadsheetId}` });
    } catch (error) {
      console.error('Error creating Google Sheet:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      res.status(500).json({ message: 'Failed to create Google Sheet', error: errorMessage });
    }
  });

  // Background scan function
  async function performCveScan(scanId: string, timeframeYears: number) {
    try {
      await storage.updateCveScan(scanId, { status: 'running' });

      // Fetch CVEs from NIST
      console.log(`Starting CVE scan for ${timeframeYears} years...`);
      const nistCves = await cveService.fetchCvesFromNist(timeframeYears);
      console.log(`Fetched ${nistCves.length} CVEs from NIST`);
      
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

          // Enhanced multi-source PoC discovery
          console.log(`Discovering comprehensive sources for ${cveData.cveId}...`);
          const discoveryResults = await multiSourceDiscoveryService.discoverAllSources(
            cveData.cveId,
            { 
              query: `${cveData.cveId} poc exploit vulnerability`,
              maxResults: 20,
              includeDockerInfo: true
            }
          );

          if (discoveryResults.sources.length > 0) {
            withPoc++;
            cveData.hasPublicPoc = true;
            
            // Collect URLs from all sources (GitHub, Medium, DockerHub, YouTube, etc.)
            cveData.pocUrls = discoveryResults.sources.map(source => source.url);
            
            // Precise Docker deployability based on actual deployment capabilities
            const hasActualDockerCapability = discoveryResults.dockerInfo.some(info => 
              (info.hasDockerfile || info.hasCompose) && info.deploymentComplexity !== 'complex'
            );
            const hasDockerHubContainers = discoveryResults.sources.some(source => 
              source.type === 'dockerhub'
            );
            
            // Only mark as deployable if there are actual Docker deployment capabilities
            cveData.isDockerDeployable = hasActualDockerCapability || hasDockerHubContainers;
            if (cveData.isDockerDeployable) {
              labDeployable++;
            }

            // Store comprehensive discovery metadata
            cveData.discoveryMetadata = {
              totalSources: discoveryResults.totalSources,
              sourceBreakdown: discoveryResults.sourceBreakdown,
              dockerInfo: discoveryResults.dockerInfo,
              topSources: discoveryResults.sources.slice(0, 5).map(source => ({
                type: source.type,
                title: source.title,
                url: source.url,
                relevanceScore: source.relevanceScore
              }))
            };

            console.log(`Found ${discoveryResults.totalSources} sources across ${Object.keys(discoveryResults.sourceBreakdown).length} platforms for ${cveData.cveId}`);
          } else {
            console.log(`No PoC sources found for ${cveData.cveId}`);
          }

          // Determine if curl/nmap testable (network services)
          cveData.isCurlTestable = cveData.attackVector === 'Network' && 
            ['Web Server', 'Network Service', 'CMS'].includes(cveData.category);

          // Calculate advanced lab suitability score AFTER all enrichment data is available
          const advancedScore = cveService.calculateAdvancedLabScore(cveData);
          cveData.labSuitabilityScore = advancedScore.score;
          cveData.scoringBreakdown = advancedScore.breakdown;

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
        criticalSeverity
      });

      console.log(`CVE scan completed: ${totalFound} total, ${labDeployable} deployable, ${withPoc} with PoC`);
    } catch (error) {
      console.error('CVE scan failed:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      await storage.updateCveScan(scanId, {
        status: 'failed',
        errorMessage
      });
    }
  }

  // Advanced Scoring Configuration API
  app.get("/api/scoring/config", async (req, res) => {
    try {
      const config = advancedScoringService.getConfig();
      res.json(config);
    } catch (error) {
      console.error('Error fetching scoring config:', error);
      res.status(500).json({ message: 'Failed to fetch scoring configuration' });
    }
  });

  app.post("/api/scoring/config", async (req, res) => {
    try {
      const validatedConfig = advancedScoringConfigSchema.parse(req.body);
      advancedScoringService.updateConfig(validatedConfig);
      const updatedConfig = advancedScoringService.getConfig();
      res.json(updatedConfig);
    } catch (error) {
      console.error('Error updating scoring config:', error);
      if (error instanceof Error && error.name === 'ZodError') {
        res.status(400).json({ message: 'Invalid configuration format', details: error.message });
      } else {
        res.status(500).json({ message: 'Failed to update scoring configuration' });
      }
    }
  });

  // CVE Advanced Scoring API
  app.get("/api/cves/:id/scoring", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const advancedScore = cveService.calculateAdvancedLabScore(cve);
      const basicScore = cveService.calculateBasicLabScore(cve);

      res.json({
        cveId: cve.cveId,
        advancedScore: advancedScore.score,
        basicScore,
        breakdown: advancedScore.breakdown,
        comparison: {
          improvement: Math.round((advancedScore.score - basicScore) * 10) / 10,
          percentChange: basicScore > 0 ? Math.round(((advancedScore.score - basicScore) / basicScore) * 100) : 0
        }
      });
    } catch (error) {
      console.error('Error calculating CVE scores:', error);
      res.status(500).json({ message: 'Failed to calculate CVE scores' });
    }
  });

  // Multi-Source Discovery API
  app.post("/api/cves/:id/sources", async (req, res) => {
    try {
      const cveId = req.params.id;
      const options = {
        query: req.body.query || cveId,
        maxResults: req.body.maxResults || 20,
        includeDockerInfo: req.body.includeDockerInfo || true,
        includeVideoTranscripts: req.body.includeVideoTranscripts || false
      };

      const discoveryResults = await multiSourceDiscoveryService.discoverAllSources(cveId, options);
      
      res.json({
        cveId,
        ...discoveryResults,
        searchTime: Date.now() - Date.now() // Placeholder for actual timing
      });
    } catch (error) {
      console.error('Error discovering sources for CVE:', error);
      res.status(500).json({ message: 'Failed to discover sources for CVE' });
    }
  });

  app.get("/api/cves/:id/sources", async (req, res) => {
    try {
      const cveId = req.params.id;
      const options = {
        query: cveId,
        maxResults: parseInt(req.query.maxResults as string) || 20,
        includeDockerInfo: req.query.includeDockerInfo === 'true',
        includeVideoTranscripts: req.query.includeVideoTranscripts === 'true'
      };

      const discoveryResults = await multiSourceDiscoveryService.discoverAllSources(cveId, options);
      
      res.json({
        cveId,
        ...discoveryResults
      });
    } catch (error) {
      console.error('Error discovering sources for CVE:', error);
      res.status(500).json({ message: 'Failed to discover sources for CVE' });
    }
  });

  // Docker Deployment Automation API
  app.get("/api/deployment/templates", async (req, res) => {
    try {
      const category = req.query.category as string;
      
      if (category) {
        const templates = await dockerDeploymentService.getTemplatesForCategory(category as any);
        res.json(templates);
      } else {
        const templates = await dockerDeploymentService.getAvailableTemplates();
        res.json(templates);
      }
    } catch (error) {
      console.error('Error fetching deployment templates:', error);
      res.status(500).json({ message: 'Failed to fetch deployment templates' });
    }
  });

  app.get("/api/deployment/templates/:templateId", async (req, res) => {
    try {
      const template = await dockerDeploymentService.getTemplate(req.params.templateId);
      if (!template) {
        return res.status(404).json({ message: 'Template not found' });
      }
      res.json(template);
    } catch (error) {
      console.error('Error fetching deployment template:', error);
      res.status(500).json({ message: 'Failed to fetch deployment template' });
    }
  });

  app.post("/api/cves/:id/deployment/analyze", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const analysis = await dockerDeploymentService.analyzeDeploymentPossibilities(cve);
      
      res.json({
        cveId: cve.cveId,
        ...analysis,
        analysisTime: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error analyzing deployment possibilities for CVE:', error);
      res.status(500).json({ message: 'Failed to analyze deployment possibilities' });
    }
  });

  app.post("/api/cves/:id/deployment/generate", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const deployment = await dockerDeploymentService.generateAutomatedDeployment(cve);
      
      if (!deployment) {
        return res.status(404).json({ 
          message: 'No suitable deployment template found for this CVE',
          cveId: cve.cveId,
          reason: 'CVE may not be suitable for automated Docker deployment'
        });
      }

      res.json(deployment);
    } catch (error) {
      console.error('Error generating automated deployment for CVE:', error);
      res.status(500).json({ message: 'Failed to generate automated deployment' });
    }
  });

  app.get("/api/cves/:id/deployment", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const deploymentPackage = await dockerDeploymentService.generateDeploymentPackage(cve);
      
      res.json({
        cveId: cve.cveId,
        ...deploymentPackage,
        generatedAt: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error generating deployment package for CVE:', error);
      res.status(500).json({ message: 'Failed to generate deployment package' });
    }
  });

  app.post("/api/cves/:id/deployment/scripts", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const { scriptType = 'all' } = req.body;
      const deployment = await dockerDeploymentService.generateAutomatedDeployment(cve);
      
      if (!deployment) {
        return res.status(404).json({ 
          message: 'No deployment available for this CVE',
          cveId: cve.cveId
        });
      }

      const scripts = {
        deployment: scriptType === 'all' || scriptType === 'deployment' ? deployment.deploymentScript : null,
        testing: scriptType === 'all' || scriptType === 'testing' ? deployment.testingScript : null,
        cleanup: scriptType === 'all' || scriptType === 'cleanup' ? deployment.cleanupScript : null
      };

      res.json({
        cveId: cve.cveId,
        scripts,
        instructions: deployment.customInstructions,
        resourceRequirements: deployment.resourceRequirements
      });
    } catch (error) {
      console.error('Error generating deployment scripts for CVE:', error);
      res.status(500).json({ message: 'Failed to generate deployment scripts' });
    }
  });

  // Docker deployment analytics endpoint
  app.get("/api/deployment/analytics", async (req, res) => {
    try {
      const cves = await storage.getCves();
      const analytics = {
        totalCves: cves.length,
        deployableCves: 0,
        templateUsage: {} as Record<string, number>,
        complexityDistribution: {
          simple: 0,
          moderate: 0,
          complex: 0
        },
        categoryDeployability: {} as Record<string, { total: number; deployable: number }>,
        averageSetupTime: '0 minutes',
        topDeployableCves: [] as any[]
      };

      const deployableAnalysis = [];

      for (const cve of cves) {
        try {
          const analysis = await dockerDeploymentService.analyzeDeploymentPossibilities(cve);
          
          if (analysis.isDeployable && analysis.recommendedTemplate) {
            analytics.deployableCves++;
            
            // Track template usage
            const templateId = analysis.recommendedTemplate.id;
            analytics.templateUsage[templateId] = (analytics.templateUsage[templateId] || 0) + 1;
            
            // Track complexity
            const complexity = analysis.recommendedTemplate.complexity;
            analytics.complexityDistribution[complexity]++;
            
            deployableAnalysis.push({
              cveId: cve.cveId,
              category: cve.category,
              severity: cve.severity,
              cvssScore: cve.cvssScore,
              template: analysis.recommendedTemplate.name,
              complexity,
              estimatedTime: analysis.recommendedTemplate.estimatedSetupTime
            });
          }

          // Track by category
          const category = cve.category || 'Unknown';
          if (!analytics.categoryDeployability[category]) {
            analytics.categoryDeployability[category] = { total: 0, deployable: 0 };
          }
          analytics.categoryDeployability[category].total++;
          if (analysis.isDeployable) {
            analytics.categoryDeployability[category].deployable++;
          }
        } catch (error) {
          console.warn(`Failed to analyze deployment for CVE ${cve.cveId}:`, error);
        }
      }

      // Calculate average setup time (simplified)
      const timeEstimates = deployableAnalysis.map(d => {
        const timeStr = d.estimatedTime;
        const match = timeStr.match(/(\d+)-?(\d+)?/);
        return match ? parseInt(match[1]) : 10;
      });
      const avgTime = timeEstimates.length > 0 
        ? Math.round(timeEstimates.reduce((a, b) => a + b, 0) / timeEstimates.length)
        : 0;
      analytics.averageSetupTime = `${avgTime} minutes`;

      // Top deployable CVEs by CVSS score
      analytics.topDeployableCves = deployableAnalysis
        .filter(d => d.cvssScore)
        .sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0))
        .slice(0, 10)
        .map(d => ({
          cveId: d.cveId,
          cvssScore: d.cvssScore,
          template: d.template,
          estimatedTime: d.estimatedTime
        }));

      res.json(analytics);
    } catch (error) {
      console.error('Error generating deployment analytics:', error);
      res.status(500).json({ message: 'Failed to generate deployment analytics' });
    }
  });

  // Batch scoring comparison for dashboard analytics
  app.get("/api/scoring/analytics", async (req, res) => {
    try {
      const cves = await storage.getCves();
      const analytics = {
        totalCves: cves.length,
        scoringComparison: {
          averageAdvanced: 0,
          averageBasic: 0,
          improvement: 0
        },
        distributionByCategory: {} as any,
        topScoredCves: [] as any[]
      };

      let totalAdvanced = 0;
      let totalBasic = 0;
      const scoredCves = [];

      for (const cve of cves) {
        const advancedScore = cveService.calculateAdvancedLabScore(cve);
        const basicScore = cveService.calculateBasicLabScore(cve);
        
        totalAdvanced += advancedScore.score;
        totalBasic += basicScore;

        scoredCves.push({
          cveId: cve.cveId,
          category: cve.category,
          advancedScore: advancedScore.score,
          basicScore,
          improvement: advancedScore.score - basicScore
        });

        // Track by category
        if (cve.category && !analytics.distributionByCategory[cve.category]) {
          analytics.distributionByCategory[cve.category] = { count: 0, avgAdvanced: 0, avgBasic: 0 };
        }
        if (cve.category) {
          analytics.distributionByCategory[cve.category].count++;
        }
      }

      analytics.scoringComparison.averageAdvanced = Math.round((totalAdvanced / cves.length) * 10) / 10;
      analytics.scoringComparison.averageBasic = Math.round((totalBasic / cves.length) * 10) / 10;
      analytics.scoringComparison.improvement = Math.round((analytics.scoringComparison.averageAdvanced - analytics.scoringComparison.averageBasic) * 10) / 10;

      // Calculate category averages
      for (const category in analytics.distributionByCategory) {
        const categoryData = analytics.distributionByCategory[category];
        const categoryCves = scoredCves.filter(c => c.category === category);
        categoryData.avgAdvanced = Math.round((categoryCves.reduce((sum, c) => sum + c.advancedScore, 0) / categoryCves.length) * 10) / 10;
        categoryData.avgBasic = Math.round((categoryCves.reduce((sum, c) => sum + c.basicScore, 0) / categoryCves.length) * 10) / 10;
      }

      // Top scored CVEs
      analytics.topScoredCves = scoredCves
        .sort((a, b) => b.advancedScore - a.advancedScore)
        .slice(0, 10)
        .map(c => ({ cveId: c.cveId, score: c.advancedScore, improvement: c.improvement }));

      res.json(analytics);
    } catch (error) {
      console.error('Error generating scoring analytics:', error);
      res.status(500).json({ message: 'Failed to generate scoring analytics' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
