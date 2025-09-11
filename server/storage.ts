import { type User, type InsertUser, type Cve, type InsertCve, type CveScan, type InsertCveScan } from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  getCve(id: string): Promise<Cve | undefined>;
  getCveByIds(ids: string[]): Promise<Cve[]>;
  getCves(filters?: CveFilters): Promise<Cve[]>;
  createCve(cve: InsertCve): Promise<Cve>;
  updateCve(id: string, updates: Partial<InsertCve>): Promise<Cve | undefined>;
  deleteCve(id: string): Promise<boolean>;
  
  getCveScan(id: string): Promise<CveScan | undefined>;
  getCveScans(): Promise<CveScan[]>;
  createCveScan(scan: InsertCveScan): Promise<CveScan>;
  updateCveScan(id: string, updates: Partial<InsertCveScan>): Promise<CveScan | undefined>;
  
  getCveStats(): Promise<CveStats>;
}

export interface CveFilters {
  severity?: string[];
  technology?: string[];
  hasPublicPoc?: boolean;
  isDockerDeployable?: boolean;
  isCurlTestable?: boolean;
  minCvssScore?: number;
  maxCvssScore?: number;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface CveStats {
  totalCves: number;
  deployable: number;
  withPoc: number;
  critical: number;
}

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private cves: Map<string, Cve>;
  private cveScans: Map<string, CveScan>;

  constructor() {
    this.users = new Map();
    this.cves = new Map();
    this.cveScans = new Map();
    
    // Add some sample CVE data for demonstration
    this.initializeSampleData();
  }

  private initializeSampleData() {
    const sampleCves = [
      {
        cveId: "CVE-2024-6387",
        description: "A signal handler race condition was found in OpenSSH's server (sshd), where a client does not authenticate within LoginGraceTime seconds (120 by default, 600 in old OpenSSH versions), then sshd's SIGALRM handler is called asynchronously.",
        publishedDate: new Date("2024-07-01"),
        lastModifiedDate: new Date("2024-07-15"),
        cvssScore: 8.1,
        cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity: "HIGH",
        affectedProduct: "OpenSSH",
        affectedVersions: ["< 9.8"],
        attackVector: "Network",
        technology: "OpenSSH",
        category: "Network Service",
        hasPublicPoc: true,
        isDockerDeployable: true,
        isCurlTestable: true,
        pocUrls: ["https://github.com/zgzhang/cve-2024-6387-poc"],
        dockerInfo: { available: true },
        fingerprintInfo: { testable: true },
        exploitabilityScore: 7.5,
        labSuitabilityScore: 8.9
      },
      {
        cveId: "CVE-2024-4577",
        description: "In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if a certain case-insensitive bypass of the Windows Unicode feature is used, PHP may execute shell commands.",
        publishedDate: new Date("2024-06-06"),
        lastModifiedDate: new Date("2024-06-20"),
        cvssScore: 9.8,
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity: "CRITICAL",
        affectedProduct: "PHP",
        affectedVersions: ["8.1.0 - 8.1.28", "8.2.0 - 8.2.19", "8.3.0 - 8.3.7"],
        attackVector: "Network",
        technology: "PHP",
        category: "Web Server",
        hasPublicPoc: true,
        isDockerDeployable: true,
        isCurlTestable: true,
        pocUrls: ["https://github.com/watchtowrlabs/CVE-2024-4577"],
        dockerInfo: { available: true },
        fingerprintInfo: { testable: true },
        exploitabilityScore: 9.2,
        labSuitabilityScore: 9.5
      },
      {
        cveId: "CVE-2024-3400",
        description: "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        publishedDate: new Date("2024-04-12"),
        lastModifiedDate: new Date("2024-04-25"),
        cvssScore: 10.0,
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity: "CRITICAL",
        affectedProduct: "PAN-OS",
        affectedVersions: ["10.2.0 - 10.2.9", "11.0.0 - 11.0.4", "11.1.0 - 11.1.2"],
        attackVector: "Network",
        technology: "Palo Alto Networks",
        category: "Network Security",
        hasPublicPoc: true,
        isDockerDeployable: false,
        isCurlTestable: true,
        pocUrls: ["https://github.com/h4x0r-dz/CVE-2024-3400"],
        dockerInfo: null,
        fingerprintInfo: { testable: true },
        exploitabilityScore: 9.8,
        labSuitabilityScore: 7.2
      }
    ];

    sampleCves.forEach(cveData => {
      const id = randomUUID();
      const now = new Date();
      const cve = {
        ...cveData,
        id,
        createdAt: now,
        updatedAt: now,
        hasPublicPoc: cveData.hasPublicPoc || false,
        isDockerDeployable: cveData.isDockerDeployable || false,
        isCurlTestable: cveData.isCurlTestable || false
      };
      this.cves.set(id, cve as any);
    });
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async getCve(id: string): Promise<Cve | undefined> {
    return this.cves.get(id);
  }

  async getCveByIds(ids: string[]): Promise<Cve[]> {
    return ids.map(id => this.cves.get(id)).filter(Boolean) as Cve[];
  }

  async getCves(filters?: CveFilters): Promise<Cve[]> {
    let results = Array.from(this.cves.values());

    if (filters) {
      if (filters.severity && filters.severity.length > 0) {
        results = results.filter(cve => filters.severity!.includes(cve.severity));
      }
      
      if (filters.technology && filters.technology.length > 0) {
        results = results.filter(cve => 
          filters.technology!.some(tech => 
            cve.technology?.toLowerCase().includes(tech.toLowerCase()) ||
            cve.affectedProduct?.toLowerCase().includes(tech.toLowerCase())
          )
        );
      }
      
      if (filters.hasPublicPoc !== undefined) {
        results = results.filter(cve => cve.hasPublicPoc === filters.hasPublicPoc);
      }
      
      if (filters.isDockerDeployable !== undefined) {
        results = results.filter(cve => cve.isDockerDeployable === filters.isDockerDeployable);
      }
      
      if (filters.isCurlTestable !== undefined) {
        results = results.filter(cve => cve.isCurlTestable === filters.isCurlTestable);
      }
      
      if (filters.minCvssScore !== undefined) {
        results = results.filter(cve => cve.cvssScore && cve.cvssScore >= filters.minCvssScore!);
      }
      
      if (filters.maxCvssScore !== undefined) {
        results = results.filter(cve => cve.cvssScore && cve.cvssScore <= filters.maxCvssScore!);
      }
      
      if (filters.search) {
        const searchLower = filters.search.toLowerCase();
        results = results.filter(cve => 
          cve.cveId.toLowerCase().includes(searchLower) ||
          cve.description.toLowerCase().includes(searchLower) ||
          cve.technology?.toLowerCase().includes(searchLower) ||
          cve.affectedProduct?.toLowerCase().includes(searchLower)
        );
      }
      
      if (filters.offset) {
        results = results.slice(filters.offset);
      }
      
      if (filters.limit) {
        results = results.slice(0, filters.limit);
      }
    }

    return results.sort((a, b) => new Date(b.publishedDate).getTime() - new Date(a.publishedDate).getTime());
  }

  async createCve(insertCve: InsertCve): Promise<Cve> {
    const id = randomUUID();
    const now = new Date();
    const cve: Cve = { 
      ...insertCve,
      id,
      createdAt: now,
      updatedAt: now,
      cvssScore: insertCve.cvssScore ?? null,
      cvssVector: insertCve.cvssVector ?? null,
      affectedProduct: insertCve.affectedProduct ?? null,
      affectedVersions: insertCve.affectedVersions ?? null,
      attackVector: insertCve.attackVector ?? null,
      technology: insertCve.technology ?? null,
      category: insertCve.category ?? null,
      pocUrls: insertCve.pocUrls ?? null,
      exploitabilityScore: insertCve.exploitabilityScore ?? null,
      labSuitabilityScore: insertCve.labSuitabilityScore ?? null
    };
    this.cves.set(id, cve);
    return cve;
  }

  async updateCve(id: string, updates: Partial<InsertCve>): Promise<Cve | undefined> {
    const existing = this.cves.get(id);
    if (!existing) return undefined;
    
    const updated: Cve = { 
      ...existing, 
      ...updates, 
      updatedAt: new Date() 
    };
    this.cves.set(id, updated);
    return updated;
  }

  async deleteCve(id: string): Promise<boolean> {
    return this.cves.delete(id);
  }

  async getCveScan(id: string): Promise<CveScan | undefined> {
    return this.cveScans.get(id);
  }

  async getCveScans(): Promise<CveScan[]> {
    return Array.from(this.cveScans.values())
      .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
  }

  async createCveScan(insertScan: InsertCveScan): Promise<CveScan> {
    const id = randomUUID();
    const now = new Date();
    const scan: CveScan = { 
      timeframeYears: insertScan.timeframeYears || 3,
      status: insertScan.status || 'pending',
      totalFound: insertScan.totalFound ?? 0,
      labDeployable: insertScan.labDeployable ?? 0,
      withPoc: insertScan.withPoc ?? 0,
      criticalSeverity: insertScan.criticalSeverity ?? 0,
      errorMessage: insertScan.errorMessage ?? null,
      id,
      startedAt: now,
      completedAt: null
    };
    this.cveScans.set(id, scan);
    return scan;
  }

  async updateCveScan(id: string, updates: Partial<InsertCveScan>): Promise<CveScan | undefined> {
    const existing = this.cveScans.get(id);
    if (!existing) return undefined;
    
    const updated: CveScan = { 
      ...existing, 
      ...updates,
      completedAt: updates.status === 'completed' || updates.status === 'failed' ? new Date() : existing.completedAt
    };
    this.cveScans.set(id, updated);
    return updated;
  }

  async getCveStats(): Promise<CveStats> {
    const allCves = Array.from(this.cves.values());
    
    return {
      totalCves: allCves.length,
      deployable: allCves.filter(cve => cve.isDockerDeployable).length,
      withPoc: allCves.filter(cve => cve.hasPublicPoc).length,
      critical: allCves.filter(cve => cve.severity === 'CRITICAL').length
    };
  }
}

export const storage = new MemStorage();
