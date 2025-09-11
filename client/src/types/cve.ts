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

export interface Cve {
  id: string;
  cveId: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  cvssScore: number | null;
  cvssVector: string | null;
  severity: string;
  affectedProduct: string | null;
  affectedVersions: string[] | null;
  attackVector: string | null;
  technology: string | null;
  category: string | null;
  hasPublicPoc: boolean;
  isDockerDeployable: boolean;
  isCurlTestable: boolean;
  pocUrls: string[] | null;
  dockerInfo: any;
  fingerprintInfo: any;
  exploitabilityScore: number | null;
  labSuitabilityScore: number | null;
  createdAt: string;
  updatedAt: string;
}

export interface CveScan {
  id: string;
  timeframeYears: number;
  totalFound: number;
  labDeployable: number;
  withPoc: number;
  criticalSeverity: number;
  status: string;
  startedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
}
