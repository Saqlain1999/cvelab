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
  // Status management filters
  status?: string[];
  listCategory?: string[];
  isPriority?: boolean;
  hideDone?: boolean;
}

export interface CveStats {
  totalCves: number;
  deployable: number;
  withPoc: number;
  critical: number;
  // Status statistics
  newCount: number;
  inProgressCount: number;
  doneCount: number;
  unlistedCount: number;
  priorityCount: number;
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
  // Status management fields
  status: string;
  listCategory: string | null;
  isPriority: boolean;
  userNotes: string | null;
  statusUpdatedAt: string | null;
}

// CVE Status Management Types
export type CveStatus = "new" | "in_progress" | "done" | "unlisted";

export interface CveStatusUpdate {
  status?: CveStatus;
  listCategory?: string | null;
  isPriority?: boolean;
  userNotes?: string | null;
}

export interface BulkStatusUpdate {
  cveIds: string[];
  updates: CveStatusUpdate;
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
