export interface SearchResult {
  id: string;
  title: string;
  url: string;
  description: string;
  source: SearchSource;
  relevanceScore: number;
  metadata: SearchResultMetadata;
  cveRelevance: CveRelevanceInfo;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface SearchResultMetadata {
  author?: string;
  publishDate?: Date;
  tags?: string[];
  language?: string;
  views?: number;
  stars?: number;
  downloads?: number;
  sourceSpecific: Record<string, any>;
}

export interface CveRelevanceInfo {
  cveMatch: 'exact' | 'partial' | 'none';
  contextType: PocContextType;
  deploymentInfo: DeploymentInfo;
  educational: boolean;
  technical: boolean;
}

export interface DeploymentInfo {
  hasDocker: boolean;
  dockerFiles?: string[];
  hasVagrant: boolean;
  hasScript: boolean;
  complexity: 'simple' | 'moderate' | 'complex';
  requirements: string[];
}

export enum SearchSource {
  GITHUB = 'github',
  DOCKERHUB = 'dockerhub',
  MEDIUM = 'medium',
  YOUTUBE = 'youtube',
  EXPLOITDB = 'exploitdb',
  SECURITY_BLOG = 'security_blog',
  CVE_MITRE = 'cve_mitre',
  NVD = 'nvd'
}

export enum PocContextType {
  PROOF_OF_CONCEPT = 'poc',
  EXPLOIT = 'exploit',
  VULNERABILITY_ANALYSIS = 'analysis',
  TUTORIAL = 'tutorial',
  WRITEUP = 'writeup',
  DEMO = 'demo',
  TOOL = 'tool',
  CONTAINER = 'container',
  LAB_SETUP = 'lab_setup'
}

export interface MultiSourceSearchRequest {
  cveId: string;
  additionalTerms?: string[];
  sources?: SearchSource[];
  maxResultsPerSource?: number;
  includeEducational?: boolean;
  includeTechnical?: boolean;
  prioritizeDeployable?: boolean;
}

export interface MultiSourceSearchResponse {
  cveId: string;
  totalResults: number;
  searchTime: number;
  results: SearchResult[];
  sourceBreakdown: Record<SearchSource, number>;
  errors: SearchError[];
}

export interface SearchError {
  source: SearchSource;
  error: string;
  recoverable: boolean;
  retryAfter?: number;
}

export interface RateLimitInfo {
  source: SearchSource;
  remaining: number;
  resetTime: Date;
  isLimited: boolean;
}

export interface SearchSourceConfig {
  enabled: boolean;
  apiKey?: string;
  baseUrl: string;
  rateLimit: {
    requestsPerMinute: number;
    requestsPerHour: number;
  };
  timeout: number;
  retryAttempts: number;
}

export interface SourceSearchOptions {
  query: string;
  maxResults: number;
  filters?: Record<string, any>;
  sortBy?: 'relevance' | 'date' | 'popularity';
}