import { rateLimit } from './rateLimiter';

export type DeploymentResourceType = 'docker' | 'vm_image' | 'iso' | 'trial' | 'documentation';

export interface DeploymentResource {
  type: DeploymentResourceType;
  title: string;
  url: string;
  description?: string;
  source?: string;
  confidence: number; // 0-1
  tags?: string[];
}

export interface DeploymentResourceOptions {
  query: string;
  maxResults?: number;
}

/**
 * Discovers deployment resources such as Docker images, VM images, ISOs, and trials.
 * Uses free endpoints and heuristics; can be extended with provider APIs later.
 */
export class DeploymentResourceService {
  async discoverResources(cveId: string, options: DeploymentResourceOptions): Promise<DeploymentResource[]> {
    const results: DeploymentResource[] = [];
    const max = options.maxResults || 10;

    // 1) Reuse Docker Hub search (HTTP JSON), already rate-limited by caller if needed
    try {
      const dockerResources = await this.searchDockerHub(options.query, Math.min(5, max));
      results.push(...dockerResources);
    } catch (e) {
      console.warn('DeploymentResourceService: DockerHub search failed:', e);
    }

    // 2) Heuristic vendor download/trial pages (no API): build known vendor links
    results.push(...this.heuristicVendorLinks(options.query));

    // 3) Fallback documentation/build guides via curated sources (docs, wiki)
    results.push(...this.heuristicDocsLinks(options.query));

    // De-duplicate by URL and cap
    const seen = new Set<string>();
    const unique = results.filter(r => {
      if (seen.has(r.url)) return false;
      seen.add(r.url);
      return true;
    });

    return unique.slice(0, max);
  }

  private async searchDockerHub(query: string, max: number): Promise<DeploymentResource[]> {
    await rateLimit('DockerHub');
    const url = `https://hub.docker.com/v2/search/repositories/?query=${encodeURIComponent(query)}&page_size=${Math.max(10, max)}`;
    const resp = await fetch(url, { headers: { 'User-Agent': 'CVE-Lab-Hunter/2.0' }, signal: AbortSignal.timeout(15000) });
    if (!resp.ok) return [];
    const data = await resp.json();
    const items = (data.results || []).slice(0, max).map((repo: any) => ({
      type: 'docker' as const,
      title: repo.name,
      url: `https://hub.docker.com/r/${repo.namespace}/${repo.name}`,
      description: repo.short_description || 'Docker image',
      source: 'DockerHub',
      confidence: 0.6 + Math.min(0.3, Math.log10((repo.pull_count || 1))) / 10,
      tags: ['docker', repo.is_official ? 'official' : 'community']
    }));
    return items;
  }

  private heuristicVendorLinks(query: string): DeploymentResource[] {
    const q = query.toLowerCase();
    const links: DeploymentResource[] = [];

    const push = (type: DeploymentResourceType, title: string, url: string, confidence = 0.5, tags: string[] = []) => {
      links.push({ type, title, url, confidence, tags, source: 'heuristic' });
    };

    // Common vendors/platforms where trials/ISOs are public
    if (q.includes('vmware') || q.includes('esxi') || q.includes('vcenter')) {
      push('iso', 'VMware ESXi ISO (portal)', 'https://customerconnect.vmware.com/downloads');
      push('trial', 'VMware Product Trials', 'https://www.vmware.com/try-vmware.html');
    }
    if (q.includes('microsoft') || q.includes('exchange') || q.includes('sharepoint') || q.includes('windows')) {
      push('trial', 'Microsoft Evaluation Center', 'https://www.microsoft.com/evalcenter/');
    }
    if (q.includes('oracle') || q.includes('weblogic')) {
      push('trial', 'Oracle Software Downloads', 'https://www.oracle.com/downloads/');
    }
    if (q.includes('sap') || q.includes('netweaver')) {
      push('trial', 'SAP Trials and Downloads', 'https://www.sap.com/products/trials-downloads.html');
    }
    if (q.includes('fortinet') || q.includes('fortigate')) {
      push('trial', 'Fortinet Trial Licensing', 'https://www.fortinet.com/support/product-downloads');
    }
    if (q.includes('palo alto') || q.includes('panos')) {
      push('trial', 'Palo Alto Networks Software', 'https://support.paloaltonetworks.com/Updates');
    }
    if (q.includes('f5') || q.includes('big-ip')) {
      push('trial', 'F5 Downloads (BIG-IP)', 'https://downloads.f5.com/');
    }
    if (q.includes('citrix') || q.includes('adc') || q.includes('netscaler')) {
      push('trial', 'Citrix Downloads', 'https://www.citrix.com/downloads/');
    }

    return links;
  }

  private heuristicDocsLinks(query: string): DeploymentResource[] {
    const docs: DeploymentResource[] = [];
    const enc = encodeURIComponent(query);
    docs.push({
      type: 'documentation',
      title: 'Search: Official Docs',
      url: `https://duckduckgo.com/?q=${enc}+site%3Adocs.*`,
      source: 'heuristic',
      confidence: 0.3,
      tags: ['docs']
    });
    docs.push({
      type: 'documentation',
      title: 'Search: Build Guides',
      url: `https://duckduckgo.com/?q=${enc}+install+guide+documentation`,
      source: 'heuristic',
      confidence: 0.3,
      tags: ['build']
    });
    return docs;
  }
}

export const deploymentResourceService = new DeploymentResourceService();


