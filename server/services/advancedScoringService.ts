export interface EducationalFactors {
  skillLevel: 'beginner' | 'intermediate' | 'advanced';
  learningObjectives: string[];
  owasp?: string[];
  realWorldPrevalence: number; // 1-10 scale
}

export interface DeploymentFactors {
  setupComplexity: 'simple' | 'moderate' | 'complex';
  prerequisites: string[];
  deploymentTime: 'quick' | 'moderate' | 'lengthy'; // <5min, 5-30min, >30min
  resourceRequirements: 'low' | 'medium' | 'high';
}

export interface TechnicalFactors {
  exploitComplexity: 'low' | 'medium' | 'high';
  requiredTools: string[];
  successProbability: number; // 1-10 scale
  knowledgeRequired: string[];
}

export interface PracticalFactors {
  industryRelevance: number; // 1-10 scale
  activeExploitation: boolean;
  mitigationValue: number; // 1-10 scale
  certificationRelevance: string[];
}

export interface AdvancedScoringConfig {
  weights: {
    educational: number;
    deployment: number;
    technical: number;
    practical: number;
    baseline: number; // Original CVSS-based score
  };
  skillLevelMultipliers: {
    beginner: number;
    intermediate: number;
    advanced: number;
  };
  complexityPenalties: {
    simple: number;
    moderate: number;
    complex: number;
  };
}

export class AdvancedScoringService {
  private config: AdvancedScoringConfig = {
    weights: {
      educational: 0.25,
      deployment: 0.20,
      technical: 0.15,
      practical: 0.15,
      baseline: 0.25
    },
    skillLevelMultipliers: {
      beginner: 1.2,
      intermediate: 1.0,
      advanced: 0.8
    },
    complexityPenalties: {
      simple: 1.0,
      moderate: 0.85,
      complex: 0.7
    }
  };

  calculateAdvancedScore(
    cve: any,
    educational: EducationalFactors,
    deployment: DeploymentFactors,
    technical: TechnicalFactors,
    practical: PracticalFactors
  ): { score: number; breakdown: any } {
    // Get baseline score from existing system
    const baselineScore = this.calculateBaselineScore(cve);
    
    // Calculate component scores
    const educationalScore = this.calculateEducationalScore(educational);
    const deploymentScore = this.calculateDeploymentScore(deployment);
    const technicalScore = this.calculateTechnicalScore(technical);
    const practicalScore = this.calculatePracticalScore(practical);
    
    // Weighted combination
    const weightedScore = 
      (baselineScore * this.config.weights.baseline) +
      (educationalScore * this.config.weights.educational) +
      (deploymentScore * this.config.weights.deployment) +
      (technicalScore * this.config.weights.technical) +
      (practicalScore * this.config.weights.practical);
    
    const finalScore = Math.min(weightedScore, 10);
    
    return {
      score: Math.round(finalScore * 10) / 10,
      breakdown: {
        baseline: Math.round(baselineScore * 10) / 10,
        educational: Math.round(educationalScore * 10) / 10,
        deployment: Math.round(deploymentScore * 10) / 10,
        technical: Math.round(technicalScore * 10) / 10,
        practical: Math.round(practicalScore * 10) / 10,
        weights: this.config.weights
      }
    };
  }

  private calculateBaselineScore(cve: any): number {
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

  private calculateEducationalScore(factors: EducationalFactors): number {
    let score = 0;
    
    // Skill level appropriateness (40%)
    const skillMultiplier = this.config.skillLevelMultipliers[factors.skillLevel];
    score += 4 * skillMultiplier;
    
    // Learning objectives breadth (30%)
    const objectiveScore = Math.min(factors.learningObjectives.length * 0.5, 3);
    score += objectiveScore;
    
    // OWASP relevance (20%)
    if (factors.owasp && factors.owasp.length > 0) {
      score += Math.min(factors.owasp.length * 0.4, 2);
    }
    
    // Real-world prevalence (10%)
    score += (factors.realWorldPrevalence / 10) * 1;
    
    return Math.min(score, 10);
  }

  private calculateDeploymentScore(factors: DeploymentFactors): number {
    let score = 10; // Start high, apply penalties
    
    // Setup complexity penalty (40%)
    const complexityPenalty = this.config.complexityPenalties[factors.setupComplexity];
    score *= complexityPenalty;
    
    // Prerequisites penalty (25%)
    const prereqPenalty = Math.max(0.5, 1 - (factors.prerequisites.length * 0.1));
    score *= prereqPenalty;
    
    // Deployment time penalty (25%)
    const timePenalties = { quick: 1.0, moderate: 0.8, lengthy: 0.6 };
    score *= timePenalties[factors.deploymentTime];
    
    // Resource requirements penalty (10%)
    const resourcePenalties = { low: 1.0, medium: 0.9, high: 0.7 };
    score *= resourcePenalties[factors.resourceRequirements];
    
    return Math.max(score, 1);
  }

  private calculateTechnicalScore(factors: TechnicalFactors): number {
    let score = 0;
    
    // Exploit complexity (40%) - inverted (easier = higher score)
    const complexityScores = { low: 4, medium: 2.5, high: 1 };
    score += complexityScores[factors.exploitComplexity];
    
    // Success probability (30%)
    score += (factors.successProbability / 10) * 3;
    
    // Tool availability (20%)
    const toolScore = Math.min(factors.requiredTools.length * 0.3, 2);
    score += toolScore;
    
    // Knowledge requirements (10%) - fewer requirements = higher score
    const knowledgePenalty = Math.max(0.5, 1 - (factors.knowledgeRequired.length * 0.1));
    score += 1 * knowledgePenalty;
    
    return Math.min(score, 10);
  }

  private calculatePracticalScore(factors: PracticalFactors): number {
    let score = 0;
    
    // Industry relevance (40%)
    score += (factors.industryRelevance / 10) * 4;
    
    // Active exploitation bonus (30%)
    if (factors.activeExploitation) {
      score += 3;
    }
    
    // Mitigation learning value (20%)
    score += (factors.mitigationValue / 10) * 2;
    
    // Certification relevance (10%)
    if (factors.certificationRelevance.length > 0) {
      score += Math.min(factors.certificationRelevance.length * 0.2, 1);
    }
    
    return Math.min(score, 10);
  }

  // Auto-generate factors based on CVE data for demonstration
  generateFactorsFromCve(cve: any): {
    educational: EducationalFactors;
    deployment: DeploymentFactors;
    technical: TechnicalFactors;
    practical: PracticalFactors;
  } {
    const product = cve.affectedProduct?.toLowerCase() || '';
    const severity = cve.severity || '';
    
    // Educational factors based on CVE characteristics
    const educational: EducationalFactors = {
      skillLevel: this.determineSkillLevel(cve),
      learningObjectives: this.generateLearningObjectives(cve),
      owasp: this.mapToOwaspTop10(cve),
      realWorldPrevalence: this.estimatePrevalence(product)
    };
    
    // Deployment factors
    const deployment: DeploymentFactors = {
      setupComplexity: this.determineSetupComplexity(product),
      prerequisites: this.generatePrerequisites(product),
      deploymentTime: this.estimateDeploymentTime(cve),
      resourceRequirements: this.estimateResourceRequirements(product)
    };
    
    // Technical factors
    const technical: TechnicalFactors = {
      exploitComplexity: this.mapCvssComplexity(cve.cvssVector),
      requiredTools: this.generateRequiredTools(cve),
      successProbability: this.estimateSuccessProbability(cve),
      knowledgeRequired: this.generateKnowledgeRequirements(cve)
    };
    
    // Practical factors
    const practical: PracticalFactors = {
      industryRelevance: this.estimateIndustryRelevance(product),
      activeExploitation: this.estimateActiveExploitation(cve),
      mitigationValue: this.estimateMitigationValue(severity),
      certificationRelevance: this.mapToCertifications(cve)
    };
    
    return { educational, deployment, technical, practical };
  }

  private determineSkillLevel(cve: any): 'beginner' | 'intermediate' | 'advanced' {
    const cvssScore = cve.cvssScore || 0;
    const hasPoC = cve.hasPublicPoc;
    const isNetworkVector = cve.attackVector === 'Network';
    
    if (hasPoC && isNetworkVector && cvssScore >= 7) {
      return 'beginner';
    } else if (cvssScore >= 5) {
      return 'intermediate';
    }
    return 'advanced';
  }

  private generateLearningObjectives(cve: any): string[] {
    const objectives = ['Vulnerability Assessment', 'Exploitation Techniques'];
    
    if (cve.attackVector === 'Network') objectives.push('Network Security');
    if (cve.hasPublicPoc) objectives.push('Proof of Concept Analysis');
    if (cve.isDockerDeployable) objectives.push('Containerized Lab Setup');
    if (cve.category?.includes('Web')) objectives.push('Web Application Security');
    
    return objectives;
  }

  private mapToOwaspTop10(cve: any): string[] {
    const owasp = [];
    const description = cve.description?.toLowerCase() || '';
    
    if (description.includes('injection') || description.includes('sql')) {
      owasp.push('A03-Injection');
    }
    if (description.includes('authentication') || description.includes('bypass')) {
      owasp.push('A07-Authentication Failures');
    }
    if (description.includes('xss') || description.includes('cross-site')) {
      owasp.push('A03-Cross-Site Scripting');
    }
    if (description.includes('path traversal') || description.includes('directory')) {
      owasp.push('A01-Path Traversal');
    }
    
    return owasp;
  }

  private estimatePrevalence(product: string): number {
    const commonProducts = ['apache', 'nginx', 'mysql', 'wordpress', 'openssh'];
    if (commonProducts.some(p => product.includes(p))) return 8;
    return 5;
  }

  private determineSetupComplexity(product: string): 'simple' | 'moderate' | 'complex' {
    const simpleProducts = ['apache', 'nginx', 'wordpress'];
    const complexProducts = ['oracle', 'sap', 'citrix'];
    
    if (simpleProducts.some(p => product.includes(p))) return 'simple';
    if (complexProducts.some(p => product.includes(p))) return 'complex';
    return 'moderate';
  }

  private generatePrerequisites(product: string): string[] {
    const prereqs = ['Basic Linux Knowledge'];
    
    if (product.includes('web') || product.includes('apache') || product.includes('nginx')) {
      prereqs.push('Web Server Configuration');
    }
    if (product.includes('database') || product.includes('mysql') || product.includes('postgres')) {
      prereqs.push('Database Administration');
    }
    
    return prereqs;
  }

  private estimateDeploymentTime(cve: any): 'quick' | 'moderate' | 'lengthy' {
    if (cve.isDockerDeployable) return 'quick';
    if (cve.hasPublicPoc) return 'moderate';
    return 'lengthy';
  }

  private estimateResourceRequirements(product: string): 'low' | 'medium' | 'high' {
    const lightProducts = ['apache', 'nginx', 'openssh'];
    const heavyProducts = ['oracle', 'citrix', 'vmware'];
    
    if (lightProducts.some(p => product.includes(p))) return 'low';
    if (heavyProducts.some(p => product.includes(p))) return 'high';
    return 'medium';
  }

  private mapCvssComplexity(cvssVector: string): 'low' | 'medium' | 'high' {
    if (!cvssVector) return 'medium';
    
    if (cvssVector.includes('AC:L')) return 'low';
    if (cvssVector.includes('AC:H')) return 'high';
    return 'medium';
  }

  private generateRequiredTools(cve: any): string[] {
    const tools = ['Kali Linux', 'Metasploit'];
    
    if (cve.isCurlTestable) tools.push('curl', 'nmap');
    if (cve.category?.includes('Web')) tools.push('Burp Suite', 'OWASP ZAP');
    if (cve.hasPublicPoc) tools.push('Python', 'Git');
    
    return tools;
  }

  private estimateSuccessProbability(cve: any): number {
    let probability = 5;
    
    if (cve.hasPublicPoc) probability += 3;
    if (cve.isDockerDeployable) probability += 2;
    if (cve.cvssScore >= 8) probability += 1;
    
    return Math.min(probability, 10);
  }

  private generateKnowledgeRequirements(cve: any): string[] {
    const knowledge = ['Cybersecurity Basics'];
    
    if (cve.attackVector === 'Network') knowledge.push('Network Protocols');
    if (cve.category?.includes('Web')) knowledge.push('HTTP/HTTPS', 'Web Technologies');
    if (cve.description?.includes('buffer overflow')) knowledge.push('Memory Management', 'Assembly Language');
    
    return knowledge;
  }

  private estimateIndustryRelevance(product: string): number {
    const highRelevance = ['apache', 'nginx', 'mysql', 'openssh', 'wordpress'];
    if (highRelevance.some(p => product.includes(p))) return 9;
    return 6;
  }

  private estimateActiveExploitation(cve: any): boolean {
    // In a real system, this would query threat intelligence feeds
    const criticalCves = ['CVE-2024-4577', 'CVE-2024-3400'];
    return criticalCves.includes(cve.cveId) || cve.cvssScore >= 9.5;
  }

  private estimateMitigationValue(severity: string): number {
    const severityScores = { 'CRITICAL': 9, 'HIGH': 7, 'MEDIUM': 5, 'LOW': 3 };
    return severityScores[severity as keyof typeof severityScores] || 5;
  }

  private mapToCertifications(cve: any): string[] {
    const certs = ['CEH'];
    
    if (cve.category?.includes('Web')) certs.push('CISSP', 'OSCP');
    if (cve.cvssScore >= 8) certs.push('CISSP');
    if (cve.hasPublicPoc) certs.push('OSCP');
    
    return certs;
  }

  updateConfig(newConfig: Partial<AdvancedScoringConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  getConfig(): AdvancedScoringConfig {
    return { ...this.config };
  }
}

export const advancedScoringService = new AdvancedScoringService();