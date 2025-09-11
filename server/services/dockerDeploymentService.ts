import { Cve } from "@shared/schema";
import { multiSourceDiscoveryService, PocSource, DockerDeploymentInfo } from './multiSourceDiscoveryService';
import { GitHubService } from './githubService';

export interface DeploymentTemplate {
  id: string;
  name: string;
  category: VulnerabilityCategory;
  dockerfileContent: string;
  composeContent: string;
  setupInstructions: SetupInstruction[];
  complexity: DeploymentComplexity;
  estimatedSetupTime: string;
  prerequisites: string[];
  exposedPorts: number[];
  environment: Record<string, string>;
  volumes: VolumeMapping[];
  networkRequirements: string[];
  healthCheck?: HealthCheckConfig;
  metadata: DeploymentMetadata;
}

export interface SetupInstruction {
  id: string;
  step: number;
  title: string;
  description: string;
  command?: string;
  type: 'command' | 'manual' | 'download' | 'config' | 'verify';
  optional: boolean;
  troubleshooting?: string[];
}

export interface VolumeMapping {
  host: string;
  container: string;
  type: 'bind' | 'volume';
  readOnly?: boolean;
}

export interface HealthCheckConfig {
  test: string[];
  interval: string;
  timeout: string;
  retries: number;
  startPeriod?: string;
}

export interface DeploymentMetadata {
  author: string;
  description: string;
  tags: string[];
  lastUpdated: Date;
  version: string;
  sourceUrl?: string;
  documentation?: string;
  compatibility: {
    os: string[];
    dockerVersion: string;
    composeVersion: string;
  };
}

export enum VulnerabilityCategory {
  WEB_APPLICATION = 'web_application',
  NETWORK_SERVICE = 'network_service',
  DATABASE = 'database',
  CMS = 'cms',
  CONTAINER = 'container',
  NETWORK_SECURITY = 'network_security',
  API_SERVICE = 'api_service',
  AUTHENTICATION = 'authentication',
  FILE_UPLOAD = 'file_upload',
  OTHER = 'other'
}

export enum DeploymentComplexity {
  SIMPLE = 'simple',       // 1-2 containers, no external dependencies
  MODERATE = 'moderate',   // Multiple containers, some configuration required
  COMPLEX = 'complex'      // Complex setup, multiple services, custom configs
}

export interface AutomatedDeployment {
  cveId: string;
  template: DeploymentTemplate;
  customInstructions: SetupInstruction[];
  deploymentScript: string;
  testingScript: string;
  cleanupScript: string;
  pocUrls: string[];
  deploymentTime: string;
  resourceRequirements: {
    memory: string;
    cpu: string;
    storage: string;
  };
}

export interface DeploymentAnalysis {
  isDeployable: boolean;
  recommendedTemplate: DeploymentTemplate | null;
  alternativeOptions: DeploymentTemplate[];
  customConfiguration: any;
  deploymentChallenges: string[];
  mitigationSuggestions: string[];
  communityResources: PocSource[];
}

export class DockerDeploymentService {
  private githubService: GitHubService;
  private templates: Map<string, DeploymentTemplate>;

  constructor() {
    this.githubService = new GitHubService();
    this.templates = new Map();
    this.initializeTemplates();
  }

  private initializeTemplates() {
    // Web Application Templates
    this.templates.set('web_app_basic', this.createWebAppTemplate());
    this.templates.set('web_app_php', this.createPHPWebAppTemplate());
    this.templates.set('web_app_nodejs', this.createNodeJSWebAppTemplate());
    
    // Network Service Templates
    this.templates.set('network_ssh', this.createSSHServiceTemplate());
    this.templates.set('network_ftp', this.createFTPServiceTemplate());
    this.templates.set('network_smtp', this.createSMTPServiceTemplate());
    
    // Database Templates
    this.templates.set('database_mysql', this.createMySQLTemplate());
    this.templates.set('database_postgresql', this.createPostgreSQLTemplate());
    this.templates.set('database_mongodb', this.createMongoDBTemplate());
    
    // CMS Templates
    this.templates.set('cms_wordpress', this.createWordPressTemplate());
    this.templates.set('cms_drupal', this.createDrupalTemplate());
    this.templates.set('cms_joomla', this.createJoomlaTemplate());
    
    // Container Security Templates
    this.templates.set('container_docker', this.createDockerSecurityTemplate());
    this.templates.set('container_kubernetes', this.createKubernetesTemplate());
  }

  async generateAutomatedDeployment(cve: Cve): Promise<AutomatedDeployment | null> {
    try {
      console.log(`Generating automated deployment for ${cve.cveId}...`);
      
      // Analyze CVE for deployment possibilities
      const analysis = await this.analyzeDeploymentPossibilities(cve);
      
      if (!analysis.isDeployable || !analysis.recommendedTemplate) {
        console.log(`CVE ${cve.cveId} is not suitable for automated deployment`);
        return null;
      }

      // Generate custom instructions based on CVE specifics
      const customInstructions = await this.generateCustomInstructions(cve, analysis.recommendedTemplate);
      
      // Create deployment scripts
      const deploymentScript = this.generateDeploymentScript(cve, analysis.recommendedTemplate);
      const testingScript = this.generateTestingScript(cve, analysis.recommendedTemplate);
      const cleanupScript = this.generateCleanupScript(cve, analysis.recommendedTemplate);

      // Estimate deployment time based on complexity
      const deploymentTime = this.estimateDeploymentTime(analysis.recommendedTemplate);

      return {
        cveId: cve.cveId,
        template: analysis.recommendedTemplate,
        customInstructions,
        deploymentScript,
        testingScript,
        cleanupScript,
        pocUrls: cve.pocUrls || [],
        deploymentTime,
        resourceRequirements: {
          memory: this.calculateMemoryRequirement(analysis.recommendedTemplate),
          cpu: this.calculateCPURequirement(analysis.recommendedTemplate),
          storage: this.calculateStorageRequirement(analysis.recommendedTemplate)
        }
      };
    } catch (error) {
      console.error(`Error generating automated deployment for ${cve.cveId}:`, error);
      return null;
    }
  }

  async analyzeDeploymentPossibilities(cve: Cve): Promise<DeploymentAnalysis> {
    // Get existing discovery data if available
    const discoveryMetadata = cve.discoveryMetadata as any;
    
    // Enhanced analysis with multi-source discovery
    const discoveryResults = await multiSourceDiscoveryService.discoverAllSources(
      cve.cveId,
      { 
        query: `${cve.cveId} docker deployment setup`,
        maxResults: 15,
        includeDockerInfo: true
      }
    );

    // Determine suitable templates based on CVE category and technology
    const suitableTemplates = this.findSuitableTemplates(cve);
    const recommendedTemplate = this.selectBestTemplate(cve, suitableTemplates, discoveryResults);

    // Analyze deployment challenges
    const deploymentChallenges = this.identifyDeploymentChallenges(cve, discoveryResults);
    const mitigationSuggestions = this.generateMitigationSuggestions(deploymentChallenges, cve);

    return {
      isDeployable: recommendedTemplate !== null,
      recommendedTemplate,
      alternativeOptions: suitableTemplates.filter(t => t.id !== recommendedTemplate?.id),
      customConfiguration: this.generateCustomConfiguration(cve, discoveryResults),
      deploymentChallenges,
      mitigationSuggestions,
      communityResources: discoveryResults.sources || []
    };
  }

  private findSuitableTemplates(cve: Cve): DeploymentTemplate[] {
    const suitableTemplates: DeploymentTemplate[] = [];
    const category = cve.category?.toLowerCase() || '';
    const technology = cve.technology?.toLowerCase() || '';
    const product = cve.affectedProduct?.toLowerCase() || '';

    // Match templates based on category
    if (category.includes('web') || category.includes('cms')) {
      if (technology.includes('php') || product.includes('php')) {
        suitableTemplates.push(this.templates.get('web_app_php')!);
      }
      if (technology.includes('node') || product.includes('node')) {
        suitableTemplates.push(this.templates.get('web_app_nodejs')!);
      }
      if (product.includes('wordpress')) {
        suitableTemplates.push(this.templates.get('cms_wordpress')!);
      }
      if (product.includes('drupal')) {
        suitableTemplates.push(this.templates.get('cms_drupal')!);
      }
      if (product.includes('joomla')) {
        suitableTemplates.push(this.templates.get('cms_joomla')!);
      }
      // Add generic web app template as fallback
      suitableTemplates.push(this.templates.get('web_app_basic')!);
    }

    if (category.includes('network') || category.includes('service')) {
      if (technology.includes('ssh') || product.includes('openssh')) {
        suitableTemplates.push(this.templates.get('network_ssh')!);
      }
      if (technology.includes('ftp')) {
        suitableTemplates.push(this.templates.get('network_ftp')!);
      }
      if (technology.includes('smtp') || technology.includes('mail')) {
        suitableTemplates.push(this.templates.get('network_smtp')!);
      }
    }

    if (category.includes('database')) {
      if (technology.includes('mysql') || product.includes('mysql')) {
        suitableTemplates.push(this.templates.get('database_mysql')!);
      }
      if (technology.includes('postgresql') || product.includes('postgresql')) {
        suitableTemplates.push(this.templates.get('database_postgresql')!);
      }
      if (technology.includes('mongodb') || product.includes('mongodb')) {
        suitableTemplates.push(this.templates.get('database_mongodb')!);
      }
    }

    if (category.includes('container') || technology.includes('docker')) {
      suitableTemplates.push(this.templates.get('container_docker')!);
    }

    return suitableTemplates.filter(Boolean);
  }

  private selectBestTemplate(
    cve: Cve, 
    suitableTemplates: DeploymentTemplate[], 
    discoveryResults: any
  ): DeploymentTemplate | null {
    if (suitableTemplates.length === 0) return null;

    // Score templates based on various factors
    const scoredTemplates = suitableTemplates.map(template => {
      let score = 0;

      // Technology match score
      const technology = cve.technology?.toLowerCase() || '';
      const product = cve.affectedProduct?.toLowerCase() || '';
      
      if (template.name.toLowerCase().includes(technology)) score += 3;
      if (template.name.toLowerCase().includes(product.split(' ')[0])) score += 2;

      // Community resource availability score
      const hasDockerResources = discoveryResults.sources?.some((source: any) => 
        source.type === 'dockerhub' || source.type === 'github'
      ) || false;
      if (hasDockerResources) score += 2;

      // Complexity preference (prefer simpler setups)
      if (template.complexity === DeploymentComplexity.SIMPLE) score += 2;
      else if (template.complexity === DeploymentComplexity.MODERATE) score += 1;

      // CVSS score consideration (higher CVSS = prefer simpler deployment)
      if (cve.cvssScore && cve.cvssScore >= 9.0 && template.complexity === DeploymentComplexity.SIMPLE) {
        score += 1;
      }

      return { template, score };
    });

    // Return the highest scoring template
    scoredTemplates.sort((a, b) => b.score - a.score);
    return scoredTemplates[0].template;
  }

  private generateCustomInstructions(cve: Cve, template: DeploymentTemplate): SetupInstruction[] {
    const customInstructions: SetupInstruction[] = [...template.setupInstructions];
    
    // Add CVE-specific instructions
    if (cve.pocUrls && cve.pocUrls.length > 0) {
      customInstructions.splice(1, 0, {
        id: `download-poc-${cve.cveId}`,
        step: 1.5,
        title: 'Download Proof of Concept',
        description: `Download the PoC code for ${cve.cveId}`,
        command: `git clone ${cve.pocUrls[0]} ./poc-${cve.cveId}`,
        type: 'download',
        optional: false,
        troubleshooting: [
          'Ensure git is installed',
          'Check internet connectivity',
          'Try alternative PoC URLs if primary fails'
        ]
      });
    }

    // Add testing instructions
    customInstructions.push({
      id: `test-${cve.cveId}`,
      step: 100,
      title: 'Test Vulnerability',
      description: `Verify the ${cve.cveId} vulnerability is exploitable`,
      command: this.generateTestCommand(cve, template),
      type: 'verify',
      optional: false,
      troubleshooting: [
        'Ensure target service is running',
        'Check firewall settings',
        'Verify exploit compatibility'
      ]
    });

    return customInstructions.sort((a, b) => a.step - b.step);
  }

  private generateDeploymentScript(cve: Cve, template: DeploymentTemplate): string {
    const script = `#!/bin/bash
# Automated deployment script for ${cve.cveId}
# Generated by CVE Lab Hunter - Docker Deployment Service

set -e

echo "🚀 Starting deployment for ${cve.cveId}"
echo "📝 CVE Description: ${cve.description?.substring(0, 100)}..."
echo "⚡ Template: ${template.name}"
echo "⏱️  Estimated setup time: ${template.estimatedSetupTime}"
echo ""

# Check prerequisites
echo "🔍 Checking prerequisites..."
${this.generatePrerequisiteChecks(template)}

# Create deployment directory
DEPLOY_DIR="./cve-${cve.cveId}-lab"
mkdir -p "$DEPLOY_DIR"
cd "$DEPLOY_DIR"

# Generate Docker files
echo "📄 Creating Docker configuration..."
cat > Dockerfile << 'EOF'
${template.dockerfileContent}
EOF

cat > docker-compose.yml << 'EOF'
${template.composeContent}
EOF

# Download PoC if available
${this.generatePocDownloadScript(cve)}

# Build and start containers
echo "🏗️  Building and starting containers..."
docker-compose up -d --build

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Verify deployment
echo "✅ Verifying deployment..."
${this.generateVerificationScript(template)}

echo ""
echo "🎉 Deployment completed successfully!"
echo "🌐 Access the lab environment:"
${this.generateAccessInstructions(template)}
echo ""
echo "📚 Next steps:"
echo "  1. Test the vulnerability using the provided PoC"
echo "  2. Explore the vulnerable environment"
echo "  3. Practice exploitation techniques"
echo "  4. Run './cleanup.sh' when finished"
echo ""
`;

    return script;
  }

  private generateTestingScript(cve: Cve, template: DeploymentTemplate): string {
    return `#!/bin/bash
# Testing script for ${cve.cveId}
# This script helps verify the vulnerability is exploitable

set -e

echo "🧪 Testing ${cve.cveId} vulnerability..."

# Check if environment is running
if ! docker-compose ps | grep -q "Up"; then
    echo "❌ Environment is not running. Please start it first with './deploy.sh'"
    exit 1
fi

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Run basic connectivity tests
${this.generateConnectivityTests(template)}

# Run vulnerability-specific tests
${this.generateVulnerabilityTests(cve, template)}

echo "✅ Testing completed. Check the output above for results."
`;
  }

  private generateCleanupScript(cve: Cve, template: DeploymentTemplate): string {
    return `#!/bin/bash
# Cleanup script for ${cve.cveId}

echo "🧹 Cleaning up ${cve.cveId} lab environment..."

# Stop and remove containers
docker-compose down -v --remove-orphans

# Remove images (optional)
read -p "Remove Docker images? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker-compose down --rmi all -v --remove-orphans
fi

# Clean up files
read -p "Remove lab files? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd ..
    rm -rf "./cve-${cve.cveId}-lab"
    echo "📁 Lab directory removed"
fi

echo "✅ Cleanup completed"
`;
  }

  // Template creation methods
  private createWebAppTemplate(): DeploymentTemplate {
    return {
      id: 'web_app_basic',
      name: 'Basic Web Application',
      category: VulnerabilityCategory.WEB_APPLICATION,
      dockerfileContent: `FROM nginx:alpine
COPY ./app /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]`,
      composeContent: `version: '3.8'
services:
  webapp:
    build: .
    ports:
      - "8080:80"
    environment:
      - ENV=vulnerable
    volumes:
      - ./app:/usr/share/nginx/html:ro`,
      setupInstructions: [
        {
          id: 'setup-1',
          step: 1,
          title: 'Create application directory',
          description: 'Create the web application files',
          command: 'mkdir -p ./app',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.SIMPLE,
      estimatedSetupTime: '5-10 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [8080],
      environment: { ENV: 'vulnerable' },
      volumes: [{ host: './app', container: '/usr/share/nginx/html', type: 'bind', readOnly: true }],
      networkRequirements: [],
      healthCheck: {
        test: ['CMD', 'curl', '-f', 'http://localhost:80'],
        interval: '30s',
        timeout: '10s',
        retries: 3
      },
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'Basic web application template for testing web-based vulnerabilities',
        tags: ['web', 'nginx', 'basic'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createPHPWebAppTemplate(): DeploymentTemplate {
    return {
      id: 'web_app_php',
      name: 'PHP Web Application',
      category: VulnerabilityCategory.WEB_APPLICATION,
      dockerfileContent: `FROM php:8.1-apache
RUN docker-php-ext-install mysqli pdo pdo_mysql
COPY ./app /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80`,
      composeContent: `version: '3.8'
services:
  php-webapp:
    build: .
    ports:
      - "8080:80"
    environment:
      - APACHE_DOCUMENT_ROOT=/var/www/html
    volumes:
      - ./app:/var/www/html
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: vulnerable
      MYSQL_DATABASE: testdb
    ports:
      - "3306:3306"`,
      setupInstructions: [
        {
          id: 'php-setup-1',
          step: 1,
          title: 'Create PHP application',
          description: 'Set up the vulnerable PHP application files',
          command: 'mkdir -p ./app && echo "<?php phpinfo(); ?>" > ./app/index.php',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.MODERATE,
      estimatedSetupTime: '10-15 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [8080, 3306],
      environment: { 
        APACHE_DOCUMENT_ROOT: '/var/www/html',
        MYSQL_ROOT_PASSWORD: 'vulnerable',
        MYSQL_DATABASE: 'testdb'
      },
      volumes: [{ host: './app', container: '/var/www/html', type: 'bind' }],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'PHP web application with MySQL database for testing PHP vulnerabilities',
        tags: ['php', 'apache', 'mysql', 'web'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createNodeJSWebAppTemplate(): DeploymentTemplate {
    return {
      id: 'web_app_nodejs',
      name: 'Node.js Web Application',
      category: VulnerabilityCategory.WEB_APPLICATION,
      dockerfileContent: `FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "start"]`,
      composeContent: `version: '3.8'
services:
  nodejs-webapp:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
    volumes:
      - ./app:/app
      - /app/node_modules`,
      setupInstructions: [
        {
          id: 'node-setup-1',
          step: 1,
          title: 'Create Node.js application',
          description: 'Initialize the Node.js application structure',
          command: 'mkdir -p ./app && cd ./app && npm init -y',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.MODERATE,
      estimatedSetupTime: '10-15 minutes',
      prerequisites: ['Docker', 'Docker Compose', 'Node.js'],
      exposedPorts: [3000],
      environment: { NODE_ENV: 'development' },
      volumes: [
        { host: './app', container: '/app', type: 'bind' },
        { host: '/app/node_modules', container: '/app/node_modules', type: 'volume' }
      ],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'Node.js web application template for testing JavaScript vulnerabilities',
        tags: ['nodejs', 'javascript', 'web', 'express'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createSSHServiceTemplate(): DeploymentTemplate {
    return {
      id: 'network_ssh',
      name: 'SSH Service',
      category: VulnerabilityCategory.NETWORK_SERVICE,
      dockerfileContent: `FROM ubuntu:20.04
RUN apt-get update && apt-get install -y openssh-server sudo
RUN useradd -m -s /bin/bash testuser && echo 'testuser:password' | chpasswd
RUN echo 'testuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN mkdir /var/run/sshd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]`,
      composeContent: `version: '3.8'
services:
  ssh-service:
    build: .
    ports:
      - "2222:22"
    environment:
      - SSH_USERS=testuser:password`,
      setupInstructions: [
        {
          id: 'ssh-setup-1',
          step: 1,
          title: 'Configure SSH keys',
          description: 'Set up SSH configuration for testing',
          command: 'mkdir -p ./ssh-config',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.SIMPLE,
      estimatedSetupTime: '5-10 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [2222],
      environment: { SSH_USERS: 'testuser:password' },
      volumes: [],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'SSH service template for testing SSH-related vulnerabilities',
        tags: ['ssh', 'network', 'service'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createFTPServiceTemplate(): DeploymentTemplate {
    return {
      id: 'network_ftp',
      name: 'FTP Service',
      category: VulnerabilityCategory.NETWORK_SERVICE,
      dockerfileContent: `FROM stilliard/pure-ftpd
ENV PUBLICHOST=localhost
ENV FTP_USER_NAME=ftpuser
ENV FTP_USER_PASS=ftppass
ENV FTP_USER_HOME=/home/ftpuser
EXPOSE 21 30000-30009`,
      composeContent: `version: '3.8'
services:
  ftp-service:
    build: .
    ports:
      - "21:21"
      - "30000-30009:30000-30009"
    environment:
      - PUBLICHOST=localhost
      - FTP_USER_NAME=ftpuser
      - FTP_USER_PASS=ftppass`,
      setupInstructions: [
        {
          id: 'ftp-setup-1',
          step: 1,
          title: 'Create FTP directory',
          description: 'Set up FTP home directory',
          command: 'mkdir -p ./ftp-data',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.SIMPLE,
      estimatedSetupTime: '5-10 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [21],
      environment: {
        PUBLICHOST: 'localhost',
        FTP_USER_NAME: 'ftpuser',
        FTP_USER_PASS: 'ftppass'
      },
      volumes: [{ host: './ftp-data', container: '/home/ftpuser', type: 'bind' }],
      networkRequirements: ['Passive FTP ports 30000-30009'],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'FTP service template for testing FTP-related vulnerabilities',
        tags: ['ftp', 'network', 'service'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createSMTPServiceTemplate(): DeploymentTemplate {
    return {
      id: 'network_smtp',
      name: 'SMTP Service',
      category: VulnerabilityCategory.NETWORK_SERVICE,
      dockerfileContent: `FROM python:3.9-slim
RUN pip install aiosmtpd
EXPOSE 25 587
CMD ["python", "-m", "aiosmtpd", "-n", "-l", "0.0.0.0:25"]`,
      composeContent: `version: '3.8'
services:
  smtp-service:
    build: .
    ports:
      - "25:25"
      - "587:587"
    environment:
      - SMTP_RELAY=false`,
      setupInstructions: [
        {
          id: 'smtp-setup-1',
          step: 1,
          title: 'Configure SMTP',
          description: 'Set up SMTP service configuration',
          command: 'mkdir -p ./smtp-config',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.SIMPLE,
      estimatedSetupTime: '5-10 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [25, 587],
      environment: { SMTP_RELAY: 'false' },
      volumes: [],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'SMTP service template for testing email-related vulnerabilities',
        tags: ['smtp', 'email', 'network', 'service'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createMySQLTemplate(): DeploymentTemplate {
    return {
      id: 'database_mysql',
      name: 'MySQL Database',
      category: VulnerabilityCategory.DATABASE,
      dockerfileContent: `FROM mysql:8.0
COPY ./init.sql /docker-entrypoint-initdb.d/
EXPOSE 3306`,
      composeContent: `version: '3.8'
services:
  mysql-db:
    build: .
    ports:
      - "3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: vulnerable
      MYSQL_DATABASE: testdb
      MYSQL_USER: testuser
      MYSQL_PASSWORD: testpass
    volumes:
      - mysql-data:/var/lib/mysql
volumes:
  mysql-data:`,
      setupInstructions: [
        {
          id: 'mysql-setup-1',
          step: 1,
          title: 'Create database initialization script',
          description: 'Set up initial database schema with vulnerable configurations',
          command: 'echo "CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50));" > ./init.sql',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.SIMPLE,
      estimatedSetupTime: '5-10 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [3306],
      environment: {
        MYSQL_ROOT_PASSWORD: 'vulnerable',
        MYSQL_DATABASE: 'testdb',
        MYSQL_USER: 'testuser',
        MYSQL_PASSWORD: 'testpass'
      },
      volumes: [{ host: 'mysql-data', container: '/var/lib/mysql', type: 'volume' }],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'MySQL database template for testing database vulnerabilities',
        tags: ['mysql', 'database', 'sql'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createPostgreSQLTemplate(): DeploymentTemplate {
    return {
      id: 'database_postgresql',
      name: 'PostgreSQL Database',
      category: VulnerabilityCategory.DATABASE,
      dockerfileContent: `FROM postgres:14
COPY ./init.sql /docker-entrypoint-initdb.d/
EXPOSE 5432`,
      composeContent: `version: '3.8'
services:
  postgresql-db:
    build: .
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: testdb
      POSTGRES_USER: testuser
      POSTGRES_PASSWORD: testpass
    volumes:
      - postgres-data:/var/lib/postgresql/data
volumes:
  postgres-data:`,
      setupInstructions: [
        {
          id: 'postgres-setup-1',
          step: 1,
          title: 'Create database initialization script',
          description: 'Set up initial PostgreSQL schema',
          command: 'echo "CREATE TABLE users (id SERIAL, username VARCHAR(50), password VARCHAR(50));" > ./init.sql',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.SIMPLE,
      estimatedSetupTime: '5-10 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [5432],
      environment: {
        POSTGRES_DB: 'testdb',
        POSTGRES_USER: 'testuser',
        POSTGRES_PASSWORD: 'testpass'
      },
      volumes: [{ host: 'postgres-data', container: '/var/lib/postgresql/data', type: 'volume' }],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'PostgreSQL database template for testing database vulnerabilities',
        tags: ['postgresql', 'database', 'sql'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createMongoDBTemplate(): DeploymentTemplate {
    return {
      id: 'database_mongodb',
      name: 'MongoDB Database',
      category: VulnerabilityCategory.DATABASE,
      dockerfileContent: `FROM mongo:5.0
EXPOSE 27017`,
      composeContent: `version: '3.8'
services:
  mongodb:
    build: .
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: root
      MONGO_INITDB_ROOT_PASSWORD: vulnerable
    volumes:
      - mongo-data:/data/db
volumes:
  mongo-data:`,
      setupInstructions: [
        {
          id: 'mongo-setup-1',
          step: 1,
          title: 'Configure MongoDB',
          description: 'Set up MongoDB with vulnerable configuration',
          command: 'mkdir -p ./mongo-init',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.SIMPLE,
      estimatedSetupTime: '5-10 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [27017],
      environment: {
        MONGO_INITDB_ROOT_USERNAME: 'root',
        MONGO_INITDB_ROOT_PASSWORD: 'vulnerable'
      },
      volumes: [{ host: 'mongo-data', container: '/data/db', type: 'volume' }],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'MongoDB database template for testing NoSQL vulnerabilities',
        tags: ['mongodb', 'database', 'nosql'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createWordPressTemplate(): DeploymentTemplate {
    return {
      id: 'cms_wordpress',
      name: 'WordPress CMS',
      category: VulnerabilityCategory.CMS,
      dockerfileContent: `FROM wordpress:php8.1-apache
COPY ./wp-config.php /var/www/html/
EXPOSE 80`,
      composeContent: `version: '3.8'
services:
  wordpress:
    build: .
    ports:
      - "8080:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - wordpress-data:/var/www/html
    depends_on:
      - db
  db:
    image: mysql:5.7
    environment:
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress
      MYSQL_ROOT_PASSWORD: rootpassword
    volumes:
      - db-data:/var/lib/mysql
volumes:
  wordpress-data:
  db-data:`,
      setupInstructions: [
        {
          id: 'wp-setup-1',
          step: 1,
          title: 'Download WordPress',
          description: 'Download vulnerable WordPress version',
          command: 'curl -O https://wordpress.org/wordpress-5.8.tar.gz',
          type: 'download',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.MODERATE,
      estimatedSetupTime: '15-20 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [8080],
      environment: {
        WORDPRESS_DB_HOST: 'db',
        WORDPRESS_DB_USER: 'wordpress',
        WORDPRESS_DB_PASSWORD: 'wordpress',
        WORDPRESS_DB_NAME: 'wordpress'
      },
      volumes: [
        { host: 'wordpress-data', container: '/var/www/html', type: 'volume' },
        { host: 'db-data', container: '/var/lib/mysql', type: 'volume' }
      ],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'WordPress CMS template for testing WordPress vulnerabilities',
        tags: ['wordpress', 'cms', 'php', 'mysql'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createDrupalTemplate(): DeploymentTemplate {
    return {
      id: 'cms_drupal',
      name: 'Drupal CMS',
      category: VulnerabilityCategory.CMS,
      dockerfileContent: `FROM drupal:9-apache
EXPOSE 80`,
      composeContent: `version: '3.8'
services:
  drupal:
    build: .
    ports:
      - "8080:80"
    environment:
      DRUPAL_DATABASE_HOST: postgres
      DRUPAL_DATABASE_PORT: 5432
      DRUPAL_DATABASE_NAME: drupal
      DRUPAL_DATABASE_USERNAME: drupal
      DRUPAL_DATABASE_PASSWORD: drupal
    volumes:
      - drupal-data:/var/www/html
    depends_on:
      - postgres
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: drupal
      POSTGRES_USER: drupal
      POSTGRES_PASSWORD: drupal
    volumes:
      - postgres-data:/var/lib/postgresql/data
volumes:
  drupal-data:
  postgres-data:`,
      setupInstructions: [
        {
          id: 'drupal-setup-1',
          step: 1,
          title: 'Configure Drupal',
          description: 'Set up Drupal with vulnerable configuration',
          command: 'mkdir -p ./drupal-config',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.MODERATE,
      estimatedSetupTime: '15-20 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [8080],
      environment: {
        DRUPAL_DATABASE_HOST: 'postgres',
        DRUPAL_DATABASE_PORT: '5432',
        DRUPAL_DATABASE_NAME: 'drupal',
        DRUPAL_DATABASE_USERNAME: 'drupal',
        DRUPAL_DATABASE_PASSWORD: 'drupal'
      },
      volumes: [
        { host: 'drupal-data', container: '/var/www/html', type: 'volume' },
        { host: 'postgres-data', container: '/var/lib/postgresql/data', type: 'volume' }
      ],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'Drupal CMS template for testing Drupal vulnerabilities',
        tags: ['drupal', 'cms', 'php', 'postgresql'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createJoomlaTemplate(): DeploymentTemplate {
    return {
      id: 'cms_joomla',
      name: 'Joomla CMS',
      category: VulnerabilityCategory.CMS,
      dockerfileContent: `FROM joomla:php8.1-apache
EXPOSE 80`,
      composeContent: `version: '3.8'
services:
  joomla:
    build: .
    ports:
      - "8080:80"
    environment:
      JOOMLA_DB_HOST: mysql
      JOOMLA_DB_USER: joomla
      JOOMLA_DB_PASSWORD: joomla
      JOOMLA_DB_NAME: joomla
    volumes:
      - joomla-data:/var/www/html
    depends_on:
      - mysql
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: joomla
      MYSQL_USER: joomla
      MYSQL_PASSWORD: joomla
      MYSQL_ROOT_PASSWORD: rootpassword
    volumes:
      - mysql-data:/var/lib/mysql
volumes:
  joomla-data:
  mysql-data:`,
      setupInstructions: [
        {
          id: 'joomla-setup-1',
          step: 1,
          title: 'Configure Joomla',
          description: 'Set up Joomla with vulnerable configuration',
          command: 'mkdir -p ./joomla-config',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.MODERATE,
      estimatedSetupTime: '15-20 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [8080],
      environment: {
        JOOMLA_DB_HOST: 'mysql',
        JOOMLA_DB_USER: 'joomla',
        JOOMLA_DB_PASSWORD: 'joomla',
        JOOMLA_DB_NAME: 'joomla'
      },
      volumes: [
        { host: 'joomla-data', container: '/var/www/html', type: 'volume' },
        { host: 'mysql-data', container: '/var/lib/mysql', type: 'volume' }
      ],
      networkRequirements: [],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'Joomla CMS template for testing Joomla vulnerabilities',
        tags: ['joomla', 'cms', 'php', 'mysql'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createDockerSecurityTemplate(): DeploymentTemplate {
    return {
      id: 'container_docker',
      name: 'Docker Security Test',
      category: VulnerabilityCategory.CONTAINER,
      dockerfileContent: `FROM ubuntu:20.04
RUN apt-get update && apt-get install -y curl
USER root
EXPOSE 8080`,
      composeContent: `version: '3.8'
services:
  docker-test:
    build: .
    ports:
      - "8080:8080"
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock`,
      setupInstructions: [
        {
          id: 'docker-setup-1',
          step: 1,
          title: 'Configure Docker security test',
          description: 'Set up Docker security testing environment',
          command: 'mkdir -p ./docker-test',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.COMPLEX,
      estimatedSetupTime: '20-30 minutes',
      prerequisites: ['Docker', 'Docker Compose'],
      exposedPorts: [8080],
      environment: {},
      volumes: [{ host: '/var/run/docker.sock', container: '/var/run/docker.sock', type: 'bind' }],
      networkRequirements: ['Docker socket access'],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'Docker security testing template for container vulnerabilities',
        tags: ['docker', 'container', 'security'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  private createKubernetesTemplate(): DeploymentTemplate {
    return {
      id: 'container_kubernetes',
      name: 'Kubernetes Security Test',
      category: VulnerabilityCategory.CONTAINER,
      dockerfileContent: `FROM ubuntu:20.04
RUN apt-get update && apt-get install -y curl kubectl
EXPOSE 8080`,
      composeContent: `version: '3.8'
services:
  k8s-test:
    build: .
    ports:
      - "8080:8080"
    environment:
      - KUBECONFIG=/kubeconfig
    volumes:
      - ./kubeconfig:/kubeconfig`,
      setupInstructions: [
        {
          id: 'k8s-setup-1',
          step: 1,
          title: 'Configure Kubernetes test',
          description: 'Set up Kubernetes security testing environment',
          command: 'mkdir -p ./k8s-test',
          type: 'command',
          optional: false
        }
      ],
      complexity: DeploymentComplexity.COMPLEX,
      estimatedSetupTime: '30-45 minutes',
      prerequisites: ['Docker', 'Docker Compose', 'Kubernetes'],
      exposedPorts: [8080],
      environment: { KUBECONFIG: '/kubeconfig' },
      volumes: [{ host: './kubeconfig', container: '/kubeconfig', type: 'bind' }],
      networkRequirements: ['Kubernetes cluster access'],
      metadata: {
        author: 'CVE Lab Hunter',
        description: 'Kubernetes security testing template for K8s vulnerabilities',
        tags: ['kubernetes', 'container', 'security'],
        lastUpdated: new Date(),
        version: '1.0.0',
        compatibility: {
          os: ['linux', 'windows', 'macos'],
          dockerVersion: '>=20.10',
          composeVersion: '>=1.29'
        }
      }
    };
  }

  // Helper methods for script generation
  private generatePrerequisiteChecks(template: DeploymentTemplate): string {
    return template.prerequisites.map(prereq => {
      switch (prereq.toLowerCase()) {
        case 'docker':
          return 'command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed."; exit 1; }';
        case 'docker compose':
          return 'command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed."; exit 1; }';
        case 'node.js':
          return 'command -v node >/dev/null 2>&1 || { echo "Node.js is required but not installed."; exit 1; }';
        default:
          return `echo "Checking for ${prereq}..."`;
      }
    }).join('\n');
  }

  private generatePocDownloadScript(cve: Cve): string {
    if (!cve.pocUrls || cve.pocUrls.length === 0) {
      return 'echo "No PoC URLs available"';
    }

    return `if [ ! -d "./poc" ]; then
    echo "📥 Downloading PoC..."
    git clone ${cve.pocUrls[0]} ./poc || curl -L -o poc.zip ${cve.pocUrls[0]}
fi`;
  }

  private generateVerificationScript(template: DeploymentTemplate): string {
    const checks = template.exposedPorts.map(port => 
      `curl -f http://localhost:${port} >/dev/null 2>&1 && echo "✅ Port ${port} is accessible" || echo "❌ Port ${port} is not accessible"`
    ).join('\n');

    return checks || 'echo "No verification checks configured"';
  }

  private generateAccessInstructions(template: DeploymentTemplate): string {
    return template.exposedPorts.map(port => 
      `echo "  http://localhost:${port}"`
    ).join('\n') || 'echo "  No web interfaces exposed"';
  }

  private generateConnectivityTests(template: DeploymentTemplate): string {
    return template.exposedPorts.map(port => 
      `nc -z localhost ${port} && echo "✅ Port ${port} is open" || echo "❌ Port ${port} is closed"`
    ).join('\n');
  }

  private generateVulnerabilityTests(cve: Cve, template: DeploymentTemplate): string {
    return `echo "🔍 Running vulnerability-specific tests for ${cve.cveId}..."
# Add CVE-specific test commands here
echo "💡 Manual testing required - check the PoC documentation"`;
  }

  private generateTestCommand(cve: Cve, template: DeploymentTemplate): string {
    const primaryPort = template.exposedPorts[0] || 80;
    return `curl -v http://localhost:${primaryPort} || echo "Test command placeholder for ${cve.cveId}"`;
  }

  private estimateDeploymentTime(template: DeploymentTemplate): string {
    return template.estimatedSetupTime;
  }

  private calculateMemoryRequirement(template: DeploymentTemplate): string {
    switch (template.complexity) {
      case DeploymentComplexity.SIMPLE: return '512MB';
      case DeploymentComplexity.MODERATE: return '1GB';
      case DeploymentComplexity.COMPLEX: return '2GB';
      default: return '1GB';
    }
  }

  private calculateCPURequirement(template: DeploymentTemplate): string {
    switch (template.complexity) {
      case DeploymentComplexity.SIMPLE: return '0.5 CPU';
      case DeploymentComplexity.MODERATE: return '1 CPU';
      case DeploymentComplexity.COMPLEX: return '2 CPU';
      default: return '1 CPU';
    }
  }

  private calculateStorageRequirement(template: DeploymentTemplate): string {
    switch (template.complexity) {
      case DeploymentComplexity.SIMPLE: return '1GB';
      case DeploymentComplexity.MODERATE: return '5GB';
      case DeploymentComplexity.COMPLEX: return '10GB';
      default: return '5GB';
    }
  }

  private identifyDeploymentChallenges(cve: Cve, discoveryResults: any): string[] {
    const challenges: string[] = [];

    if (!cve.pocUrls || cve.pocUrls.length === 0) {
      challenges.push('No public proof-of-concept available');
    }

    if (cve.cvssScore && cve.cvssScore >= 9.0) {
      challenges.push('High severity vulnerability requires careful handling');
    }

    if (cve.category === 'Network Security') {
      challenges.push('Network security vulnerabilities may require special network configuration');
    }

    if (!discoveryResults.dockerInfo || discoveryResults.dockerInfo.length === 0) {
      challenges.push('No existing Docker configurations found in community resources');
    }

    return challenges;
  }

  private generateMitigationSuggestions(challenges: string[], cve: Cve): string[] {
    const suggestions: string[] = [];

    challenges.forEach(challenge => {
      if (challenge.includes('proof-of-concept')) {
        suggestions.push('Check alternative security research sources for exploitation examples');
      }
      if (challenge.includes('severity')) {
        suggestions.push('Use isolated test environment and restrict network access');
      }
      if (challenge.includes('network configuration')) {
        suggestions.push('Consider using Docker network isolation and custom bridge networks');
      }
      if (challenge.includes('Docker configurations')) {
        suggestions.push('Create custom Docker configuration based on vulnerability requirements');
      }
    });

    return suggestions;
  }

  private generateCustomConfiguration(cve: Cve, discoveryResults: any): any {
    return {
      cveSpecific: {
        targetVersion: cve.affectedVersions?.[0] || 'latest vulnerable',
        attackVector: cve.attackVector,
        cvssScore: cve.cvssScore
      },
      communityResources: {
        availableSources: discoveryResults.sourceBreakdown || {},
        dockerHubImages: discoveryResults.sources?.filter((s: any) => s.type === 'dockerhub').length || 0,
        githubRepos: discoveryResults.sources?.filter((s: any) => s.type === 'github').length || 0
      },
      recommendations: {
        useIsolatedNetwork: true,
        enableLogging: true,
        restrictOutboundAccess: cve.cvssScore ? cve.cvssScore >= 8.0 : false
      }
    };
  }

  // Public API methods
  async getAvailableTemplates(): Promise<DeploymentTemplate[]> {
    return Array.from(this.templates.values());
  }

  async getTemplate(templateId: string): Promise<DeploymentTemplate | null> {
    return this.templates.get(templateId) || null;
  }

  async getTemplatesForCategory(category: VulnerabilityCategory): Promise<DeploymentTemplate[]> {
    return Array.from(this.templates.values()).filter(t => t.category === category);
  }

  async generateDeploymentPackage(cve: Cve): Promise<{
    deployment: AutomatedDeployment | null;
    analysis: DeploymentAnalysis;
  }> {
    const analysis = await this.analyzeDeploymentPossibilities(cve);
    const deployment = await this.generateAutomatedDeployment(cve);

    return { deployment, analysis };
  }
}

// Export singleton instance
export const dockerDeploymentService = new DockerDeploymentService();