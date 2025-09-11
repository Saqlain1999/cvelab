import { Bug, Server, Code, AlertTriangle, Clock, CheckCircle, Star, Plus } from "lucide-react";
import type { Cve } from "@/types/cve";

interface StatsGridProps {
  cves: Cve[];
  isLoading?: boolean;
}

export function StatsGrid({ cves = [], isLoading }: StatsGridProps) {
  // Calculate stats from the current filtered CVE data
  const stats = {
    totalCves: cves.length,
    deployable: cves.filter(cve => cve.isDockerDeployable).length,
    withPoc: cves.filter(cve => cve.hasPublicPoc).length,
    critical: cves.filter(cve => cve.severity === 'CRITICAL').length,
    // Status statistics
    newCount: cves.filter(cve => cve.status === 'new').length,
    inProgressCount: cves.filter(cve => cve.status === 'in_progress').length,
    doneCount: cves.filter(cve => cve.status === 'done').length,
    priorityCount: cves.filter(cve => cve.isPriority).length,
  };

  const statCards = [
    // Core CVE Stats
    {
      title: "Total CVEs Found",
      value: stats?.totalCves || 0,
      icon: Bug,
      change: stats?.newCount > 0 ? `${stats.newCount} new` : "No new CVEs",
      changeLabel: "in this view",
      color: "text-primary",
      bgColor: "bg-primary/10",
      category: "overview"
    },
    {
      title: "Critical Severity",
      value: stats?.critical || 0,
      icon: AlertTriangle,
      change: stats?.critical > 0 ? "High Priority" : "No critical CVEs",
      changeLabel: "immediate attention",
      color: "text-red-400",
      bgColor: "bg-red-500/10",
      category: "overview"
    },
    {
      title: "Lab Deployable",
      value: stats?.deployable || 0,
      icon: Server,
      change: `${Math.round(((stats?.deployable || 0) / (stats?.totalCves || 1)) * 100)}%`,
      changeLabel: "deployment ready",
      color: "text-accent",
      bgColor: "bg-accent/10",
      category: "overview"
    },
    {
      title: "With Public PoC",
      value: stats?.withPoc || 0,
      icon: Code,
      change: `${Math.round(((stats?.withPoc || 0) / (stats?.totalCves || 1)) * 100)}%`,
      changeLabel: "exploits available",
      color: "text-orange-400",
      bgColor: "bg-orange-500/10",
      category: "overview"
    },
    // Status Management Stats
    {
      title: "New CVEs",
      value: stats?.newCount || 0,
      icon: Plus,
      change: "Needs Review",
      changeLabel: "awaiting triage",
      color: "text-blue-400",
      bgColor: "bg-blue-500/10",
      category: "status"
    },
    {
      title: "In Progress",
      value: stats?.inProgressCount || 0,
      icon: Clock,
      change: "Active Work",
      changeLabel: "being investigated",
      color: "text-yellow-400",
      bgColor: "bg-yellow-500/10",
      category: "status"
    },
    {
      title: "Completed",
      value: stats?.doneCount || 0,
      icon: CheckCircle,
      change: "Finished",
      changeLabel: "analysis complete",
      color: "text-green-400",
      bgColor: "bg-green-500/10",
      category: "status"
    },
    {
      title: "Priority CVEs",
      value: stats?.priorityCount || 0,
      icon: Star,
      change: "Flagged",
      changeLabel: "high interest",
      color: "text-yellow-500",
      bgColor: "bg-yellow-500/10",
      category: "status"
    },
  ];

  if (isLoading) {
    return (
      <div className="space-y-6 mb-8">
        {/* Loading skeleton for overview cards */}
        <div>
          <h3 className="text-lg font-semibold mb-4">CVE Overview</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="bg-card p-6 rounded-lg border border-border animate-pulse">
                <div className="h-16 bg-muted rounded"></div>
              </div>
            ))}
          </div>
        </div>
        {/* Loading skeleton for status cards */}
        <div>
          <h3 className="text-lg font-semibold mb-4">Status Breakdown</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="bg-card p-6 rounded-lg border border-border animate-pulse">
                <div className="h-16 bg-muted rounded"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const overviewCards = statCards.filter(card => card.category === 'overview');
  const statusCards = statCards.filter(card => card.category === 'status');

  return (
    <div className="space-y-6 mb-8" data-testid="stats-grid">
      {/* CVE Overview Section */}
      <div>
        <h3 className="text-lg font-semibold mb-4">CVE Overview</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {overviewCards.map((stat, index) => (
            <div key={index} className="bg-card p-6 rounded-lg border border-border" data-testid={`stat-card-${stat.title.toLowerCase().replace(/\s+/g, '-')}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{stat.title}</p>
                  <p className="text-3xl font-bold text-foreground" data-testid={`stat-value-${index}`}>
                    {stat.value.toLocaleString()}
                  </p>
                </div>
                <div className={`p-3 ${stat.bgColor} rounded-lg`}>
                  <stat.icon className={`text-2xl ${stat.color}`} />
                </div>
              </div>
              <div className="mt-4 flex items-center text-sm">
                <span className={`${stat.color}`}>{stat.change}</span>
                <span className="text-muted-foreground ml-1">{stat.changeLabel}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Status Breakdown Section */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Status Breakdown</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {statusCards.map((stat, index) => (
            <div key={`status-${index}`} className="bg-card p-6 rounded-lg border border-border" data-testid={`status-card-${stat.title.toLowerCase().replace(/\s+/g, '-')}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{stat.title}</p>
                  <p className="text-3xl font-bold text-foreground" data-testid={`status-value-${index}`}>
                    {stat.value.toLocaleString()}
                  </p>
                </div>
                <div className={`p-3 ${stat.bgColor} rounded-lg`}>
                  <stat.icon className={`text-2xl ${stat.color}`} />
                </div>
              </div>
              <div className="mt-4 flex items-center text-sm">
                <span className={`${stat.color}`}>{stat.change}</span>
                <span className="text-muted-foreground ml-1">{stat.changeLabel}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
