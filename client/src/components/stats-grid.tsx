import { Bug, Server, Code, AlertTriangle } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import type { CveStats } from "@/types/cve";

export function StatsGrid() {
  const { data: stats, isLoading } = useQuery<CveStats>({
    queryKey: ["/api/stats"],
  });

  const statCards = [
    {
      title: "Total CVEs Found",
      value: stats?.totalCves || 0,
      icon: Bug,
      change: "+12%",
      changeLabel: "from last scan",
      color: "text-primary",
      bgColor: "bg-primary/10",
    },
    {
      title: "Lab Deployable",
      value: stats?.deployable || 0,
      icon: Server,
      change: "+8%",
      changeLabel: "docker ready",
      color: "text-accent",
      bgColor: "bg-accent/10",
    },
    {
      title: "With Public PoC",
      value: stats?.withPoc || 0,
      icon: Code,
      change: "Active",
      changeLabel: "exploits found",
      color: "text-orange-400",
      bgColor: "bg-orange-500/10",
    },
    {
      title: "Critical Severity",
      value: stats?.critical || 0,
      icon: AlertTriangle,
      change: "High Priority",
      changeLabel: "immediate action",
      color: "text-red-400",
      bgColor: "bg-red-500/10",
    },
  ];

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-card p-6 rounded-lg border border-border animate-pulse">
            <div className="h-16 bg-muted rounded"></div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8" data-testid="stats-grid">
      {statCards.map((stat, index) => (
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
  );
}
