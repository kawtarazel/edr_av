import { useState, useEffect } from 'react';
import { BarChart, Bar, PieChart, Pie, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import Papa from 'papaparse';

interface CountObject {
  [key: string]: number;
}

// Déclaration des types pour window.fs
declare global {
  interface Window {
    fs: {
      readFile: (path: string, options?: { encoding?: string }) => Promise<any>;
    }
  }
}

// Interface pour les KPIs EDR
interface EdrKpis {
  totalAlerts: number;
  criticalRate: number;
  iocDetectionRate: number;
  severityData: { name: string; value: number; percentage: number }[];
  alertTypeData: { name: string; value: number; percentage: number }[];
  suspiciousConnectionRate: number;
  uniqueEndpoints: number;
  statusData: { name: string; value: number; percentage: number }[];
}

// Interface pour les KPIs de vulnérabilités
interface VulnKpis {
  totalVulnerabilities: number;
  severityData: { name: string; value: number; percentage: number }[];
  statusData: { name: string; value: number; percentage: number }[];
  sourceData: { name: string; value: number; percentage: number }[];
  remediationRate: number;
  avgRemediationTime: number;
  criticalVulnerabilityRate: number;
  patchesInTimeRate: number;
}

// Add type definition for severity colors
type SeverityColorMap = {
  [key: string]: string;
  Critical: string;
  High: string;
  Medium: string;
  Low: string;
  Critique: string;
  Majeure: string;
  Mineure: string;
};

const SEVERITY_COLORS: SeverityColorMap = {
  'Critical': '#d9534f',
  'High': '#f0ad4e',
  'Medium': '#5bc0de',
  'Low': '#5cb85c',
  'Critique': '#d9534f',
  'Majeure': '#f0ad4e',
  'Mineure': '#5cb85c'
};

const DashboardVisualization: React.FC = () => {
  // Interface pour les données EDR
  interface EdrDataType {
    Severity: string;
    IOCType: string;
    AlertType: string;
    Status: string;
    Hostname: string;
    [key: string]: any;
  }
  
  // Interface pour les données de vulnérabilité
  interface VulnDataType {
    Severity: string;
    Status: string;
    DetectionSource: string;
    DetectionDate: string;
    PatchAppliedDate: string;
    IsCritical: string;
    IsPatchable: string;
    AssetID: string;
    RecommendedTimeframe: number;
    [key: string]: any;
  }
  
  // État pour stocker les données des fichiers CSV
  const [, setEdrData] = useState<EdrDataType[]>([]);
  const [, setVulnData] = useState<VulnDataType[]>([]);
  
  // État pour stocker les KPIs calculés
  const [edrKpis, setEdrKpis] = useState<EdrKpis>({
    totalAlerts: 0,
    criticalRate: 0,
    iocDetectionRate: 0,
    severityData: [],
    alertTypeData: [],
    suspiciousConnectionRate: 0,
    uniqueEndpoints: 0,
    statusData: []
  });
  
  const [vulnKpis, setVulnKpis] = useState<VulnKpis>({
    totalVulnerabilities: 0,
    severityData: [],
    statusData: [],
    sourceData: [],
    remediationRate: 0,
    avgRemediationTime: 0,
    criticalVulnerabilityRate: 0,
    patchesInTimeRate: 0
  });

  // État pour le chargement
  const [loading, setLoading] = useState(true);

  // Couleurs pour les graphiques
  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8', '#82ca9d', '#ffc658', '#8dd1e1'];

  useEffect(() => {
    // Fonction pour charger les données CSV
    const loadData = async () => {
      try {
        // Charger les données EDR
        const edrResponse = await fetch('/public/edr_data.csv');
        const edrText = await edrResponse.text();
        const edrResult = Papa.parse<EdrDataType>(edrText, { 
          header: true, 
          skipEmptyLines: true,
          dynamicTyping: true 
        });
        
        // Charger les données de vulnérabilités
        const vulnResponse = await fetch('/public/vulnerabilities_data.csv');
        const vulnText = await vulnResponse.text();
        const vulnResult = Papa.parse<VulnDataType>(vulnText, { 
          header: true, 
          skipEmptyLines: true,
          dynamicTyping: true 
        });
        
        setEdrData(edrResult.data as EdrDataType[]);
        setVulnData(vulnResult.data as VulnDataType[]);
        
        // Calculer les KPIs une fois les données chargées
        calculateEdrKpis(edrResult.data);
        calculateVulnKpis(vulnResult.data);
        
        setLoading(false);
      } catch (error) {
        console.error("Erreur lors du chargement des données:", error);
        setLoading(false);
      }
    };
    
    loadData();
  }, []);

  // Fonction pour calculer les KPIs EDR
  const calculateEdrKpis = (data: EdrDataType[]) => {
    // Nombre total d'alertes
    const totalAlerts = data.length;
    
    // Taux d'alertes critiques
    const criticalAlerts = data.filter(alert => alert.Severity === "Critical").length;
    const criticalRate = (criticalAlerts / totalAlerts) * 100;
    
    // Taux de détection des IoCs
    const alertsWithIoC = data.filter(alert => alert.IOCType && alert.IOCType !== "None" && alert.IOCType !== "").length;
    const iocDetectionRate = (alertsWithIoC / totalAlerts) * 100;
    
    // Répartition des sévérités
    const severityCounts = calculateSeverityCounts(data);
    
    // Convertir les comptes en tableaux pour les graphiques
    const severityData = Object.keys(severityCounts).map(key => ({
      name: key,
      value: severityCounts[key],
      percentage: (severityCounts[key] / totalAlerts) * 100
    }));
    
    // Type d'alertes
    const alertTypeCounts = calculateAlertTypeCounts(data);
    
    const alertTypeData = Object.keys(alertTypeCounts).map(key => ({
      name: key,
      value: alertTypeCounts[key],
      percentage: (alertTypeCounts[key] / totalAlerts) * 100
    }));
    
    // Taux de connexions suspectes
    const networkConnections = data.filter(alert => alert.AlertType === "Network Connection").length;
    const suspiciousConnections = data.filter(alert => 
      alert.AlertType === "Network Connection" && 
      (alert.Severity === "Critical" || alert.Severity === "High")
    ).length;
    const suspiciousConnectionRate = networkConnections ? (suspiciousConnections / networkConnections) * 100 : 0;
    
    // Endpoints uniques
    const uniqueEndpoints = [...new Set(data.map(alert => alert.Hostname))];
    
    // Statut des alertes
    const statusCounts = calculateStatusCounts(data);
    
    const statusData = Object.keys(statusCounts).map(key => ({
      name: key,
      value: statusCounts[key],
      percentage: (statusCounts[key] / totalAlerts) * 100
    }));
    
    setEdrKpis({
      totalAlerts,
      criticalRate,
      iocDetectionRate,
      severityData,
      alertTypeData,
      suspiciousConnectionRate,
      uniqueEndpoints: uniqueEndpoints.length,
      statusData
    });
  };

  // Fonction pour calculer les KPIs de vulnérabilité
  const calculateVulnKpis = (data: VulnDataType[]) => {
    // Nombre total de vulnérabilités
    const totalVulnerabilities = data.length;
    
    // Répartition par sévérité
    const severityCounts = calculateVulnSeverityCounts(data);
    
    const severityData = Object.keys(severityCounts).map(key => ({
      name: key,
      value: severityCounts[key],
      percentage: (severityCounts[key] / totalVulnerabilities) * 100
    }));
    
    // Statut des vulnérabilités
    const statusCounts = calculateVulnStatusCounts(data);
    
    const statusData = Object.keys(statusCounts).map(key => ({
      name: key,
      value: statusCounts[key],
      percentage: (statusCounts[key] / totalVulnerabilities) * 100
    }));
    
    // Répartition par source de détection
    const sourceCounts = calculateSourceCounts(data);
    
    const sourceData = Object.keys(sourceCounts).map(key => ({
      name: key,
      value: sourceCounts[key],
      percentage: (sourceCounts[key] / totalVulnerabilities) * 100
    }));
    
    // Taux de correction
    const resolvedVulnerabilities = data.filter(vuln => vuln.Status === "Resolved").length;
    const remediationRate = (resolvedVulnerabilities / totalVulnerabilities) * 100;
    
    // Temps moyen de correction (en jours)
    const resolvedVulns = data.filter(vuln => vuln.Status === "Resolved" && vuln.PatchAppliedDate && vuln.DetectionDate);
    let totalRemediationTime = 0;
    
    resolvedVulns.forEach(vuln => {
      const detectionDate = new Date(vuln.DetectionDate);
      const patchDate = new Date(vuln.PatchAppliedDate);
      const timeDiff = patchDate.getTime() - detectionDate.getTime();
      const daysDiff = timeDiff / (1000 * 60 * 60 * 24);
      totalRemediationTime += daysDiff;
    });
    
    const avgRemediationTime = resolvedVulns.length > 0 ? totalRemediationTime / resolvedVulns.length : 0;
    
    // Assets critiques non patchables
    const criticalAssets = [...new Set(data.filter(vuln => vuln.IsCritical === "Oui").map(vuln => vuln.AssetID))];
    const unpatchableCriticalAssets = [...new Set(data.filter(vuln => 
      vuln.IsCritical === "Oui" && vuln.IsPatchable === "Non"
    ).map(vuln => vuln.AssetID))];
    
    const criticalVulnerabilityRate = criticalAssets.length > 0 ? 
      (unpatchableCriticalAssets.length / criticalAssets.length) * 100 : 0;
    
    // Correctifs appliqués dans les délais
    let patchesInTime = 0;
    resolvedVulns.forEach(vuln => {
      const detectionDate = new Date(vuln.DetectionDate);
      const patchDate = new Date(vuln.PatchAppliedDate);
      const actualDays = (patchDate.getTime() - detectionDate.getTime()) / (1000 * 60 * 60 * 24);
      const recommendedDays = vuln.RecommendedTimeframe || Infinity;
      
      if (actualDays <= recommendedDays) {
        patchesInTime++;
      }
    });
    
    const patchesInTimeRate = resolvedVulns.length > 0 ? 
      (patchesInTime / resolvedVulns.length) * 100 : 0;
    
    setVulnKpis({
      totalVulnerabilities,
      severityData,
      statusData,
      sourceData,
      remediationRate,
      avgRemediationTime,
      criticalVulnerabilityRate,
      patchesInTimeRate
    });
  };

  // Helper functions for EDR KPIs
  const calculateSeverityCounts = (data: EdrDataType[]): CountObject => {
    return data.reduce((acc: CountObject, alert) => {
      acc[alert.Severity] = (acc[alert.Severity] || 0) + 1;
      return acc;
    }, {});
  };

  const calculateAlertTypeCounts = (data: EdrDataType[]): CountObject => {
    return data.reduce((acc: CountObject, alert) => {
      acc[alert.AlertType] = (acc[alert.AlertType] || 0) + 1;
      return acc;
    }, {});
  };

  const calculateStatusCounts = (data: EdrDataType[]): CountObject => {
    return data.reduce((acc: CountObject, alert) => {
      acc[alert.Status] = (acc[alert.Status] || 0) + 1;
      return acc;
    }, {});
  };

  // Helper functions for Vulnerability KPIs
  const calculateVulnSeverityCounts = (data: VulnDataType[]): CountObject => {
    return data.reduce((acc: CountObject, vuln) => {
      acc[vuln.Severity] = (acc[vuln.Severity] || 0) + 1;
      return acc;
    }, {});
  };

  const calculateVulnStatusCounts = (data: VulnDataType[]): CountObject => {
    return data.reduce((acc: CountObject, vuln) => {
      acc[vuln.Status] = (acc[vuln.Status] || 0) + 1;
      return acc;
    }, {});
  };

  const calculateSourceCounts = (data: VulnDataType[]): CountObject => {
    return data.reduce((acc: CountObject, vuln) => {
      acc[vuln.DetectionSource] = (acc[vuln.DetectionSource] || 0) + 1;
      return acc;
    }, {});
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
        <div className="p-8 bg-white rounded-lg shadow-xl">
          <div className="flex items-center space-x-4">
            <div className="w-12 h-12 border-t-4 border-blue-500 rounded-full animate-spin"></div>
            <div className="text-xl font-semibold text-gray-700">Chargement des données...</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 py-8 px-4">
      <div className="max-w-7xl mx-auto space-y-8">
        <header className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-800 mb-4">Dashboard des KPIs Cybersécurité</h1>
          <p className="text-gray-600">Vue d'ensemble de la sécurité et des vulnérabilités</p>
        </header>
        
        {/* Section EDR */}
        <section className="bg-white rounded-2xl shadow-xl p-8 hover:shadow-2xl transition-shadow duration-300">
          <h2 className="text-3xl font-bold text-gray-800 mb-8 pb-4 border-b border-gray-200">
            <span className="text-blue-600">EDR</span> - Endpoint Detection & Response
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
            {/* KPI Cards */}
            <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6 shadow-lg transform hover:scale-105 transition-transform duration-300">
              <h3 className="text-lg font-semibold text-blue-800 mb-2">Taux d'alertes critiques</h3>
              <p className="text-4xl font-bold text-blue-600 mb-2">{edrKpis.criticalRate?.toFixed(1)}%</p>
              <p className="text-sm text-blue-600/80">Sur {edrKpis.totalAlerts} alertes au total</p>
            </div>
            
            <div className="bg-gradient-to-br from-green-50 to-green-100 rounded-xl p-6 shadow-lg transform hover:scale-105 transition-transform duration-300">
              <h3 className="text-lg font-semibold text-green-800 mb-2">Taux de détection des IoCs</h3>
              <p className="text-4xl font-bold text-green-600 mb-2">{edrKpis.iocDetectionRate?.toFixed(1)}%</p>
              <p className="text-sm text-green-600/80">Alertes avec indicateurs de compromission</p>
            </div>
            
            <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl p-6 shadow-lg transform hover:scale-105 transition-transform duration-300">
              <h3 className="text-lg font-semibold text-purple-800 mb-2">Taux de connexions suspectes</h3>
              <p className="text-4xl font-bold text-purple-600 mb-2">{edrKpis.suspiciousConnectionRate?.toFixed(1)}%</p>
              <p className="text-sm text-purple-600/80">Connexions réseau suspectes</p>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Charts avec style amélioré */}
            <div className="bg-white rounded-xl p-6 shadow-lg border border-gray-100 hover:shadow-xl transition-shadow duration-300">
              <h3 className="text-xl font-semibold text-gray-800 mb-6">Répartition par sévérité</h3>
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={edrKpis.severityData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      nameKey="name"
                      label={({ name, percentage }) => `${name}: ${percentage.toFixed(1)}%`}
                    >
                      {edrKpis.severityData?.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value, name, props) => [`${value} alertes (${props.payload.percentage.toFixed(1)}%)`, name]} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="bg-white rounded-xl p-6 shadow-lg border border-gray-100 hover:shadow-xl transition-shadow duration-300">
              <h3 className="text-xl font-semibold text-gray-800 mb-6">Types d'alertes</h3>
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={edrKpis.alertTypeData?.slice(0, 6)} // Prendre les 6 premiers pour la lisibilité
                    layout="vertical"
                    margin={{ top: 5, right: 30, left: 100, bottom: 5 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis type="number" />
                    <YAxis dataKey="name" type="category" width={100} />
                    <Tooltip formatter={(value) => [`${value} alertes`, '']} />
                    <Bar dataKey="value" fill="#8884d8">
                      {edrKpis.alertTypeData?.slice(0, 6).map((_, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </section>
        
        {/* Section Vulnérabilités */}
        <section className="bg-white rounded-2xl shadow-xl p-8 hover:shadow-2xl transition-shadow duration-300">
          <h2 className="text-3xl font-bold text-gray-800 mb-8 pb-4 border-b border-gray-200">
            <span className="text-red-600">Vulnérabilités</span> - Gestion et Suivi
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12">
            {/* KPI Cards */}
            <div className="bg-gradient-to-br from-red-50 to-red-100 rounded-xl p-6 shadow-lg transform hover:scale-105 transition-transform duration-300">
              <h3 className="text-lg font-semibold text-red-800 mb-2">Vulnérabilités critiques</h3>
              <p className="text-4xl font-bold text-red-600 mb-2">{vulnKpis.criticalVulnerabilityRate?.toFixed(1)}%</p>
              <p className="text-sm text-red-600/80">Des assets critiques</p>
            </div>
            
            <div className="bg-gradient-to-br from-amber-50 to-amber-100 rounded-xl p-6 shadow-lg transform hover:scale-105 transition-transform duration-300">
              <h3 className="text-lg font-semibold text-amber-800 mb-2">Taux de correction</h3>
              <p className="text-4xl font-bold text-amber-600 mb-2">{vulnKpis.remediationRate?.toFixed(1)}%</p>
              <p className="text-sm text-amber-600/80">Vulnérabilités corrigées</p>
            </div>
            
            <div className="bg-gradient-to-br from-emerald-50 to-emerald-100 rounded-xl p-6 shadow-lg transform hover:scale-105 transition-transform duration-300">
              <h3 className="text-lg font-semibold text-emerald-800 mb-2">Temps de correction</h3>
              <p className="text-4xl font-bold text-emerald-600 mb-2">{vulnKpis.avgRemediationTime?.toFixed(0)} j</p>
              <p className="text-sm text-emerald-600/80">Moyenne de résolution</p>
            </div>
            
            <div className="bg-gradient-to-br from-teal-50 to-teal-100 rounded-xl p-6 shadow-lg transform hover:scale-105 transition-transform duration-300">
              <h3 className="text-lg font-semibold text-teal-800 mb-2">Correctifs dans les délais</h3>
              <p className="text-4xl font-bold text-teal-600 mb-2">{vulnKpis.patchesInTimeRate?.toFixed(1)}%</p>
              <p className="text-sm text-teal-600/80">Respect des délais</p>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Charts avec style amélioré */}
            <div className="bg-white rounded-xl p-6 shadow-lg border border-gray-100 hover:shadow-xl transition-shadow duration-300">
              <h3 className="text-xl font-semibold text-gray-800 mb-6">Répartition par sévérité</h3>
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={vulnKpis.severityData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      nameKey="name"
                      label={({ name, percentage }) => `${name}: ${percentage.toFixed(1)}%`}
                    >
                      {vulnKpis.severityData?.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value, name, props) => [`${value} vulnérabilités (${props.payload.percentage.toFixed(1)}%)`, name]} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="bg-white rounded-xl p-6 shadow-lg border border-gray-100 hover:shadow-xl transition-shadow duration-300">
              <h3 className="text-xl font-semibold text-gray-800 mb-6">Sources de détection</h3>
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={vulnKpis.sourceData}
                    margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip formatter={(value, name, props) => [`${value} vulnérabilités (${props.payload.percentage.toFixed(1)}%)`, name]} />
                    <Bar dataKey="value" name="Nombre" fill="#8884d8">
                      {vulnKpis.sourceData?.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </section>
        
        <footer className="mt-12 text-center">
          <p className="text-gray-600 text-sm">
            Dashboard généré le {new Date().toLocaleDateString('fr-FR', { 
              day: 'numeric', 
              month: 'long', 
              year: 'numeric'
            })}
          </p>
        </footer>
      </div>
    </div>
  );
};

export default DashboardVisualization;