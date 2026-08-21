import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import DashboardLayout from "@/components/DashboardLayout";
import AuditLog from "@/pages/AuditLog";
import CveFeed from "@/pages/CveFeed";
import Home from "@/pages/Home";
import NotFound from "@/pages/NotFound";
import ReportGenerator from "@/pages/ReportGenerator";
import TriageMatrix from "@/pages/TriageMatrix";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";

function Router() {
  return <DashboardLayout><Switch>
    <Route path="/" component={Home} />
    <Route path="/triage" component={TriageMatrix} />
    <Route path="/feed" component={CveFeed} />
    <Route path="/audit" component={AuditLog} />
    <Route path="/reports" component={ReportGenerator} />
    <Route path="/404" component={NotFound} />
    <Route component={NotFound} />
  </Switch></DashboardLayout>;
}

function App() {
  return <ErrorBoundary><ThemeProvider defaultTheme="dark"><TooltipProvider><Toaster /><Router /></TooltipProvider></ThemeProvider></ErrorBoundary>;
}

export default App;
