import { useState } from "react";
import { NavLink } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Menu,
  Shield,
  Briefcase,
  LayoutDashboard,
  Activity,
  Globe,
  ShieldAlert,
  Key,
  Braces,
  Eraser,
  HelpCircle,
  Settings,
} from "lucide-react";
import { useProjectStore } from "../../stores/projectStore";

const navItems = [
  { label: "Workspace", path: "/workspace", icon: Briefcase },
  {
    label: "Overview",
    path: "overview",
    icon: LayoutDashboard,
    requiresProject: true,
  },
  {
    label: "Live Events",
    path: "live-events",
    icon: Activity,
    requiresProject: true,
  },

  {
    label: "Threat Intelligence",
    path: "threat-intel",
    icon: Globe,
    requiresProject: true,
  },
  {
    label: "Incidents",
    path: "incidents",
    icon: ShieldAlert,
    requiresProject: true,
  },
  { label: "API Keys", path: "api-keys", icon: Key, requiresProject: true },
  {
    label: "Integrations",
    path: "integrations",
    icon: Braces,
    requiresProject: true,
  },

  {
    label: "Data Cleanup",
    path: "data-cleanup",
    icon: Eraser,
    requiresProject: true,
  },
];

const bottomNav = [
  { label: "Help", path: "/help", icon: HelpCircle },
  { label: "Settings", path: "/settings", icon: Settings },
];

function NavItem({ to, label, icon: Icon, onClick }) {
  return (
    <NavLink
      to={to}
      end={to === "/workspace" || to === "/help" || to === "/settings"}
      onClick={onClick}
      className={({ isActive }) =>
        `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-soc-accent focus-visible:ring-offset-2 focus-visible:ring-offset-white ${
          isActive
            ? "bg-soc-tint-steel border border-soc-accent/25 text-soc-accent"
            : "text-soc-muted border border-transparent hover:bg-soc-panel hover:text-soc-text"
        }`
      }
    >
      {({ isActive }) => (
        <>
          <Icon size={18} strokeWidth={isActive ? 2.2 : 1.8} />
          <span>{label}</span>
        </>
      )}
    </NavLink>
  );
}

export function Sidebar() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const [mobileOpen, setMobileOpen] = useState(false);

  const currentProjectId = activeProject?.id ?? null;

  const close = () => setMobileOpen(false);

  const sidebarContent = (
    <aside className="h-full bg-white border-r border-soc-border flex flex-col">
      {/* Branding lockup */}
      <div className="px-5 pt-6 pb-5 border-b border-soc-border">
        <div className="flex items-center gap-2.5">
          <span className="w-8 h-8 rounded-lg bg-soc-tint-steel border border-soc-accent/20 flex items-center justify-center">
            <Shield size={18} className="text-soc-accent" strokeWidth={2.2} />
          </span>
          <span className="text-lg font-bold text-soc-text tracking-tight">
            SOC
          </span>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          if (item.requiresProject && !currentProjectId) {
            return (
              <div key={item.path} className="relative group">
                <button
                  disabled
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-soc-muted/45 cursor-not-allowed"
                >
                  <item.icon size={18} strokeWidth={1.8} />
                  <span>{item.label}</span>
                </button>
                <div className="absolute left-full top-1/2 -translate-y-1/2 ml-2 px-2 py-1 rounded bg-soc-tooltip text-xs text-white whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                  Select a project first
                </div>
              </div>
            );
          }
          const to =
            item.path === "/workspace"
              ? "/workspace"
              : `/${item.path}`;
          return (
            <NavItem
              key={item.path}
              to={to}
              label={item.label}
              icon={item.icon}
              onClick={close}
            />
          );
        })}
      </nav>

      <div className="px-3 py-3 border-t border-soc-border space-y-1">
        {bottomNav.map((item) => (
          <NavItem
            key={item.path}
            to={item.path}
            label={item.label}
            icon={item.icon}
            onClick={close}
          />
        ))}
        <div className="pt-2 px-3">
          <p className="text-[10px] text-soc-muted/60">v0.1.0</p>
        </div>
      </div>
    </aside>
  );

  return (
    <>
      <button
        onClick={() => setMobileOpen(true)}
        className="lg:hidden fixed top-3 left-3 z-50 p-2 rounded-lg bg-white border border-soc-border shadow-lift text-soc-muted hover:text-soc-accent transition-colors"
        aria-label="Open sidebar"
      >
        <Menu size={20} />
      </button>

      <div className="hidden lg:block fixed left-0 top-0 bottom-0 w-60 z-40">
        {sidebarContent}
      </div>

      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-soc-overlay/60 lg:hidden"
            onClick={() => setMobileOpen(false)}
          >
            <motion.div
              initial={{ x: -300 }}
              animate={{ x: 0 }}
              exit={{ x: -300 }}
              transition={{ type: "spring", stiffness: 300, damping: 30 }}
              className="w-60 h-full"
              onClick={(e) => e.stopPropagation()}
            >
              {sidebarContent}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
