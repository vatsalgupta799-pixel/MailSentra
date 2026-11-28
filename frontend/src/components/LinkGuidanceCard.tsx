import React, { useState } from 'react';
import {
  AlertOctagon,
  ShieldAlert,
  HelpCircle,
  X,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  Info,
} from 'lucide-react';
import { ExtractedUrl, LinkConsequences, PostClickGuidance } from '../types';

interface LinkGuidanceProps {
  urlItem: ExtractedUrl;
}

export const LinkGuidanceCard: React.FC<LinkGuidanceProps> = ({ urlItem }) => {
  const [showPostClickModal, setShowPostClickModal] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState<string | null>(null);

  const consequences: LinkConsequences | undefined = urlItem.consequences || undefined;
  const guidanceList: PostClickGuidance[] = urlItem.post_click_guidance || [];

  const isSuspicious = urlItem.finding?.severity === 'SUSPICIOUS' || consequences;
  const isMalicious = urlItem.finding?.severity === 'MALICIOUS';

  return (
    <div className="mt-3 pt-3 border-t border-gray-800/80 space-y-3 font-sans">
      {/* 1 & 2: Threat Identification & Rationale */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          {isMalicious ? (
            <span className="flex items-center space-x-1 px-2 py-0.5 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs font-semibold">
              <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
              <span>MALICIOUS URL: {consequences?.category_title || 'High-Risk Link'}</span>
            </span>
          ) : isSuspicious ? (
            <span className="flex items-center space-x-1 px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300 text-xs font-semibold">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>SUSPICIOUS URL: {consequences?.category_title || 'Anomalous Link'}</span>
            </span>
          ) : (
            <span className="flex items-center space-x-1 px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-800 text-emerald-300 text-xs">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>NO SUSPICIOUS STATIC INDICATORS</span>
            </span>
          )}
        </div>

        {/* Action Button: I ALREADY CLICKED THIS LINK */}
        {isSuspicious && (
          <button
            type="button"
            onClick={() => setShowPostClickModal(true)}
            className="flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 border border-rose-500/40 text-rose-300 hover:text-rose-200 text-xs font-semibold transition-all shadow-sm"
          >
            <HelpCircle className="w-3.5 h-3.5 text-rose-400" />
            <span>I ALREADY CLICKED THIS LINK — WHAT SHOULD I DO?</span>
          </button>
        )}
      </div>

      {/* Detection rationale explanation */}
      {urlItem.finding?.reason && (
        <div className="text-xs text-gray-400 bg-gray-950/60 p-2.5 rounded border border-gray-800/80">
          <span className="font-semibold text-gray-300">Why MailSentra flagged this: </span>
          <span className="font-mono text-[11px] text-gray-300">{urlItem.finding.reason}</span>
        </div>
      )}

      {/* 3. Section: WHAT COULD HAPPEN IF YOU CLICK THIS LINK? */}
      {consequences && (
        <div className="bg-gradient-to-r from-gray-950 to-gray-900/80 border border-amber-500/30 rounded-lg p-3.5 space-y-2.5">
          <div className="flex items-center space-x-2 text-amber-400 text-xs font-bold uppercase tracking-wider">
            <ShieldAlert className="w-4 h-4 text-amber-400 flex-shrink-0" />
            <span>WHAT COULD HAPPEN IF YOU CLICK THIS LINK?</span>
          </div>

          <p className="text-xs text-gray-300 leading-relaxed">
            {consequences.risk_summary}
          </p>

          <div className="space-y-1.5 pl-1">
            <div className="text-[11px] font-semibold text-amber-200/90 uppercase tracking-wide">
              Potential Consequences:
            </div>
            <ul className="space-y-1">
              {consequences.what_could_happen.map((item, idx) => (
                <li key={idx} className="flex items-start space-x-2 text-xs text-gray-200">
                  <ChevronRight className="w-3.5 h-3.5 text-amber-400 mt-0.5 flex-shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Risk Distinction / Non-Exaggeration Context */}
          {consequences.risk_distinctions.length > 0 && (
            <div className="mt-2 pt-2 border-t border-gray-800/80 text-[11px] text-gray-400 space-y-1 bg-gray-950/40 p-2 rounded">
              <div className="flex items-center space-x-1.5 text-blue-400 font-semibold">
                <Info className="w-3.5 h-3.5 flex-shrink-0" />
                <span>Risk Distinction & Clarity:</span>
              </div>
              <ul className="list-disc list-inside space-y-0.5 pl-1 text-gray-400">
                {consequences.risk_distinctions.map((dist, dIdx) => (
                  <li key={dIdx}>{dist}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Interactive Modal / Dialog: I Already Clicked This Link */}
      {showPostClickModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between p-5 border-b border-gray-800 bg-gray-950">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 bg-rose-500/20 border border-rose-500/30 rounded-lg text-rose-400">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">
                    Post-Click Guided Assistance
                  </h3>
                  <p className="text-xs text-gray-400">
                    Step-by-step guidance based on what you actually did after clicking
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setShowPostClickModal(false);
                  setSelectedScenario(null);
                }}
                className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-gray-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-6">
              {/* Question 1: What did you do? */}
              <div>
                <label className="block text-xs font-bold text-gray-200 uppercase tracking-wider mb-2">
                  Step 1: What happened after you opened or clicked the link?
                </label>
                <p className="text-xs text-gray-400 mb-3">
                  Select the option that best matches what you actually did. We will never ask for your passwords or credit card numbers.
                </p>

                <div className="space-y-2">
                  {guidanceList.map((g) => {
                    const isSelected = selectedScenario === g.scenario;
                    return (
                      <button
                        key={g.scenario}
                        type="button"
                        onClick={() => setSelectedScenario(g.scenario)}
                        className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-start space-x-3 ${
                          isSelected
                            ? 'bg-blue-950/40 border-blue-500 text-white shadow-md shadow-blue-950/50'
                            : 'bg-gray-950/50 border-gray-800 text-gray-300 hover:border-gray-700 hover:bg-gray-950'
                        }`}
                      >
                        <div
                          className={`w-4 h-4 rounded-full border mt-0.5 flex items-center justify-center flex-shrink-0 ${
                            isSelected ? 'border-blue-400 bg-blue-500' : 'border-gray-600'
                          }`}
                        >
                          {isSelected && <div className="w-1.5 h-1.5 bg-white rounded-full" />}
                        </div>
                        <div className="flex-1 text-xs leading-relaxed">
                          <span className="font-medium text-gray-200">{g.scenario_label}</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Step 2: Tailored Action Checklist */}
              {selectedScenario && (
                <div className="animate-in fade-in duration-200 space-y-4">
                  {(() => {
                    const currentGuidance = guidanceList.find((g) => g.scenario === selectedScenario);
                    if (!currentGuidance) return null;

                    const isCrit = currentGuidance.urgency_level === 'CRITICAL';
                    const isHigh = currentGuidance.urgency_level === 'HIGH';

                    return (
                      <div
                        className={`p-4 rounded-xl border space-y-3 ${
                          isCrit
                            ? 'bg-red-950/30 border-red-800/80'
                            : isHigh
                            ? 'bg-amber-950/30 border-amber-800/80'
                            : 'bg-blue-950/30 border-blue-800/80'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                            <span>Step 2: Recommended Immediate Actions</span>
                          </span>
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                              isCrit
                                ? 'bg-red-500/20 text-red-300 border-red-500/30'
                                : isHigh
                                ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                                : 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                            }`}
                          >
                            Urgency: {currentGuidance.urgency_level}
                          </span>
                        </div>

                        <div className="space-y-2.5">
                          {currentGuidance.recommended_actions.map((act, idx) => (
                            <div key={idx} className="flex items-start space-x-2.5 text-xs text-gray-200">
                              <span className="flex-shrink-0 w-5 h-5 rounded-full bg-gray-800 text-gray-300 flex items-center justify-center font-bold text-[10px]">
                                {idx + 1}
                              </span>
                              <span className="leading-relaxed mt-0.5">{act}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-gray-800 bg-gray-950 flex justify-end">
              <button
                type="button"
                onClick={() => {
                  setShowPostClickModal(false);
                  setSelectedScenario(null);
                }}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg text-xs font-semibold transition-colors"
              >
                Close Guidance
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
