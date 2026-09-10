"use client";

import React, { useState } from "react";
import { FileCode, Copy, Check } from "lucide-react";
import { CollapsibleCard } from "@/components/dashboard/CollapsibleCard";

interface EmailBodyPreviewProps {
  emailBodyText: string;
}

export const EmailBodyPreview: React.FC<EmailBodyPreviewProps> = ({
  emailBodyText,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(emailBodyText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lines = emailBodyText.split("\n");

  return (
    <CollapsibleCard
      title="Raw Email Payload Preview"
      icon={<FileCode className="w-5 h-5" />}
      defaultOpen={false}
      badge={
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-white/10">
          RFC 5322 ASCII
        </span>
      }
    >
      <div className="relative rounded-xl bg-black/80 border border-white/10 overflow-hidden font-mono text-xs">
        {/* Top Terminal Bar */}
        <div className="px-4 py-2.5 bg-black/90 border-b border-white/10 flex items-center justify-between text-zinc-400">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-green-500/80 inline-block" />
            <span className="ml-2 text-[11px] text-zinc-400">payload_stream.txt</span>
          </div>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white/5 hover:bg-white/10 text-zinc-300 hover:text-white transition-colors text-[11px]"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-red-400" />
                <span className="text-red-400 font-bold">COPIED</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>COPY PAYLOAD</span>
              </>
            )}
          </button>
        </div>

        {/* Text Body with Line Numbers */}
        <div className="p-4 max-h-80 overflow-y-auto overflow-x-auto select-text text-zinc-300 leading-relaxed font-mono">
          <table className="w-full border-collapse">
            <tbody>
              {lines.map((line, idx) => (
                <tr key={idx} className="hover:bg-white/[0.02]">
                  <td className="w-10 pr-4 text-right select-none text-zinc-600 font-mono text-[11px] align-top">
                    {idx + 1}
                  </td>
                  <td className="whitespace-pre-wrap break-all text-zinc-200">
                    {line || " "}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </CollapsibleCard>
  );
};
