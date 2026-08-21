export interface ContextBudgetMetadata {
  estimatedTokens: number;
  contextWindow: number;
  reservedOutputTokens: number;
}

export type ContextBudgetTone = "normal" | "warning" | "critical";

export interface ContextBudgetState extends ContextBudgetMetadata {
  usedTokens: number;
  percent: number;
  tone: ContextBudgetTone;
  remainingTokens: number;
}

export function estimateMessageTokens(
  messages: ReadonlyArray<{ content: string }>,
): number {
  const characters = messages.reduce(
    (total, message) => total + message.content.length,
    0,
  );
  return Math.ceil(characters / 4) + messages.length * 4;
}

export function buildContextBudget(
  estimatedTokens: number,
  contextWindow: number,
  reservedOutputTokens: number,
): ContextBudgetState {
  const safeWindow = Math.max(1, Math.floor(contextWindow));
  const estimate = Math.max(0, Math.floor(estimatedTokens));
  const reserve = Math.max(0, Math.floor(reservedOutputTokens));
  const usedTokens = estimate + reserve;
  const percent = Math.min(100, Math.round((usedTokens / safeWindow) * 100));
  const tone: ContextBudgetTone =
    percent >= 90 ? "critical" : percent >= 75 ? "warning" : "normal";

  return {
    estimatedTokens: estimate,
    contextWindow: safeWindow,
    reservedOutputTokens: reserve,
    usedTokens,
    percent,
    tone,
    remainingTokens: Math.max(0, safeWindow - usedTokens),
  };
}
