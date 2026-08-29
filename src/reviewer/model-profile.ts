export const MODEL_PROFILE_IDS = ["deepseek-v4-flash", "mimo-v2.5"] as const;
export type ModelProfileID = (typeof MODEL_PROFILE_IDS)[number];

export interface ModelProfile {
  readonly id: ModelProfileID;
  readonly providerID: string;
  readonly modelID: string;
  readonly model: string;
  readonly requestedVariant: string | null;
}

function defineProfile<const ID extends ModelProfileID, const Provider extends string, const Model extends string, const Variant extends string | null>(
  id: ID,
  providerID: Provider,
  modelID: Model,
  requestedVariant: Variant,
) {
  return Object.freeze({ id, providerID, modelID, model: `${providerID}/${modelID}` as const, requestedVariant });
}

const profiles = {
  "deepseek-v4-flash": defineProfile("deepseek-v4-flash", "opencode-go", "deepseek-v4-flash", "low"),
  "mimo-v2.5": defineProfile("mimo-v2.5", "opencode-go", "mimo-v2.5", null),
} as const satisfies Record<ModelProfileID, ModelProfile>;

export const MODEL_PROFILES = Object.freeze(profiles);
export const ACTIVE_PRODUCTION_PROFILE_ID = "deepseek-v4-flash" as const;
export const ACTIVE_PRODUCTION_PROFILE = MODEL_PROFILES[ACTIVE_PRODUCTION_PROFILE_ID];

export function isModelProfileID(value: unknown): value is ModelProfileID {
  return typeof value === "string" && (MODEL_PROFILE_IDS as readonly string[]).includes(value);
}

export function getModelProfile(id: string): ModelProfile {
  if (!isModelProfileID(id)) throw new Error(`unknown model profile: ${id}`);
  return MODEL_PROFILES[id];
}

/** Accept only an exact, canonical registry profile. */
export function validateModelProfile(value: unknown): ModelProfile {
  if (typeof value !== "object" || value === null) throw new Error("model profile is missing");
  const record = value as Record<string, unknown>;
  if (!isModelProfileID(record.id)) throw new Error("model profile id is unknown");
  const canonical = MODEL_PROFILES[record.id];
  const keys = Object.keys(record).sort();
  const expected = ["id", "model", "modelID", "providerID", "requestedVariant"].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) throw new Error("model profile has unknown or missing fields");
  if (record.providerID !== canonical.providerID || record.modelID !== canonical.modelID || record.model !== canonical.model || record.requestedVariant !== canonical.requestedVariant) {
    throw new Error("model profile is stale or mutated");
  }
  return canonical;
}

export function runtimeModelFields(profile: ModelProfile): { readonly providerID: string; readonly modelID: string; readonly variant?: string } {
  return profile.requestedVariant === null
    ? { providerID: profile.providerID, modelID: profile.modelID }
    : { providerID: profile.providerID, modelID: profile.modelID, variant: profile.requestedVariant };
}

export function profileForModel(model: string): ModelProfile | undefined {
  return MODEL_PROFILE_IDS.map((id) => MODEL_PROFILES[id]).find((profile) => profile.model === model);
}
