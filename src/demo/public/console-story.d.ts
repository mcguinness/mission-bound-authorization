/** Types for console-story.js, the console story's revocation proof. */

export interface StoryMission {
  id: string;
  state: string;
  effective?: Array<{ actions?: string[] }>;
}

export interface ActionResponse {
  ok?: boolean;
  reason?: string | null;
  denial_reason?: string;
  refusal_reason?: string;
  error?: string;
}

export interface RevokeResponse {
  id?: string;
  state?: string;
  termination?: { reason?: string };
  error?: string;
}

export declare const REVOCATION_REFUSALS: string[];

export declare function contrastMission(missions: StoryMission[] | undefined, revokedId: string): StoryMission | undefined;

export declare function proveRevocation(input: {
  revoke: RevokeResponse | undefined;
  missions: StoryMission[];
  missionId: string;
  read: (missionId: string, heading: string) => Promise<ActionResponse | undefined>;
}): Promise<{ done: true; otherId: string } | { done: false; problem: string }>;
