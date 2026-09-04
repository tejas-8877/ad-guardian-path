/**
 * TanStack Query hooks over the FastAPI backend.
 *
 * Every hook is disabled in demo mode so fixtures are never silently swapped
 * in for a failed live request — the pages choose their source explicitly.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  api,
  toAttackPath,
  toCompromiseImpact,
  toEdge,
  toFinding,
  toPrincipal,
} from "./api";
import { useLive } from "./auth";
import { AttackGraph } from "./graph";

const LIVE_STALE = 30_000;

export function useAdHealth() {
  const live = useLive();
  return useQuery({
    queryKey: ["ad", "health"],
    queryFn: api.adHealth,
    enabled: live,
    refetchInterval: live ? 60_000 : false,
    retry: false,
  });
}

export function useCollectAd() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.adCollect,
    onSuccess: () => {
      // Every view derives from the snapshot the collection just refreshed.
      void qc.invalidateQueries();
    },
  });
}

export function useDashboard() {
  const live = useLive();
  return useQuery({
    queryKey: ["dashboard"],
    queryFn: api.dashboard,
    enabled: live,
    staleTime: LIVE_STALE,
    retry: false,
  });
}

export function useAssets(type: string) {
  const live = useLive();
  return useQuery({
    queryKey: ["assets", type],
    queryFn: async () => (await api.assets({ type })).items.map(toPrincipal),
    enabled: live,
    staleTime: LIVE_STALE,
    retry: false,
  });
}

export function useFindings() {
  const live = useLive();
  return useQuery({
    queryKey: ["findings"],
    queryFn: async () => (await api.findings()).items.map(toFinding),
    enabled: live,
    staleTime: LIVE_STALE,
    retry: false,
  });
}

export function useMyHygiene() {
  const live = useLive();
  return useQuery({
    queryKey: ["hygiene"],
    queryFn: async () => (await api.myHygiene()).map(toFinding),
    enabled: live,
    staleTime: LIVE_STALE,
    retry: false,
  });
}

export function useAttackPaths() {
  const live = useLive();
  return useQuery({
    queryKey: ["attack-paths"],
    queryFn: async () => (await api.attackPaths()).map(toAttackPath),
    enabled: live,
    staleTime: LIVE_STALE,
    retry: false,
  });
}

/** Backend principals + relationship edges assembled into the client graph. */
export function useBackendGraph() {
  const live = useLive();
  return useQuery({
    queryKey: ["graph", "backend"],
    queryFn: async () => {
      const [assets, edges] = await Promise.all([api.assets({ page_size: 500 }), api.removableEdges()]);
      return new AttackGraph(assets.items.map(toPrincipal), edges.map(toEdge));
    },
    enabled: live,
    staleTime: LIVE_STALE,
    retry: false,
  });
}

export function useEndpoints() {
  const live = useLive();
  return useQuery({
    queryKey: ["endpoints"],
    queryFn: api.endpoints,
    enabled: live,
    staleTime: LIVE_STALE,
    retry: false,
  });
}

export function useCompromiseImpact(endpointId: string | null, status: string) {
  const live = useLive();
  return useQuery({
    queryKey: ["compromise-impact", endpointId, status],
    queryFn: async () => toCompromiseImpact(await api.compromiseImpact(endpointId!, status)),
    enabled: live && !!endpointId,
    staleTime: LIVE_STALE,
    retry: false,
  });
}
