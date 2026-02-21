import { env } from './env.ts';

type SchoolApiResponse = {
  success?: boolean;
  data?: unknown[];
};

export async function fetchSchoolProfileByNpsn(npsn: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.schoolApiTimeoutMs);

  try {
    const url = new URL(env.schoolApiBaseUrl);
    url.searchParams.set('npsn', npsn);
    url.searchParams.set('limit', '1');

    const response = await fetch(url.toString(), {
      signal: controller.signal,
      headers: {
        accept: 'application/json'
      }
    });

    if (!response.ok) {
      return null;
    }

    const json = (await response.json()) as SchoolApiResponse;
    if (!json?.success || !Array.isArray(json.data) || json.data.length === 0) {
      return null;
    }

    return json.data[0] as Record<string, unknown>;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}
