import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';

export function FooterBar() {
  const { data, isError } = useQuery({
    queryKey: ['health'],
    queryFn: () => api.health(),
    refetchInterval: 30000,
    retry: 1,
  });

  const mongoOk = !isError && data?.mongo;
  const esOk = !isError && data?.elasticsearch;

  return (
    <footer className="h-9 bg-white border-t border-soc-border flex items-center px-6 ml-60 max-lg:ml-0 text-xs text-soc-muted">
      <span className="flex items-center gap-2">
        <span className={`w-1.5 h-1.5 rounded-full ${isError ? 'bg-red-500' : mongoOk ? 'bg-soc-sage' : 'bg-amber-500'}`} />
        Ingest: {isError ? 'Offline' : mongoOk ? 'OK' : 'Degraded'}
      </span>
      <span className="mx-3 text-soc-border">|</span>
      <span className="flex items-center gap-2">
        <span className={`w-1.5 h-1.5 rounded-full ${esOk ? 'bg-soc-sage' : 'bg-amber-500'}`} />
        ES Cluster: {esOk ? 'Connected' : 'Mongo fallback'}
      </span>
    </footer>
  );
}
